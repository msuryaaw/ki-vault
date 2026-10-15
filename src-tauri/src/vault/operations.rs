//! Vault Lifecycle Operations
//!
//! Handles creating, unlocking, locking, and rotating master passwords for KiVault containers.
//! In accordance with `vault-format.md`, `security.md`, and `database.md`:
//! - Secrets (VDK and intermediate plaintext buffers) are wrapped in `Zeroizing` containers.
//! - Unlocked vaults hold an active in-memory SQLite database ([`InMemoryDb`]) instead of
//!   a persistent raw plaintext buffer.
//! - Upon unlocking, decrypted SQLite images are deserialized into [`InMemoryDb`]; the intermediate
//!   decrypted buffer is held in a `Zeroizing<Vec<u8>>` and discarded after deserialization.
//! - `header.schema_version` is validated against `PRAGMA user_version` (rejecting mismatch).
//! - Locking explicitly closes the SQLite connection and zeroizes the VDK.
//!
//! # Zeroization Boundaries & Limitations
//! - Buffers directly owned by KiVault (such as the VDK and temporary plaintext decryption/serialization
//!   buffers) are cleared using `Zeroize`/`Zeroizing`.
//! - Internal SQLite memory pages (B-Tree cache, heap allocations managed by SQLite's C engine) are
//!   freed to the process allocator upon `InMemoryDb::close()` or `drop()`, but are NOT zeroized by SQLite.
//! - Paging to disk (`pagefile.sys`/swap) or OS crash dumps remain outside userspace zeroization guarantees.

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    build_payload_aad, build_vdk_wrap_aad, decrypt_payload, derive_kek, derive_pek,
    encrypt_payload, generate_nonce, generate_salt, generate_vault_id, generate_vdk, unwrap_vdk,
    wrap_vdk, PayloadAadParams, GCM_TAG_LEN,
};
use crate::errors::{AppError, DatabaseError, Result, VaultError};
use crate::vault::cbor::{VaultHeader, VaultHeaderParams};
use crate::vault::container::{build_container, parse_container};
use crate::vault::sqlite::InMemoryDb;

/// Output of a successful vault creation or unlock operation held in memory.
#[derive(Debug)]
pub struct UnlockedVault {
    pub header: VaultHeader,
    pub vdk: Zeroizing<[u8; 32]>,
    pub db: InMemoryDb,
}

impl UnlockedVault {
    /// Explicitly lock this vault, closing the database connection and zeroizing the VDK.
    pub fn lock(&mut self) {
        // Close in-memory database connection
        self.db.close();
        // Zeroize VDK
        self.vdk.zeroize();
    }

    /// Serializes the current active `InMemoryDb`, encrypts it under the vault's VDK
    /// with fresh payload salt and nonce, updates `header`, and returns the complete
    /// binary `.kivault` container.
    ///
    /// # Workflow (§4.2, §8, §12 of `vault-format.md`):
    /// 1. Serialize SQLite database in memory to a `Zeroizing<Vec<u8>>` buffer.
    /// 2. Validate that `header.schema_version` matches the database's `PRAGMA user_version`.
    /// 3. Generate fresh random 32-byte `payload_kdf_salt` and fresh 12-byte `payload_nonce`.
    /// 4. Construct updated `VaultHeader` with new payload salt & nonce, preserving all other fields.
    /// 5. Compute `header_length` via canonical deterministic CBOR encoding.
    /// 6. Compute `ciphertext_length = serialized_bytes.len() + 16` using checked arithmetic.
    /// 7. Derive per-save PEK from VDK and `payload_kdf_salt` using HKDF-SHA256.
    /// 8. Build 118-byte payload AAD.
    /// 9. Encrypt serialized database bytes with AES-256-GCM.
    /// 10. Assemble and return full container binary (`FixedPrefix` + CBOR header + ciphertext).
    /// 11. Update `self.header` in place only upon complete success.
    pub fn save_to_container(&mut self) -> Result<Vec<u8>> {
        let serialized_bytes = self.db.to_image()?;
        let db_schema_version = self.db.schema_version()?;
        if self.header.schema_version != db_schema_version {
            return Err(AppError::Database(
                DatabaseError::UnsupportedSchemaVersion {
                    version: db_schema_version,
                    supported: self.header.schema_version,
                },
            ));
        }

        // Generate fresh per-save cryptographic parameters
        let new_payload_kdf_salt = generate_salt()?;
        let new_payload_nonce = generate_nonce()?;

        // Build candidate header
        let updated_header = VaultHeader::new_v1(VaultHeaderParams {
            vault_id: self.header.vault_id,
            created_at: self.header.created_at,
            schema_version: self.header.schema_version,
            minimum_reader: self.header.minimum_reader,
            kdf_salt: self.header.kdf_salt,
            wrap_nonce: self.header.wrap_nonce,
            wrapped_vdk: self.header.wrapped_vdk,
            payload_kdf_salt: new_payload_kdf_salt,
            payload_nonce: new_payload_nonce,
        })?;

        let header_bytes = updated_header.to_cbor();
        let header_len = header_bytes.len() as u32;

        let ciphertext_len = (serialized_bytes.len() as u64)
            .checked_add(GCM_TAG_LEN as u64)
            .ok_or(VaultError::SizeArithmeticOverflow)?;

        // Derive PEK and encrypt payload
        let pek = derive_pek(&self.vdk, &new_payload_kdf_salt)?;
        let payload_aad = build_payload_aad(&PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: header_len,
            created_at: updated_header.created_at,
            vault_id: &updated_header.vault_id,
            schema_version: updated_header.schema_version,
            minimum_reader: updated_header.minimum_reader,
            payload_kdf_salt: &new_payload_kdf_salt,
            payload_nonce: &new_payload_nonce,
            ciphertext_length: ciphertext_len,
        });

        let ciphertext =
            encrypt_payload(&pek, &new_payload_nonce, &payload_aad, &serialized_bytes)?;

        let container_bytes = build_container(&updated_header, &ciphertext)?;

        // Success: update self.header with new payload parameters
        self.header = updated_header;

        Ok(container_bytes)
    }

    /// Serializes and encrypts `InMemoryDb`, then atomically saves the container to `destination`.
    ///
    /// Never creates or writes plaintext database files to disk.
    pub fn save_to_file(&mut self, destination: &std::path::Path) -> Result<()> {
        let container_bytes = self.save_to_container()?;
        crate::vault::storage::write_vault_atomic(destination, &container_bytes)
    }
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.lock();
    }
}

/// Create a new `.kivault` container in memory.
///
/// Steps (§4.2, §7, §8 of `vault-format.md`):
/// 1. Validate that `initial_payload` is a valid SQLite database image or reject before crypto.
/// 2. Generate fresh random values:
///    - `vault_id`: 16-byte raw UUIDv4
///    - `kdf_salt`: 32-byte salt for Argon2id KEK derivation
///    - `wrap_nonce`: 12-byte nonce for VDK wrapping
///    - `vdk`: 32-byte Vault Data Key
///    - `payload_kdf_salt`: 32-byte salt for per-save HKDF PEK derivation
///    - `payload_nonce`: 12-byte nonce for payload encryption
/// 3. Derive KEK from `password` and `kdf_salt` using Argon2id.
/// 4. Wrap VDK with AES-256-GCM using 71-byte AAD.
/// 5. Construct preliminary `VaultHeader` with placeholder wrapping/payload metadata.
/// 6. Compute `header_length` from canonical deterministic CBOR encoding.
/// 7. Compute `ciphertext_length = initial_payload.len() + 16` using checked arithmetic.
/// 8. Derive PEK from VDK and `payload_kdf_salt` using HKDF-SHA256.
/// 9. Build 118-byte payload AAD.
/// 10. Encrypt `initial_payload` using AES-256-GCM with PEK and payload AAD.
/// 11. Assemble and return complete container binary (`FixedPrefix` + CBOR header + ciphertext).
pub fn create_vault(
    password: &[u8],
    created_at: u64,
    schema_version: u32,
    minimum_reader: u32,
    initial_payload: &[u8],
) -> Result<Vec<u8>> {
    // Validate that initial_payload is a valid SQLite image with matching schema version
    let temp_db = InMemoryDb::from_image(initial_payload)?;
    let db_version = temp_db.schema_version()?;
    if db_version != schema_version {
        return Err(AppError::Database(
            DatabaseError::UnsupportedSchemaVersion {
                version: db_version,
                supported: schema_version,
            },
        ));
    }

    let vault_id = generate_vault_id()?;
    let kdf_salt = generate_salt()?;
    let wrap_nonce = generate_nonce()?;
    let vdk = generate_vdk()?;
    let payload_kdf_salt = generate_salt()?;
    let payload_nonce = generate_nonce()?;

    // 1. Derive KEK and wrap VDK
    let kek = derive_kek(password, &kdf_salt)?;
    let wrap_aad = build_vdk_wrap_aad(1, 0, &vault_id, &kdf_salt);
    let wrapped_vdk = wrap_vdk(&kek, &vdk, &wrap_nonce, &wrap_aad)?;

    // 2. Build canonical CBOR header
    let header = VaultHeader::new_v1(VaultHeaderParams {
        vault_id,
        created_at,
        schema_version,
        minimum_reader,
        kdf_salt,
        wrap_nonce,
        wrapped_vdk,
        payload_kdf_salt,
        payload_nonce,
    })?;

    let header_bytes = header.to_cbor();
    let header_len = header_bytes.len() as u32;

    // 3. Checked arithmetic for ciphertext length (plaintext + 16B tag)
    let ciphertext_len = (initial_payload.len() as u64)
        .checked_add(GCM_TAG_LEN as u64)
        .ok_or(VaultError::SizeArithmeticOverflow)?;

    // 4. Derive PEK and encrypt payload
    let pek = derive_pek(&vdk, &payload_kdf_salt)?;
    let payload_aad = build_payload_aad(&PayloadAadParams {
        format_major: 1,
        format_minor: 0,
        header_length: header_len,
        created_at,
        vault_id: &vault_id,
        schema_version,
        minimum_reader,
        payload_kdf_salt: &payload_kdf_salt,
        payload_nonce: &payload_nonce,
        ciphertext_length: ciphertext_len,
    });

    let ciphertext = encrypt_payload(&pek, &payload_nonce, &payload_aad, initial_payload)?;

    // 5. Assemble final container
    build_container(&header, &ciphertext)
}

/// Unlock a `.kivault` container in memory.
///
/// Steps (§4.2, §13 of `vault-format.md`):
/// 1. Parse and validate container binary (`parse_container`).
/// 2. Re-verify header bounds and KDF parameters before executing KDF.
/// 3. Derive KEK from `password` and header's `kdf_salt`.
/// 4. Construct 71-byte VDK-wrap AAD and unwrap VDK. Any tag failure fails closed.
/// 5. Derive PEK from VDK and header's `payload_kdf_salt`.
/// 6. Construct 118-byte payload AAD using prefix/header metadata and ciphertext length.
/// 7. Decrypt and authenticate payload using AES-256-GCM into a temporary `Zeroizing<Vec<u8>>`.
/// 8. Import decrypted image into `InMemoryDb` via SQLite deserialization.
/// 9. Verify `header.schema_version` matches SQLite's `PRAGMA user_version`. Reject mismatch.
/// 10. Return `UnlockedVault` containing the header, zeroizing VDK, and active `InMemoryDb`.
pub fn unlock_vault(container_bytes: &[u8], password: &[u8]) -> Result<UnlockedVault> {
    // 1. Parse container (validates prefix, file size, CBOR canonical header, and length matches)
    let container = parse_container(container_bytes)?;
    let header = container.header;

    // 2. Validate KDF constants before expensive KDF
    header.validate()?;

    // 3. Derive KEK and unwrap VDK
    let kek = derive_kek(password, &header.kdf_salt)?;
    let wrap_aad = build_vdk_wrap_aad(
        container.prefix.format_major,
        container.prefix.format_minor,
        &header.vault_id,
        &header.kdf_salt,
    );
    let vdk = unwrap_vdk(&kek, &header.wrapped_vdk, &header.wrap_nonce, &wrap_aad)?;

    // 4. Derive PEK and decrypt payload
    let pek = derive_pek(&vdk, &header.payload_kdf_salt)?;
    let payload_aad = build_payload_aad(&PayloadAadParams {
        format_major: container.prefix.format_major,
        format_minor: container.prefix.format_minor,
        header_length: container.prefix.header_length,
        created_at: header.created_at,
        vault_id: &header.vault_id,
        schema_version: header.schema_version,
        minimum_reader: header.minimum_reader,
        payload_kdf_salt: &header.payload_kdf_salt,
        payload_nonce: &header.payload_nonce,
        ciphertext_length: container.prefix.ciphertext_length,
    });

    let decrypted = Zeroizing::new(decrypt_payload(
        &pek,
        &header.payload_nonce,
        &payload_aad,
        &container.ciphertext,
    )?);

    // 5. Deserialize into InMemoryDb
    let db = InMemoryDb::from_image(&decrypted)?;

    // 6. Validate header.schema_version against database PRAGMA user_version
    let db_schema_version = db.schema_version()?;
    if header.schema_version != db_schema_version {
        return Err(AppError::Database(
            DatabaseError::UnsupportedSchemaVersion {
                version: db_schema_version,
                supported: header.schema_version,
            },
        ));
    }

    Ok(UnlockedVault { header, vdk, db })
}

/// Change master password by re-wrapping the VDK (§7, §11.4 of `vault-format.md`).
///
/// Invariant (§11.4 & ST-030):
/// - A fresh 32-byte `kdf_salt` and fresh 12-byte `wrap_nonce` are generated.
/// - New KEK is derived from `new_password` and the new salt.
/// - The existing VDK is re-wrapped under the new KEK with the new 71-byte AAD.
/// - The payload ciphertext, `payload_kdf_salt`, `payload_nonce`, `vault_id`, and `created_at`
///   remain strictly unchanged.
/// - Since only 32B salt, 12B nonce, and 48B wrapped VDK change in content (not in byte length),
///   the resulting CBOR `header_length` must remain exactly identical.
pub fn change_master_password(
    container_bytes: &[u8],
    current_password: &[u8],
    new_password: &[u8],
) -> Result<Vec<u8>> {
    // 1. First authenticate and unwrap with current password
    let container = parse_container(container_bytes)?;
    let old_header = container.header;
    let old_header_len = container.prefix.header_length;

    let kek_old = derive_kek(current_password, &old_header.kdf_salt)?;
    let wrap_aad_old = build_vdk_wrap_aad(
        container.prefix.format_major,
        container.prefix.format_minor,
        &old_header.vault_id,
        &old_header.kdf_salt,
    );
    let vdk = unwrap_vdk(
        &kek_old,
        &old_header.wrapped_vdk,
        &old_header.wrap_nonce,
        &wrap_aad_old,
    )?;

    // 2. Generate new wrapping parameters
    let new_kdf_salt = generate_salt()?;
    let new_wrap_nonce = generate_nonce()?;

    // 3. Derive new KEK and re-wrap the SAME VDK
    let kek_new = derive_kek(new_password, &new_kdf_salt)?;
    let wrap_aad_new = build_vdk_wrap_aad(
        container.prefix.format_major,
        container.prefix.format_minor,
        &old_header.vault_id,
        &new_kdf_salt,
    );
    let new_wrapped_vdk = wrap_vdk(&kek_new, &vdk, &new_wrap_nonce, &wrap_aad_new)?;

    // 4. Construct updated header keeping all other fields identical
    let new_header = VaultHeader::new_v1(VaultHeaderParams {
        vault_id: old_header.vault_id,
        created_at: old_header.created_at,
        schema_version: old_header.schema_version,
        minimum_reader: old_header.minimum_reader,
        kdf_salt: new_kdf_salt,
        wrap_nonce: new_wrap_nonce,
        wrapped_vdk: new_wrapped_vdk,
        payload_kdf_salt: old_header.payload_kdf_salt,
        payload_nonce: old_header.payload_nonce,
    })?;

    // 5. Invariant check: header_length must remain identical (§11.4)
    let new_header_bytes = new_header.to_cbor();
    if new_header_bytes.len() as u32 != old_header_len {
        return Err(VaultError::HeaderLengthMismatch {
            prefix_len: old_header_len,
            actual_len: new_header_bytes.len(),
        }
        .into());
    }

    // 6. Build and return container with the UNCHANGED payload ciphertext
    build_container(&new_header, &container.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CryptoError;
    use crate::vault::sqlite::SCHEMA_VERSION_V1;

    fn make_test_sqlite_image() -> Vec<u8> {
        let db = InMemoryDb::create_empty().expect("Failed to create empty test DB");
        {
            let conn = db.conn().unwrap();
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                ("test-vault-id", "Test Vault", 12345, 12345),
            )
            .unwrap();
        }
        db.to_image().unwrap().to_vec()
    }

    #[test]
    fn test_vault_create_rejects_invalid_sqlite_image() {
        let password = b"strong-master-password-123";
        let bad_payload = b"not a sqlite database image";

        let res = create_vault(password, 1000, 1, 1, bad_payload);
        assert!(matches!(
            res,
            Err(AppError::Database(DatabaseError::CorruptDatabase(_)))
        ));
    }

    #[test]
    fn test_vault_create_rejects_schema_version_mismatch() {
        let password = b"strong-master-password-123";
        let valid_payload = make_test_sqlite_image();

        // Pass schema_version = 2 while the DB user_version is 1
        let res = create_vault(password, 1000, 2, 1, &valid_payload);
        assert!(matches!(
            res,
            Err(AppError::Database(
                DatabaseError::UnsupportedSchemaVersion {
                    version: 1,
                    supported: 2
                }
            ))
        ));
    }

    #[test]
    fn test_vault_create_unlock_roundtrip() {
        let password = b"strong-master-password-123";
        let payload = make_test_sqlite_image();
        let created_at = 1776123456;

        let container_bytes =
            create_vault(password, created_at, 1, 1, &payload).expect("create_vault succeeds");

        let mut unlocked = unlock_vault(&container_bytes, password).expect("unlock_vault succeeds");

        assert_eq!(unlocked.header.created_at, created_at);
        assert_eq!(unlocked.header.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(unlocked.header.minimum_reader, 1);
        assert!(unlocked.db.is_open());

        // Verify data in the in-memory SQLite database
        let conn = unlocked.db.conn().unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM vault_metadata WHERE id = ?1;",
                ["test-vault-id"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Test Vault");

        // Test explicit lock cleanup
        unlocked.lock();
        assert!(!unlocked.db.is_open());
        assert_eq!(*unlocked.vdk, [0u8; 32]);
    }

    #[test]
    fn test_vault_unlock_wrong_password_fails() {
        let password_correct = b"correct-password";
        let password_wrong = b"wrong-password";
        let payload = make_test_sqlite_image();

        let container_bytes =
            create_vault(password_correct, 1000, 1, 1, &payload).expect("create_vault succeeds");

        let res = unlock_vault(&container_bytes, password_wrong);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_vault_unlock_corrupted_payload_fails() {
        let password = b"master-pass";
        let payload = make_test_sqlite_image();

        let mut container_bytes =
            create_vault(password, 1000, 1, 1, &payload).expect("create_vault succeeds");

        // Corrupt the last byte of the ciphertext (part of the auth tag)
        let last_idx = container_bytes.len() - 1;
        container_bytes[last_idx] ^= 0x01;

        let res = unlock_vault(&container_bytes, password);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_vault_unlock_corrupted_header_fails() {
        let password = b"master-pass";
        let payload = make_test_sqlite_image();

        let mut container_bytes =
            create_vault(password, 1000, 1, 1, &payload).expect("create_vault succeeds");

        // Corrupt a byte inside the header (starts after prefix at byte 24)
        container_bytes[25] ^= 0x01;

        let res = unlock_vault(&container_bytes, password);
        assert!(res.is_err(), "tampered header must fail unlock");
    }

    #[test]
    fn test_change_master_password_invariant() {
        let password_old = b"old-master-password";
        let password_new = b"new-super-secure-password";
        let payload = make_test_sqlite_image();

        let container_old =
            create_vault(password_old, 2000, 1, 1, &payload).expect("create_vault succeeds");

        // 1. Change master password
        let container_new = change_master_password(&container_old, password_old, password_new)
            .expect("change_master_password succeeds");

        // 2. Old password must now fail
        let res_old = unlock_vault(&container_new, password_old);
        assert!(matches!(
            res_old,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // 3. New password must unlock and retrieve valid working in-memory DB
        let unlocked_new =
            unlock_vault(&container_new, password_new).expect("unlock with new password succeeds");
        let conn = unlocked_new.db.conn().unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM vault_metadata WHERE id = ?1;",
                ["test-vault-id"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Test Vault");

        // 4. Invariant verifications (§11.4 & ST-030):
        let parsed_old = parse_container(&container_old).unwrap();
        let parsed_new = parse_container(&container_new).unwrap();

        // Exact VDK must be preserved
        let unlocked_old = unlock_vault(&container_old, password_old).unwrap();
        assert_eq!(
            *unlocked_old.vdk, *unlocked_new.vdk,
            "VDK must remain identical across password rotation"
        );

        // Exact payload ciphertext must be identical
        assert_eq!(
            parsed_old.ciphertext, parsed_new.ciphertext,
            "Payload ciphertext must remain identical across password rotation"
        );

        // Exact header_length must be identical
        assert_eq!(
            parsed_old.prefix.header_length, parsed_new.prefix.header_length,
            "header_length must remain identical across password rotation"
        );

        // vault_id, created_at, schema_version must be identical
        assert_eq!(parsed_old.header.vault_id, parsed_new.header.vault_id);
        assert_eq!(parsed_old.header.created_at, parsed_new.header.created_at);
        assert_eq!(
            parsed_old.header.schema_version,
            parsed_new.header.schema_version
        );

        // Wrapping salt, nonce, and wrapped VDK must have changed
        assert_ne!(parsed_old.header.kdf_salt, parsed_new.header.kdf_salt);
        assert_ne!(parsed_old.header.wrap_nonce, parsed_new.header.wrap_nonce);
        assert_ne!(parsed_old.header.wrapped_vdk, parsed_new.header.wrapped_vdk);
    }

    #[test]
    fn test_unlocked_vault_save_to_container_and_unlock_roundtrip() {
        let password = b"strong-pass-999";
        let initial_payload = make_test_sqlite_image();
        let container = create_vault(password, 1000, 1, 1, &initial_payload).unwrap();

        let mut unlocked = unlock_vault(&container, password).unwrap();

        // Mutate database in memory
        {
            let conn = unlocked.db.conn().unwrap();
            conn.execute(
                "INSERT INTO platforms (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                ("plat-1", "ProtonMail", 2000, 2000),
            )
            .unwrap();
        }

        // Save to new container binary
        let new_container = unlocked.save_to_container().unwrap();

        // Unlock new container and verify mutation
        let re_unlocked = unlock_vault(&new_container, password).unwrap();
        let conn = re_unlocked.db.conn().unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM platforms WHERE id = ?1;",
                ["plat-1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "ProtonMail");

        // Verify that payload_nonce and payload_kdf_salt rotated across saves
        let old_parsed = parse_container(&container).unwrap();
        let new_parsed = parse_container(&new_container).unwrap();
        assert_ne!(
            old_parsed.header.payload_kdf_salt,
            new_parsed.header.payload_kdf_salt
        );
        assert_ne!(
            old_parsed.header.payload_nonce,
            new_parsed.header.payload_nonce
        );

        // Vault identity & created_at preserved
        assert_eq!(old_parsed.header.vault_id, new_parsed.header.vault_id);
        assert_eq!(old_parsed.header.created_at, new_parsed.header.created_at);
    }

    #[test]
    fn test_unlocked_vault_save_rejects_schema_version_mismatch() {
        let password = b"strong-pass-999";
        let initial_payload = make_test_sqlite_image();
        let container = create_vault(password, 1000, 1, 1, &initial_payload).unwrap();

        let mut unlocked = unlock_vault(&container, password).unwrap();

        // Tamper with SQLite user_version inside the database
        {
            let conn = unlocked.db.conn().unwrap();
            conn.pragma_update(None, "user_version", 2u32).unwrap();
        }

        // save_to_container must reject mismatch between header (1) and db (2)
        let res = unlocked.save_to_container();
        assert!(matches!(
            res,
            Err(AppError::Database(
                DatabaseError::UnsupportedSchemaVersion {
                    version: 2,
                    supported: 1
                }
            ))
        ));
    }
}
