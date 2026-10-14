use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    build_payload_aad, build_vdk_wrap_aad, decrypt_payload, derive_kek, derive_pek,
    encrypt_payload, generate_nonce, generate_salt, generate_vault_id, generate_vdk, unwrap_vdk,
    wrap_vdk, PayloadAadParams, GCM_TAG_LEN,
};
use crate::errors::{Result, VaultError};
use crate::vault::cbor::{VaultHeader, VaultHeaderParams};
use crate::vault::container::{build_container, parse_container};

/// Output of a successful vault creation or unlock operation held in memory.
#[derive(Debug)]
pub struct UnlockedVault {
    pub header: VaultHeader,
    pub vdk: Zeroizing<[u8; 32]>,
    pub payload_plaintext: Zeroizing<Vec<u8>>,
}

impl UnlockedVault {
    /// Explicitly lock this vault, clearing and zeroizing all secrets from memory.
    pub fn lock(&mut self) {
        // Zeroize plaintext buffer
        self.payload_plaintext.zeroize();
        // Zeroize VDK
        self.vdk.zeroize();
    }
}

/// Create a new `.kivault` container in memory.
///
/// Steps (§4.2, §7, §8 of `vault-format.md`):
/// 1. Generate fresh random values:
///    - `vault_id`: 16-byte raw UUIDv4
///    - `kdf_salt`: 32-byte salt for Argon2id KEK derivation
///    - `wrap_nonce`: 12-byte nonce for VDK wrapping
///    - `vdk`: 32-byte Vault Data Key
///    - `payload_kdf_salt`: 32-byte salt for per-save HKDF PEK derivation
///    - `payload_nonce`: 12-byte nonce for payload encryption
/// 2. Derive KEK from `password` and `kdf_salt` using Argon2id.
/// 3. Wrap VDK with AES-256-GCM using 71-byte AAD.
/// 4. Construct preliminary `VaultHeader` with placeholder wrapping/payload metadata.
/// 5. Compute `header_length` from canonical deterministic CBOR encoding.
/// 6. Compute `ciphertext_length = initial_payload.len() + 16` using checked arithmetic.
/// 7. Derive PEK from VDK and `payload_kdf_salt` using HKDF-SHA256.
/// 8. Build 118-byte payload AAD.
/// 9. Encrypt `initial_payload` using AES-256-GCM with PEK and payload AAD.
/// 10. Assemble and return complete container binary (`FixedPrefix` + CBOR header + ciphertext).
pub fn create_vault(
    password: &[u8],
    created_at: u64,
    schema_version: u32,
    minimum_reader: u32,
    initial_payload: &[u8],
) -> Result<Vec<u8>> {
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
/// 7. Decrypt and authenticate payload using AES-256-GCM.
/// 8. Return `UnlockedVault` containing the header, zeroizing VDK, and zeroizing plaintext buffer.
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

    let decrypted = decrypt_payload(
        &pek,
        &header.payload_nonce,
        &payload_aad,
        &container.ciphertext,
    )?;

    Ok(UnlockedVault {
        header,
        vdk,
        payload_plaintext: Zeroizing::new(decrypted),
    })
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

    #[test]
    fn test_vault_create_unlock_roundtrip() {
        let password = b"strong-master-password-123";
        let payload = b"SQLite format 3\0... sample database bytes ...";
        let created_at = 1776123456;

        let container_bytes =
            create_vault(password, created_at, 1, 1, payload).expect("create_vault succeeds");

        let mut unlocked = unlock_vault(&container_bytes, password).expect("unlock_vault succeeds");

        assert_eq!(unlocked.payload_plaintext.as_slice(), payload);
        assert_eq!(unlocked.header.created_at, created_at);
        assert_eq!(unlocked.header.schema_version, 1);
        assert_eq!(unlocked.header.minimum_reader, 1);

        // Test explicit lock cleanup
        unlocked.lock();
        assert!(unlocked.payload_plaintext.is_empty());
        assert_eq!(*unlocked.vdk, [0u8; 32]);
    }

    #[test]
    fn test_vault_unlock_wrong_password_fails() {
        let password_correct = b"correct-password";
        let password_wrong = b"wrong-password";
        let payload = b"Secret vault data";

        let container_bytes =
            create_vault(password_correct, 1000, 1, 1, payload).expect("create_vault succeeds");

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
        let payload = b"Critical personal data";

        let mut container_bytes =
            create_vault(password, 1000, 1, 1, payload).expect("create_vault succeeds");

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
        let payload = b"Critical personal data";

        let mut container_bytes =
            create_vault(password, 1000, 1, 1, payload).expect("create_vault succeeds");

        // Corrupt a byte inside the header (starts after prefix at byte 24)
        container_bytes[25] ^= 0x01;

        let res = unlock_vault(&container_bytes, password);
        assert!(res.is_err(), "tampered header must fail unlock");
    }

    #[test]
    fn test_change_master_password_invariant() {
        let password_old = b"old-master-password";
        let password_new = b"new-super-secure-password";
        let payload = b"Unchanged SQLite database content";

        let container_old =
            create_vault(password_old, 2000, 1, 1, payload).expect("create_vault succeeds");

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

        // 3. New password must unlock and retrieve identical payload
        let unlocked_new =
            unlock_vault(&container_new, password_new).expect("unlock with new password succeeds");
        assert_eq!(unlocked_new.payload_plaintext.as_slice(), payload);

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
}
