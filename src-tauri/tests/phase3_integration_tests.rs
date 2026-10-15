use std::path::PathBuf;
use std::sync::Arc;

use ki_vault_lib::crypto::{build_payload_aad, decrypt_payload, derive_pek, PayloadAadParams};
use ki_vault_lib::errors::{AppError, CryptoError, StorageError, VaultError};
use ki_vault_lib::vault::container::{build_container, parse_container};
use ki_vault_lib::vault::operations::{
    change_master_password, create_vault, unlock_vault, UnlockedVault,
};
use ki_vault_lib::vault::sqlite::InMemoryDb;
use ki_vault_lib::vault::storage::{
    backup_path_for, cleanup_stale_staging, read_vault, staging_path_for, write_vault_atomic,
};
use ki_vault_lib::vault::FIXED_PREFIX_LEN;

struct TestDirGuard {
    path: PathBuf,
}

impl TestDirGuard {
    fn new(suffix: &str) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("kivault_integ_{suffix}_{uuid}"));
        std::fs::create_dir_all(&path).expect("create integration test dir");
        Self { path }
    }
}

impl Drop for TestDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn make_test_sqlite_image() -> Vec<u8> {
    let db = InMemoryDb::create_empty().expect("create empty test db");
    {
        let conn = db.conn().unwrap();
        conn.execute(
            "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
            ("integ-vault-1", "Integration Vault", 1000, 1000),
        )
        .unwrap();
    }
    db.to_image().expect("serialize test db").to_vec()
}

// ============================================================================
// Integration 1: Complete Lifecycle (Create -> Persist -> Read -> Unlock -> Lock)
// Relevant to ST-001, ST-022, ST-024
// ============================================================================

#[test]
fn test_integration_create_persist_read_unlock_lock_lifecycle() {
    let guard = TestDirGuard::new("lifecycle");
    let vault_path = guard.path.join("my_wallet.kivault");
    let password = b"MasterSuperSecretPassword!2026";
    let initial_db_payload = make_test_sqlite_image();
    let created_at = 1776100000;

    // 1. Create vault container in memory
    let container_bytes = create_vault(password, created_at, 1, 1, &initial_db_payload)
        .expect("create_vault succeeds");

    // 2. Persist atomically to disk
    write_vault_atomic(&vault_path, &container_bytes).expect("write_vault_atomic succeeds");
    assert!(vault_path.exists());
    assert!(!staging_path_for(&vault_path).exists());
    assert!(!backup_path_for(&vault_path).exists());

    // 3. Read raw container from disk
    let disk_bytes = read_vault(&vault_path).expect("read_vault succeeds");
    assert_eq!(disk_bytes, container_bytes);

    // 4. Unlock vault
    let mut unlocked: UnlockedVault =
        unlock_vault(&disk_bytes, password).expect("unlock_vault succeeds with correct password");
    assert!(unlocked.db.is_open());

    let conn = unlocked.db.conn().unwrap();
    let name: String = conn
        .query_row(
            "SELECT name FROM vault_metadata WHERE id = ?1;",
            ["integ-vault-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "Integration Vault");

    assert_eq!(unlocked.header.created_at, created_at);
    assert_eq!(unlocked.header.schema_version, 1);
    assert_eq!(unlocked.header.minimum_reader, 1);

    // 5. Explicit lock
    unlocked.lock();
    assert!(!unlocked.db.is_open());
    assert_eq!(*unlocked.vdk, [0u8; 32]);
}

// ============================================================================
// Integration 2: Security & Tampering Resistance
// Relevant to ST-001, ST-004, ST-005, ST-006, ST-027
// ============================================================================

#[test]
fn test_integration_security_wrong_password_rejected() {
    let password_correct = b"correct-horse-battery-staple";
    let password_wrong = b"wrong-horse-battery-staple";
    let payload = make_test_sqlite_image();

    let container = create_vault(password_correct, 1000, 1, 1, &payload).unwrap();

    // Unlock with wrong password must fail closed with TagVerificationFailed
    let res = unlock_vault(&container, password_wrong);
    assert!(matches!(
        res,
        Err(AppError::Crypto(CryptoError::TagVerificationFailed))
    ));
}

#[test]
fn test_integration_security_wrapped_vdk_tampering_rejected() {
    let password = b"password123";
    let payload = make_test_sqlite_image();

    let container = create_vault(password, 1000, 1, 1, &payload).unwrap();
    let mut parsed = parse_container(&container).unwrap();

    // Tamper with wrapped VDK bytes in header
    parsed.header.wrapped_vdk[0] ^= 0x55;

    // Rebuild container with tampered header
    let tampered_container = build_container(&parsed.header, &parsed.ciphertext).unwrap();

    // Must fail closed with TagVerificationFailed during unwrap
    let res = unlock_vault(&tampered_container, password);
    assert!(matches!(
        res,
        Err(AppError::Crypto(CryptoError::TagVerificationFailed))
    ));
}

#[test]
fn test_integration_security_payload_tag_tampering_rejected() {
    let password = b"password123";
    let payload = make_test_sqlite_image();

    let mut container = create_vault(password, 1000, 1, 1, &payload).unwrap();

    // The last 16 bytes are the AES-GCM authentication tag
    let last_idx = container.len() - 1;
    container[last_idx] ^= 0x01;

    let res = unlock_vault(&container, password);
    assert!(matches!(
        res,
        Err(AppError::Crypto(CryptoError::TagVerificationFailed))
    ));
}

#[test]
fn test_integration_security_aad_metadata_tampering_rejected() {
    let password = b"password123";
    let payload = make_test_sqlite_image();

    let container = create_vault(password, 1000, 1, 1, &payload).unwrap();
    let parsed = parse_container(&container).unwrap();

    // Derive KEK & unwrap VDK with valid credentials
    let kek = ki_vault_lib::crypto::derive_kek(password, &parsed.header.kdf_salt).unwrap();
    let wrap_aad = ki_vault_lib::crypto::build_vdk_wrap_aad(
        parsed.prefix.format_major,
        parsed.prefix.format_minor,
        &parsed.header.vault_id,
        &parsed.header.kdf_salt,
    );
    let vdk = ki_vault_lib::crypto::unwrap_vdk(
        &kek,
        &parsed.header.wrapped_vdk,
        &parsed.header.wrap_nonce,
        &wrap_aad,
    )
    .unwrap();
    let pek = derive_pek(&vdk, &parsed.header.payload_kdf_salt).unwrap();

    // Tamper with created_at in AAD
    let tampered_aad = build_payload_aad(&PayloadAadParams {
        format_major: parsed.prefix.format_major,
        format_minor: parsed.prefix.format_minor,
        header_length: parsed.prefix.header_length,
        created_at: parsed.header.created_at + 1, // Tampered!
        vault_id: &parsed.header.vault_id,
        schema_version: parsed.header.schema_version,
        minimum_reader: parsed.header.minimum_reader,
        payload_kdf_salt: &parsed.header.payload_kdf_salt,
        payload_nonce: &parsed.header.payload_nonce,
        ciphertext_length: parsed.prefix.ciphertext_length,
    });

    let res = decrypt_payload(
        &pek,
        &parsed.header.payload_nonce,
        &tampered_aad,
        &parsed.ciphertext,
    );
    assert!(matches!(
        res,
        Err(AppError::Crypto(CryptoError::TagVerificationFailed))
    ));
}

#[test]
fn test_integration_security_truncation_and_trailing_bytes_rejected() {
    let password = b"password123";
    let payload = make_test_sqlite_image();

    let container = create_vault(password, 1000, 1, 1, &payload).unwrap();

    // 1. Truncated in prefix (< 24B)
    assert!(matches!(
        parse_container(&container[..20]),
        Err(AppError::Vault(VaultError::UnexpectedEof { .. }))
    ));

    // 2. Truncated in header
    let parsed = parse_container(&container).unwrap();
    let cutoff = FIXED_PREFIX_LEN + (parsed.prefix.header_length as usize) / 2;
    assert!(matches!(
        parse_container(&container[..cutoff]),
        Err(AppError::Vault(VaultError::UnexpectedEof { .. }))
    ));

    // 3. Truncated in ciphertext
    assert!(matches!(
        parse_container(&container[..container.len() - 5]),
        Err(AppError::Vault(VaultError::UnexpectedEof { .. }))
    ));

    // 4. Trailing bytes appended
    let mut trailing = container.clone();
    trailing.extend_from_slice(b"MALICIOUS_EXTRA_BYTES");
    assert!(matches!(
        parse_container(&trailing),
        Err(AppError::Vault(VaultError::TrailingContainerBytes(_)))
    ));
}

// ============================================================================
// Integration 3: Password Rotation Invariant (ST-017, ST-030)
// ============================================================================

#[test]
fn test_integration_password_rotation_invariant() {
    let password_v1 = b"old-pass-123";
    let password_v2 = b"new-super-pass-456";
    let payload = make_test_sqlite_image();
    let created_at = 1776999999;

    let container_v1 = create_vault(password_v1, created_at, 1, 1, &payload).unwrap();

    // Execute password rotation
    let container_v2 =
        change_master_password(&container_v1, password_v1, password_v2).expect("rotation succeeds");

    // Old password must now fail
    assert!(matches!(
        unlock_vault(&container_v2, password_v1),
        Err(AppError::Crypto(CryptoError::TagVerificationFailed))
    ));

    // New password unlocks and recovers working in-memory DB
    let unlocked_v2 = unlock_vault(&container_v2, password_v2).expect("unlock v2 succeeds");
    assert!(unlocked_v2.db.is_open());

    // Invariant assertions
    let parsed_v1 = parse_container(&container_v1).unwrap();
    let parsed_v2 = parse_container(&container_v2).unwrap();

    // Exact VDK match
    let unlocked_v1 = unlock_vault(&container_v1, password_v1).unwrap();
    assert_eq!(*unlocked_v1.vdk, *unlocked_v2.vdk);

    // Exact payload ciphertext byte-for-byte match
    assert_eq!(parsed_v1.ciphertext, parsed_v2.ciphertext);

    // Exact header_length match
    assert_eq!(
        parsed_v1.prefix.header_length,
        parsed_v2.prefix.header_length
    );

    // Invariant fields preserved
    assert_eq!(parsed_v1.header.vault_id, parsed_v2.header.vault_id);
    assert_eq!(parsed_v1.header.created_at, parsed_v2.header.created_at);
    assert_eq!(
        parsed_v1.header.schema_version,
        parsed_v2.header.schema_version
    );
    assert_eq!(
        parsed_v1.header.payload_kdf_salt,
        parsed_v2.header.payload_kdf_salt
    );
    assert_eq!(
        parsed_v1.header.payload_nonce,
        parsed_v2.header.payload_nonce
    );

    // Wrapping fields rotated
    assert_ne!(parsed_v1.header.kdf_salt, parsed_v2.header.kdf_salt);
    assert_ne!(parsed_v1.header.wrap_nonce, parsed_v2.header.wrap_nonce);
    assert_ne!(parsed_v1.header.wrapped_vdk, parsed_v2.header.wrapped_vdk);
}

// ============================================================================
// Integration 4: Atomic Persistence & Recovery Safety (ST-019, ST-020, ST-021)
// ============================================================================

#[test]
fn test_integration_persistence_staging_isolation_and_crash_preservation() {
    let guard = TestDirGuard::new("staging_isolation");
    let dest = guard.path.join("primary.kivault");
    let password = b"isolated_pass";
    let payload = make_test_sqlite_image();

    let container_orig = create_vault(password, 1000, 1, 1, &payload).unwrap();
    write_vault_atomic(&dest, &container_orig).expect("first write succeeds");

    // Staging and backup must be cleaned up on success
    let staging = staging_path_for(&dest);
    let backup = backup_path_for(&dest);
    assert!(!staging.exists());
    assert!(!backup.exists());

    // Simulate pre-existing stale staging file
    std::fs::write(&staging, b"unrelated staging file").unwrap();

    // Attempt write with candidate v2 - must fail safely without clobbering destination
    let payload_v2 = make_test_sqlite_image();
    let container_v2 = create_vault(b"newpass", 2000, 1, 1, &payload_v2).unwrap();
    let res = write_vault_atomic(&dest, &container_v2);
    assert!(matches!(
        res,
        Err(AppError::Storage(StorageError::StagingFileExists(_)))
    ));

    // Target must be 100% preserved
    let read_bytes = read_vault(&dest).unwrap();
    assert_eq!(read_bytes, container_orig);
    let unlocked = unlock_vault(&read_bytes, password).unwrap();
    assert!(unlocked.db.is_open());

    // Staging cleanup must succeed since primary is confirmed valid
    assert!(cleanup_stale_staging(&dest).unwrap());
    assert!(!staging.exists());
}

#[test]
fn test_integration_persistence_multi_vault_concurrent_access() {
    let guard = TestDirGuard::new("multi_concurrent");
    let dest_a = Arc::new(guard.path.join("vault_alpha.kivault"));
    let dest_b = Arc::new(guard.path.join("vault_beta.kivault"));

    let payload_a = make_test_sqlite_image();
    let payload_b = make_test_sqlite_image();
    let container_a = Arc::new(create_vault(b"pass_a", 1000, 1, 1, &payload_a).unwrap());
    let container_b = Arc::new(create_vault(b"pass_b", 2000, 1, 1, &payload_b).unwrap());

    // Concurrent writers to different vaults in the same folder
    let dest_a_clone = Arc::clone(&dest_a);
    let cont_a_clone = Arc::clone(&container_a);
    let handle_a = std::thread::spawn(move || write_vault_atomic(&dest_a_clone, &cont_a_clone));

    let dest_b_clone = Arc::clone(&dest_b);
    let cont_b_clone = Arc::clone(&container_b);
    let handle_b = std::thread::spawn(move || write_vault_atomic(&dest_b_clone, &cont_b_clone));

    assert!(handle_a.join().unwrap().is_ok());
    assert!(handle_b.join().unwrap().is_ok());

    assert_eq!(read_vault(&dest_a).unwrap(), *container_a);
    assert_eq!(read_vault(&dest_b).unwrap(), *container_b);
}

// ============================================================================
// Integration 5: Encrypted Database Persistence Pipeline (Phase 4 Langkah 4)
// ============================================================================

#[test]
fn test_integration_encrypted_db_persistence_mutation_roundtrip() {
    let guard = TestDirGuard::new("db_persist_roundtrip");
    let dest = guard.path.join("secure.kivault");
    let password = b"P@ssw0rd!2026-SuperKey";
    let initial_payload = make_test_sqlite_image();

    // 1. Create and write initial vault
    let container = create_vault(password, 1000, 1, 1, &initial_payload).unwrap();
    write_vault_atomic(&dest, &container).unwrap();

    // Verify no plaintext database file exists anywhere in guard directory
    for entry in std::fs::read_dir(&guard.path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().unwrap().to_str().unwrap();
            assert_eq!(
                name, "secure.kivault",
                "Only the encrypted container file may exist"
            );
        }
    }

    // 2. Unlock vault and perform business domain mutations
    let mut unlocked = unlock_vault(&read_vault(&dest).unwrap(), password).unwrap();
    {
        let conn = unlocked.db.conn().unwrap();
        conn.execute(
            "INSERT INTO platforms (id, name, website, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5);",
            ("plat-github", "GitHub", "https://github.com", 1500, 1500),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO accounts (id, platform_id, username, password, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
            ("acc-1", "plat-github", "octocat", "super-secret-token", 1500, 1500),
        )
        .unwrap();
    }

    // 3. Atomically persist changes to disk via save_to_file
    unlocked.save_to_file(&dest).unwrap();

    // 4. Read raw file bytes directly from disk: verify ciphertext is strictly encrypted
    let disk_bytes = std::fs::read(&dest).unwrap();
    let parsed_disk = parse_container(&disk_bytes).unwrap();
    assert_ne!(
        parsed_disk.ciphertext,
        parse_container(&container).unwrap().ciphertext
    );

    // Scan raw bytes on disk: sensitive strings MUST NEVER appear in plaintext
    let disk_str = String::from_utf8_lossy(&disk_bytes);
    assert!(
        !disk_str.contains("octocat"),
        "Username must not appear as plaintext on disk"
    );
    assert!(
        !disk_str.contains("super-secret-token"),
        "Password must not appear as plaintext on disk"
    );

    // 5. Re-unlock from disk and verify persisted records
    let mut re_unlocked = unlock_vault(&read_vault(&dest).unwrap(), password).unwrap();
    let conn = re_unlocked.db.conn().unwrap();

    let username: String = conn
        .query_row(
            "SELECT username FROM accounts WHERE id = ?1;",
            ["acc-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(username, "octocat");

    let pw: String = conn
        .query_row(
            "SELECT password FROM accounts WHERE id = ?1;",
            ["acc-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pw, "super-secret-token");

    // Clean lock
    re_unlocked.lock();
    assert!(!re_unlocked.db.is_open());
}

#[test]
fn test_integration_persistence_preserves_old_vault_on_save_failure() {
    let guard = TestDirGuard::new("save_failure_preservation");
    let dest = guard.path.join("original.kivault");
    let password = b"pass123";
    let initial_payload = make_test_sqlite_image();

    let original_container = create_vault(password, 1000, 1, 1, &initial_payload).unwrap();
    write_vault_atomic(&dest, &original_container).unwrap();

    let mut unlocked = unlock_vault(&read_vault(&dest).unwrap(), password).unwrap();

    // Simulate an invalid schema version tamper in memory before save
    {
        let conn = unlocked.db.conn().unwrap();
        conn.pragma_update(None, "user_version", 99u32).unwrap();
    }

    // Save must fail validation
    let save_res = unlocked.save_to_file(&dest);
    assert!(save_res.is_err());

    // Original file must remain untouched and unlockable
    let disk_bytes = read_vault(&dest).unwrap();
    assert_eq!(disk_bytes, original_container);

    let re_unlocked = unlock_vault(&disk_bytes, password).unwrap();
    assert_eq!(re_unlocked.header.schema_version, 1);
}

// ============================================================================
// Integration 6: Domain Repositories Across Vault Lifecycle (Phase 4 Langkah 5)
// ============================================================================

#[test]
fn test_integration_domain_repositories_save_lock_unlock_roundtrip() {
    use ki_vault_lib::accounts::{
        AccountRepository, CreateAccountParams, CreateCustomFieldParamsInput, ListAccountsFilter,
    };
    use ki_vault_lib::custom_fields::CustomFieldRepository;
    use ki_vault_lib::platforms::{CreatePlatformParams, PlatformRepository};
    use ki_vault_lib::tags::TagRepository;

    let guard = TestDirGuard::new("domain_lifecycle");
    let dest = guard.path.join("domain_vault.kivault");
    let password = b"MasterDomainKey!2026";
    let initial_payload = make_test_sqlite_image();

    // 1. Create and persist fresh vault
    let container = create_vault(password, 1000, 1, 1, &initial_payload).unwrap();
    write_vault_atomic(&dest, &container).unwrap();

    // 2. Unlock vault and populate domain models
    let mut unlocked = unlock_vault(&read_vault(&dest).unwrap(), password).unwrap();
    {
        let plat_repo = PlatformRepository::new(&unlocked.db);
        let tag_repo = TagRepository::new(&unlocked.db);
        let acc_repo = AccountRepository::new(&unlocked.db);

        let platform = plat_repo
            .create(
                CreatePlatformParams {
                    name: "GitLab".into(),
                    category: Some("Developer Tools".into()),
                    website: Some("https://gitlab.com".into()),
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let tag_work = tag_repo.create("Work", 1000).unwrap();
        let tag_dev = tag_repo.create("DevOps", 1000).unwrap();

        acc_repo
            .create(
                CreateAccountParams {
                    platform_id: platform.id.clone(),
                    display_name: Some("Work Account".into()),
                    username: Some("gitlab_worker".into()),
                    email: Some("worker@company.com".into()),
                    password: Some("s3cur3-p@ss".into()),
                    url: Some("https://gitlab.com/company".into()),
                    notes: Some("Requires hardware token".into()),
                    is_favorite: true,
                    tag_ids: vec![tag_work.id.clone(), tag_dev.id.clone()],
                    custom_fields: vec![
                        CreateCustomFieldParamsInput {
                            field_name: "SSH Key Fingerprint".into(),
                            field_value: "SHA256:abc123xyz".into(),
                            field_type: Some("text".into()),
                            is_sensitive: Some(false),
                        },
                        CreateCustomFieldParamsInput {
                            field_name: "Personal Access Token".into(),
                            field_value: "glpat-secret-token".into(),
                            field_type: Some("secret".into()),
                            is_sensitive: Some(true),
                        },
                    ],
                },
                1100,
            )
            .unwrap();
    }

    // 3. Save to container & file
    unlocked.save_to_file(&dest).unwrap();

    // 4. Lock vault (zeroize runtime memory)
    unlocked.lock();
    assert!(!unlocked.db.is_open());
    assert_eq!(*unlocked.vdk, [0u8; 32]);

    // 5. Re-unlock from disk with correct password
    let mut re_unlocked = unlock_vault(&read_vault(&dest).unwrap(), password).unwrap();
    {
        let plat_repo = PlatformRepository::new(&re_unlocked.db);
        let tag_repo = TagRepository::new(&re_unlocked.db);
        let acc_repo = AccountRepository::new(&re_unlocked.db);
        let cf_repo = CustomFieldRepository::new(&re_unlocked.db);

        // Verify platform
        let platforms = plat_repo.list().unwrap();
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].name, "GitLab");
        assert_eq!(platforms[0].account_count, 1);

        // Verify accounts listing
        let accounts = acc_repo
            .list(ListAccountsFilter {
                platform_id: Some(platforms[0].id.clone()),
                favorite_only: true,
                tag_id: None,
            })
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].username.as_deref(), Some("gitlab_worker"));

        // Verify full account detail
        let detail = acc_repo.get_detail(&accounts[0].id).unwrap();
        assert_eq!(detail.tags.len(), 2);
        let tag_names: Vec<String> = detail.tags.iter().map(|t| t.name.clone()).collect();
        assert!(tag_names.contains(&"Work".to_string()));
        assert!(tag_names.contains(&"DevOps".to_string()));

        assert_eq!(detail.custom_fields.len(), 2);
        let token_cf = detail
            .custom_fields
            .iter()
            .find(|cf| cf.field_name == "Personal Access Token")
            .unwrap();
        assert_eq!(token_cf.field_value, "glpat-secret-token");
        assert!(token_cf.is_sensitive);

        // Test cascade deletion across repositories
        plat_repo.delete(&platforms[0].id).unwrap();
        assert!(acc_repo
            .list(ListAccountsFilter::default())
            .unwrap()
            .is_empty());
        assert!(cf_repo.list_by_account(&accounts[0].id).unwrap().is_empty());
        assert!(tag_repo
            .list_by_account(&accounts[0].id)
            .unwrap()
            .is_empty());
    }

    // Clean lock
    re_unlocked.lock();
    assert!(!re_unlocked.db.is_open());
}
