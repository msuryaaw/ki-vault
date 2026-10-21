//! Backup & Restore Tauri Commands
//!
//! Implements typed Tauri commands according to `docs/api-contract.md` §12:
//! - `create_backup`
//! - `restore_backup`
//!
//! # Security Properties
//! - Commands enforce that the active vault is Unlocked.
//! - Passwords received from frontend are wrapped in `Zeroizing` and wiped immediately.
//! - Destination / source paths are strictly validated against length, reparse points, and `.kivault` extension.
//! - Restoring from backup decrypts using the backup password, then re-encrypts using active VDK with fresh salts/nonces.
//! - Active vault's master password remains in force after restore.
//! - Atomicity: failure before or during replacement leaves active vault unchanged.

use std::path::PathBuf;
use tauri::State;
use zeroize::Zeroizing;

use crate::backup::{
    create_encrypted_snapshot, restore_from_backup, validate_backup_destination_path,
    validate_backup_source_path,
};
use crate::commands::vault::{
    map_error, CommandError, SharedAutoLock, SharedVaultState, VaultState,
};

/// Maximum password length in bytes (matches api-contract limit).
const MAX_PASSWORD_BYTES: usize = 1024;

fn validate_password(password: &str) -> std::result::Result<(), CommandError> {
    if password.is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Password must not be empty.",
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(CommandError::new(
            "InvalidInput",
            format!("Password exceeds maximum length of {MAX_PASSWORD_BYTES} bytes."),
        ));
    }
    Ok(())
}

/// Create a new encrypted vault snapshot at `destination_path`.
///
/// Requires the active vault to be Unlocked.
#[tauri::command]
pub fn create_backup(
    destination_path: String,
    auto_lock: State<'_, SharedAutoLock>,
    state: State<'_, SharedVaultState>,
) -> std::result::Result<(), CommandError> {
    create_backup_impl(&auto_lock, &state, destination_path)
}

pub fn create_backup_impl(
    auto_lock: &SharedAutoLock,
    shared: &SharedVaultState,
    destination_path: String,
) -> std::result::Result<(), CommandError> {
    let dest = PathBuf::from(destination_path);
    validate_backup_destination_path(&dest).map_err(map_error)?;

    // Follow strict lock order: AutoLockRuntime -> VaultState
    let mut al = auto_lock.0.lock().map_err(|_| {
        CommandError::new("Internal", "Internal auto-lock runtime lock was poisoned.")
    })?;

    if al.is_locked {
        return Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        ));
    }

    let mut vs = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;

    match &mut *vs {
        VaultState::Unlocked { path, vault } => {
            // Security safeguard: backup destination cannot be the active vault file itself
            if dest == *path || dest.canonicalize().ok() == path.canonicalize().ok() {
                return Err(CommandError::new(
                    "InvalidInput",
                    "Backup destination cannot be the active vault file.",
                ));
            }

            create_encrypted_snapshot(vault, &dest).map_err(map_error)?;
            al.last_activity = std::time::Instant::now();
            Ok(())
        }
        _ => {
            al.is_locked = true;
            Err(CommandError::new(
                "VaultLocked",
                "The vault must be unlocked to perform this operation.",
            ))
        }
    }
}

/// Restore backup into active vault.
///
/// Requires the active vault to be Unlocked, valid backup password, and explicit confirmation token.
/// Active vault master password remains preserved.
#[tauri::command]
pub fn restore_backup(
    backup_path: String,
    backup_master_password: String,
    confirmation: String,
    auto_lock: State<'_, SharedAutoLock>,
    state: State<'_, SharedVaultState>,
) -> std::result::Result<(), CommandError> {
    restore_backup_impl(
        &auto_lock,
        &state,
        backup_path,
        backup_master_password,
        confirmation,
    )
}

pub fn restore_backup_impl(
    auto_lock: &SharedAutoLock,
    shared: &SharedVaultState,
    backup_path: String,
    backup_master_password: String,
    confirmation: String,
) -> std::result::Result<(), CommandError> {
    validate_password(&backup_master_password)?;

    let src = PathBuf::from(backup_path);
    validate_backup_source_path(&src).map_err(map_error)?;

    let password_bytes = Zeroizing::new(backup_master_password.into_bytes());

    let backup_bytes = std::fs::read(&src).map_err(|e| {
        CommandError::new(
            "FileOperationFailed",
            format!("Failed to read backup file: {e}"),
        )
    })?;

    // Follow strict lock order: AutoLockRuntime -> VaultState
    let mut al = auto_lock.0.lock().map_err(|_| {
        CommandError::new("Internal", "Internal auto-lock runtime lock was poisoned.")
    })?;

    if al.is_locked {
        return Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        ));
    }

    let mut vs = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;

    match &mut *vs {
        VaultState::Unlocked { path, vault } => {
            // Security safeguard: backup source cannot be the active vault file itself
            if src == *path || src.canonicalize().ok() == path.canonicalize().ok() {
                return Err(CommandError::new(
                    "InvalidInput",
                    "Backup source cannot be the active vault file itself.",
                ));
            }

            restore_from_backup(&backup_bytes, &password_bytes, vault, path, &confirmation)
                .map_err(map_error)?;

            al.last_activity = std::time::Instant::now();
            Ok(())
        }
        _ => {
            al.is_locked = true;
            Err(CommandError::new(
                "VaultLocked",
                "The vault must be unlocked to perform this operation.",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::RESTORE_CONFIRMATION_TOKEN;
    use crate::commands::vault::unlock_vault_impl;
    use crate::vault::operations::create_vault;
    use crate::vault::sqlite::{InMemoryDb, SCHEMA_VERSION_V1};
    use crate::vault::storage::write_vault_atomic;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let uuid = format!("{:016x}", rand_u64());
            let path = std::env::temp_dir().join(format!("kivault_backup_cmd_test_{tag}_{uuid}"));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn rand_u64() -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        std::thread::current().id().hash(&mut h);
        h.finish()
    }

    fn setup_unlocked_vault(
        dir: &TempDir,
        file_name: &str,
        password: &str,
        vault_name: &str,
    ) -> (PathBuf, SharedAutoLock, SharedVaultState) {
        let vault_path = dir.file(file_name);
        let db = InMemoryDb::create_empty().unwrap();
        {
            let conn = db.conn().unwrap();
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                rusqlite::params!["0123456789abcdef0123456789abcdef", vault_name, 1000, 1000],
            )
            .unwrap();
        }
        let image = db.to_image().unwrap();
        let container = create_vault(
            password.as_bytes(),
            1000,
            SCHEMA_VERSION_V1,
            SCHEMA_VERSION_V1,
            &image,
        )
        .unwrap();
        write_vault_atomic(&vault_path, &container).unwrap();

        let auto_lock = SharedAutoLock::new();
        let state = SharedVaultState::new();

        unlock_vault_impl(
            &auto_lock,
            &state,
            password.to_string(),
            Some(vault_path.to_str().unwrap().to_string()),
        )
        .unwrap();

        (vault_path, auto_lock, state)
    }

    #[test]
    fn test_command_create_backup_success() {
        let tmp = TempDir::new("cmd_create_success");
        let (_vault_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "My Active Vault");

        let backup_path = tmp.file("snapshot.kivault");
        create_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
        )
        .unwrap();

        assert!(backup_path.exists());
    }

    #[test]
    fn test_command_create_backup_invalid_path_rejected() {
        let tmp = TempDir::new("cmd_create_invalid_path");
        let (_vault_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "My Active Vault");

        // Wrong extension
        let invalid_path = tmp.file("snapshot.txt");
        let err = create_backup_impl(
            &auto_lock,
            &state,
            invalid_path.to_str().unwrap().to_string(),
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
    }

    #[test]
    fn test_command_create_backup_when_locked_fails() {
        let tmp = TempDir::new("cmd_create_locked");
        let (_vault_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "My Active Vault");

        // Lock the auto_lock runtime
        {
            let mut al = auto_lock.0.lock().unwrap();
            al.is_locked = true;
        }

        let backup_path = tmp.file("snapshot.kivault");
        let err = create_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
        )
        .unwrap_err();
        assert_eq!(err.code, "VaultLocked");
    }

    #[test]
    fn test_command_restore_backup_success() {
        let tmp = TempDir::new("cmd_restore_success");
        let (active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "Initial Vault");

        // Create a backup snapshot from a different vault
        let backup_path = tmp.file("backup.kivault");
        {
            let (_bp, backup_al, backup_st) =
                setup_unlocked_vault(&tmp, "temp.kivault", "backup-pass-99", "Restored Name");
            create_backup_impl(
                &backup_al,
                &backup_st,
                backup_path.to_str().unwrap().to_string(),
            )
            .unwrap();
        }

        // Restore into active vault
        restore_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
            "backup-pass-99".to_string(),
            RESTORE_CONFIRMATION_TOKEN.to_string(),
        )
        .unwrap();

        // Verify active vault in-memory has the restored content
        {
            let guard = state.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let conn = vault.db.conn().unwrap();
                let name: String = conn
                    .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(name, "Restored Name");
            } else {
                panic!("Vault should still be unlocked");
            }
        }

        // Verify active vault on-disk unlocks with the ACTIVE password, NOT the backup password
        let disk_bytes = crate::vault::storage::read_vault(&active_path).unwrap();
        let unlocked = crate::vault::operations::unlock_vault(&disk_bytes, b"active-pass-1")
            .expect("Active master password must remain in force");
        let disk_conn = unlocked.db.conn().unwrap();
        let disk_name: String = disk_conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(disk_name, "Restored Name");

        // Backup password cannot unlock active vault file
        assert!(crate::vault::operations::unlock_vault(&disk_bytes, b"backup-pass-99").is_err());
    }

    #[test]
    fn test_command_restore_backup_wrong_password_rejected() {
        let tmp = TempDir::new("cmd_restore_wrong_pass");
        let (active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "Initial Vault");

        let backup_path = tmp.file("backup.kivault");
        {
            let (_bp, backup_al, backup_st) =
                setup_unlocked_vault(&tmp, "temp.kivault", "backup-pass-99", "Restored Name");
            create_backup_impl(
                &backup_al,
                &backup_st,
                backup_path.to_str().unwrap().to_string(),
            )
            .unwrap();
        }

        let err = restore_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
            "wrong-password".to_string(),
            RESTORE_CONFIRMATION_TOKEN.to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "AuthenticationFailed");

        // Verify active vault data is untouched
        let disk_bytes = crate::vault::storage::read_vault(&active_path).unwrap();
        let unlocked =
            crate::vault::operations::unlock_vault(&disk_bytes, b"active-pass-1").unwrap();
        let disk_conn = unlocked.db.conn().unwrap();
        let disk_name: String = disk_conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(disk_name, "Initial Vault");
    }

    #[test]
    fn test_command_restore_backup_corrupted_file_rejected() {
        let tmp = TempDir::new("cmd_restore_corrupt");
        let (active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "Initial Vault");

        let backup_path = tmp.file("corrupt.kivault");
        std::fs::write(
            &backup_path,
            b"KIVAULT\0corrupted-payload-data-here-12345678",
        )
        .unwrap();

        let err = restore_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
            "backup-pass-99".to_string(),
            RESTORE_CONFIRMATION_TOKEN.to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "IntegrityFailure");

        // Verify active vault is untouched
        let disk_bytes = crate::vault::storage::read_vault(&active_path).unwrap();
        let unlocked =
            crate::vault::operations::unlock_vault(&disk_bytes, b"active-pass-1").unwrap();
        let disk_conn = unlocked.db.conn().unwrap();
        let disk_name: String = disk_conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(disk_name, "Initial Vault");
    }

    #[test]
    fn test_command_restore_backup_invalid_path_rejected() {
        let tmp = TempDir::new("cmd_restore_invalid_path");
        let (_active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "Initial Vault");

        let nonexistent = tmp.file("nonexistent.kivault");
        let err = restore_backup_impl(
            &auto_lock,
            &state,
            nonexistent.to_str().unwrap().to_string(),
            "pass".to_string(),
            RESTORE_CONFIRMATION_TOKEN.to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "InvalidInput");
    }

    #[test]
    fn test_command_restore_backup_without_confirmation_rejected() {
        let tmp = TempDir::new("cmd_restore_no_confirm");
        let (_active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "Initial Vault");

        let backup_path = tmp.file("backup.kivault");
        {
            let (_bp, backup_al, backup_st) =
                setup_unlocked_vault(&tmp, "temp.kivault", "backup-pass-99", "Restored Name");
            create_backup_impl(
                &backup_al,
                &backup_st,
                backup_path.to_str().unwrap().to_string(),
            )
            .unwrap();
        }

        let err = restore_backup_impl(
            &auto_lock,
            &state,
            backup_path.to_str().unwrap().to_string(),
            "backup-pass-99".to_string(),
            "INVALID_TOKEN".to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "InvalidInput");
    }

    #[test]
    fn test_command_create_backup_targeting_active_vault_rejected() {
        let tmp = TempDir::new("cmd_create_active_collision");
        let (active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "My Active Vault");

        // Attempting to create backup directly over active vault file
        let err = create_backup_impl(
            &auto_lock,
            &state,
            active_path.to_str().unwrap().to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("cannot be the active vault file"));
    }

    #[test]
    fn test_command_restore_backup_from_active_vault_rejected() {
        let tmp = TempDir::new("cmd_restore_active_collision");
        let (active_path, auto_lock, state) =
            setup_unlocked_vault(&tmp, "active.kivault", "active-pass-1", "My Active Vault");

        // Attempting to restore active vault file into itself
        let err = restore_backup_impl(
            &auto_lock,
            &state,
            active_path.to_str().unwrap().to_string(),
            "active-pass-1".to_string(),
            RESTORE_CONFIRMATION_TOKEN.to_string(),
        )
        .unwrap_err();

        assert_eq!(err.code, "InvalidInput");
        assert!(err
            .message
            .contains("cannot be the active vault file itself"));
    }
}
