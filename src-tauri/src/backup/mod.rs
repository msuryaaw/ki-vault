//! Backup and Restore Domain Logic
//!
//! Implements encrypted snapshot creation, validation, and atomic restore
//! in accordance with `vault-format.md` (§16, §17) and `api-contract.md` (§12).
//!
//! # Security Properties
//! - Backup files are complete `.kivault` containers, encrypted with standard vault format.
//! - Creating a backup creates an encrypted snapshot from the active vault's database.
//! - Restoring from a backup validates the backup container and decrypts using the backup master password.
//! - After decrypting the backup DB, it is re-encrypted using the active vault's VDK and freshly generated salts and nonces.
//! - The active vault's master password remains strictly unchanged.
//! - Atomic restore writes to the active vault path using `write_vault_atomic`. If any step fails before
//!   or during atomic replacement, the active vault file on disk and the active in-memory state remain uncorrupted.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::errors::{AppError, BackupError, Result, StorageError, VaultError};
use crate::vault::container::parse_container;
use crate::vault::operations::{unlock_vault, UnlockedVault};
use crate::vault::sqlite::InMemoryDb;
use crate::vault::storage::write_vault_atomic;
use crate::vault::{MAX_CIPHERTEXT_LEN, MIN_CIPHERTEXT_LEN};

/// Maximum path length limit for backup files to prevent path exhaustion / buffer issues.
pub const MAX_BACKUP_PATH_LEN: usize = 4096;

/// Confirmation string required for destructive restore operations.
pub const RESTORE_CONFIRMATION_TOKEN: &str = "CONFIRM_RESTORE";

/// Check if a path is a symlink, reparse point, or directory junction.
pub fn reject_symlink_or_reparse(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if let Ok(meta) = path.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(BackupError::InvalidPath(format!(
                    "Symlinks are rejected for security: {}",
                    path.display()
                ))
                .into());
            }
        }

        let path_w = win32_path_to_wide(path);
        let attrs = unsafe { win32_get_file_attributes_w(path_w.as_ptr()) };
        if attrs != 0xFFFF_FFFF && (attrs & 0x0400) != 0 {
            return Err(BackupError::InvalidPath(format!(
                "Reparse points and directory junctions are rejected for security: {}",
                path.display()
            ))
            .into());
        }
    }

    #[cfg(unix)]
    {
        if let Ok(meta) = path.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(BackupError::InvalidPath(format!(
                    "Symlinks are rejected for security: {}",
                    path.display()
                ))
                .into());
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn win32_path_to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
unsafe fn win32_get_file_attributes_w(lp_file_name: *const u16) -> u32 {
    extern "system" {
        fn GetFileAttributesW(lpFileName: *const u16) -> u32;
    }
    GetFileAttributesW(lp_file_name)
}

/// Validate that a path and all its existing ancestor directories are free from symlinks and reparse points.
pub fn validate_path_safety(path: &Path) -> Result<()> {
    reject_symlink_or_reparse(path)?;

    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if ancestor.exists() {
            reject_symlink_or_reparse(ancestor)?;
        }
        current = ancestor.parent();
    }
    Ok(())
}

/// Validate backup destination path for creating a backup.
pub fn validate_backup_destination_path(destination: &Path) -> Result<()> {
    let path_str = destination.as_os_str().to_string_lossy();
    if path_str.trim().is_empty() {
        return Err(BackupError::InvalidPath("Backup path must not be empty.".into()).into());
    }
    if path_str.len() > MAX_BACKUP_PATH_LEN {
        return Err(BackupError::InvalidPath(format!(
            "Backup path exceeds maximum allowed length of {MAX_BACKUP_PATH_LEN} bytes."
        ))
        .into());
    }

    match destination.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("kivault") => {}
        _ => {
            return Err(BackupError::InvalidPath(
                "Backup file must have a .kivault extension.".into(),
            )
            .into())
        }
    }

    if destination.is_dir() {
        return Err(
            BackupError::InvalidPath("Backup destination cannot be a directory.".into()).into(),
        );
    }

    validate_path_safety(destination)?;

    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if !parent.exists() || !parent.is_dir() {
        return Err(BackupError::InvalidPath(
            "Backup destination parent directory does not exist or is not a directory.".into(),
        )
        .into());
    }

    Ok(())
}

/// Validate backup source path for restoring from a backup.
pub fn validate_backup_source_path(source: &Path) -> Result<()> {
    let path_str = source.as_os_str().to_string_lossy();
    if path_str.trim().is_empty() {
        return Err(
            BackupError::InvalidPath("Backup source path must not be empty.".into()).into(),
        );
    }
    if path_str.len() > MAX_BACKUP_PATH_LEN {
        return Err(BackupError::InvalidPath(format!(
            "Backup path exceeds maximum allowed length of {MAX_BACKUP_PATH_LEN} bytes."
        ))
        .into());
    }

    match source.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("kivault") => {}
        _ => {
            return Err(BackupError::InvalidPath(
                "Backup source file must have a .kivault extension.".into(),
            )
            .into())
        }
    }

    if !source.exists() {
        return Err(BackupError::InvalidPath("Backup source file does not exist.".into()).into());
    }

    if source.is_dir() {
        return Err(BackupError::InvalidPath("Backup source cannot be a directory.".into()).into());
    }

    validate_path_safety(source)?;

    let meta = source
        .metadata()
        .map_err(|e| BackupError::InvalidPath(format!("Failed to read backup metadata: {e}")))?;
    let file_len = meta.len();

    // Check minimum and maximum file size bounds
    let min_expected = 24 + 1 + MIN_CIPHERTEXT_LEN;
    let max_expected = 24 + 65536 + MAX_CIPHERTEXT_LEN;
    if file_len < min_expected || file_len > max_expected {
        return Err(BackupError::InvalidContainer(format!(
            "Backup file size ({file_len} bytes) is outside valid container limits."
        ))
        .into());
    }

    Ok(())
}

/// Create a backup of the active unlocked vault at `destination`.
///
/// # Semantics
/// - Generates a fresh `.kivault` encrypted snapshot using the active vault's in-memory DB and VDK.
/// - Fresh per-save salt and nonce are generated.
/// - Writes directly to the destination path with restrictive permissions.
pub fn create_encrypted_snapshot(
    unlocked_vault: &mut UnlockedVault,
    destination: &Path,
) -> Result<()> {
    validate_backup_destination_path(destination)?;

    // Serialize and encrypt current active vault DB
    let snapshot_bytes = unlocked_vault.save_to_container().map_err(|e| {
        BackupError::CreationFailed(format!("Failed to generate encrypted snapshot: {e}"))
    })?;

    // Pre-validate container bytes
    parse_container(&snapshot_bytes).map_err(|e| {
        BackupError::CreationFailed(format!(
            "Generated snapshot failed container validation: {e}"
        ))
    })?;

    // Write file to destination
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(destination).map_err(|e| {
        BackupError::CreationFailed(format!("Failed to open destination for writing: {e}"))
    })?;

    file.write_all(&snapshot_bytes)
        .map_err(|e| BackupError::CreationFailed(format!("Failed to write snapshot bytes: {e}")))?;

    file.sync_all()
        .map_err(|e| BackupError::CreationFailed(format!("Failed to flush backup file: {e}")))?;

    Ok(())
}

/// Validate a backup file without restoring it.
///
/// Ensures the file exists, has a valid container format, and can be decrypted with `backup_password`.
/// Returns the decrypted backup's `UnlockedVault` on success.
pub fn validate_backup(backup_bytes: &[u8], backup_password: &[u8]) -> Result<UnlockedVault> {
    // 1. Validate container header and bounds
    let _parsed = parse_container(backup_bytes).map_err(|e| match e {
        AppError::Vault(v_err) => match v_err {
            VaultError::InvalidMagic(_)
            | VaultError::UnsupportedVersion { .. }
            | VaultError::HeaderLengthOutOfBounds(_)
            | VaultError::CiphertextLengthOutOfBounds(_)
            | VaultError::FileSizeMismatch { .. }
            | VaultError::HeaderLengthMismatch { .. }
            | VaultError::CiphertextLengthMismatch { .. }
            | VaultError::TrailingContainerBytes(_)
            | VaultError::TrailingHeaderBytes(_)
            | VaultError::CborDecodeError(_)
            | VaultError::CborNonDeterministic(_) => {
                AppError::Backup(BackupError::InvalidContainer(v_err.to_string()))
            }
            other => AppError::Vault(other),
        },
        other => other,
    })?;

    // 2. Unlock and decrypt using backup master password
    unlock_vault(backup_bytes, backup_password).map_err(|e| match e {
        AppError::Crypto(crate::errors::CryptoError::TagVerificationFailed) => {
            AppError::Backup(BackupError::AuthenticationFailed)
        }
        AppError::Vault(v) => AppError::Backup(BackupError::InvalidContainer(v.to_string())),
        AppError::Database(d) => AppError::Backup(BackupError::InvalidContainer(d.to_string())),
        other => other,
    })
}

/// Restore backup into active vault atomically.
///
/// # Requirements (§17 of `vault-format.md`, ADR-013):
/// 1. Validate backup container using `backup_password`.
/// 2. Decrypt and validate backup SQLite DB.
/// 3. Import backup contents into active vault.
/// 4. Re-encrypt using active vault's VDK, fresh payload salt and fresh nonce.
/// 5. Keep active vault's master password intact.
/// 6. Atomic-write to the active vault path.
/// 7. If any error occurs prior to or during write, the active vault on disk and in memory is NOT corrupted.
pub fn restore_from_backup(
    backup_bytes: &[u8],
    backup_password: &[u8],
    active_unlocked: &mut UnlockedVault,
    active_vault_path: &Path,
    confirmation: &str,
) -> Result<()> {
    if confirmation != RESTORE_CONFIRMATION_TOKEN {
        return Err(BackupError::ConfirmationRequired.into());
    }

    // 1 & 2. Validate and decrypt backup
    let backup_unlocked = validate_backup(backup_bytes, backup_password)?;

    // 3. Serialize backup DB to verify it's cleanly readable and valid SQLite image
    let backup_image = backup_unlocked.db.to_image().map_err(|e| {
        BackupError::RestoreFailed(format!("Failed to serialize backup database image: {e}"))
    })?;

    // 4. Create an InMemoryDb from the image to test swap
    let new_active_db = InMemoryDb::from_image(&backup_image).map_err(|e| {
        BackupError::RestoreFailed(format!("Failed to import backup database into memory: {e}"))
    })?;

    // 5. Pre-serialize and encrypt using ACTIVE vault's VDK into candidate container bytes.
    // To ensure failure-safety: if save_to_container or atomic write fails, active_unlocked
    // is restored back to its previous DB and header.
    let old_header = active_unlocked.header.clone();
    let old_db = std::mem::replace(&mut active_unlocked.db, new_active_db);

    let container_bytes = match active_unlocked.save_to_container() {
        Ok(bytes) => bytes,
        Err(e) => {
            // Roll back in-memory active state immediately
            active_unlocked.header = old_header;
            active_unlocked.db = old_db;
            return Err(BackupError::RestoreFailed(format!(
                "Failed to re-encrypt backup with active VDK: {e}"
            ))
            .into());
        }
    };

    // 6. Atomic write to active vault path
    if let Err(e) = write_vault_atomic(active_vault_path, &container_bytes) {
        // Roll back in-memory active state on atomic write failure
        active_unlocked.header = old_header;
        active_unlocked.db = old_db;
        return match e {
            AppError::Storage(StorageError::ReplacementFailed(msg)) => Err(AppError::Backup(
                BackupError::RestoreFailed(format!("Atomic replacement failed: {msg}")),
            )),
            other => Err(other),
        };
    }

    // backup_unlocked goes out of scope and drops, zeroizing backup VDK
    drop(backup_unlocked);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::operations::create_vault;
    use crate::vault::sqlite::SCHEMA_VERSION_V1;
    use crate::vault::storage::read_vault;
    use std::path::PathBuf;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let uuid = format!("{:016x}", rand_u64());
            let path = std::env::temp_dir().join(format!("kivault_backup_test_{tag}_{uuid}"));
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

    fn create_test_vault(password: &str, note: &str) -> (Vec<u8>, UnlockedVault) {
        let db = InMemoryDb::create_empty().unwrap();
        {
            let conn = db.conn().unwrap();
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                rusqlite::params!["0123456789abcdef0123456789abcdef", note, 1000, 1000],
            )
            .unwrap();
        }
        let image = db.to_image().unwrap();
        let container_bytes = create_vault(
            password.as_bytes(),
            1000,
            SCHEMA_VERSION_V1,
            SCHEMA_VERSION_V1,
            &image,
        )
        .unwrap();
        let unlocked = unlock_vault(&container_bytes, password.as_bytes()).unwrap();
        (container_bytes, unlocked)
    }

    #[test]
    fn test_create_backup_success() {
        let tmp = TempDir::new("create_success");
        let backup_path = tmp.file("test_backup.kivault");

        let (_bytes, mut active) = create_test_vault("pass123", "Primary Vault");

        create_encrypted_snapshot(&mut active, &backup_path).unwrap();
        assert!(backup_path.exists());

        // Validate that the created backup is a valid container and can be unlocked with active pass
        let read_bytes = std::fs::read(&backup_path).unwrap();
        let unlocked = unlock_vault(&read_bytes, b"pass123").unwrap();
        let conn = unlocked.db.conn().unwrap();
        let name: String = conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Primary Vault");
    }

    #[test]
    fn test_create_backup_invalid_extension_rejected() {
        let tmp = TempDir::new("invalid_ext");
        let backup_path = tmp.file("backup.txt");
        let (_bytes, mut active) = create_test_vault("pass123", "Vault");

        let res = create_encrypted_snapshot(&mut active, &backup_path);
        assert!(matches!(
            res,
            Err(AppError::Backup(BackupError::InvalidPath(_)))
        ));
    }

    #[test]
    fn test_create_backup_nonexistent_parent_rejected() {
        let tmp = TempDir::new("no_parent");
        let backup_path = tmp.path.join("nonexistent_dir").join("backup.kivault");
        let (_bytes, mut active) = create_test_vault("pass123", "Vault");

        let res = create_encrypted_snapshot(&mut active, &backup_path);
        assert!(matches!(
            res,
            Err(AppError::Backup(BackupError::InvalidPath(_)))
        ));
    }

    #[test]
    fn test_restore_wrong_password_fails() {
        let tmp = TempDir::new("wrong_pass");
        let active_path = tmp.file("active.kivault");
        let (active_bytes, mut active) = create_test_vault("active_pass", "Active Vault");
        write_vault_atomic(&active_path, &active_bytes).unwrap();

        let (backup_bytes, _backup_unlocked) = create_test_vault("backup_pass", "Backup Vault");

        let res = restore_from_backup(
            &backup_bytes,
            b"wrong_password",
            &mut active,
            &active_path,
            RESTORE_CONFIRMATION_TOKEN,
        );

        assert!(matches!(
            res,
            Err(AppError::Backup(BackupError::AuthenticationFailed))
        ));

        // Active vault file and state should remain unchanged
        let conn = active.db.conn().unwrap();
        let name: String = conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Active Vault");
    }

    #[test]
    fn test_restore_corrupt_backup_fails() {
        let tmp = TempDir::new("corrupt_backup");
        let active_path = tmp.file("active.kivault");
        let (active_bytes, mut active) = create_test_vault("active_pass", "Active Vault");
        write_vault_atomic(&active_path, &active_bytes).unwrap();

        let mut corrupt_bytes = vec![0u8; 100];
        corrupt_bytes[0..8].copy_from_slice(b"KIVAULT\0");

        let res = restore_from_backup(
            &corrupt_bytes,
            b"backup_pass",
            &mut active,
            &active_path,
            RESTORE_CONFIRMATION_TOKEN,
        );

        assert!(matches!(
            res,
            Err(AppError::Backup(BackupError::InvalidContainer(_)))
        ));
    }

    #[test]
    fn test_restore_confirmation_required() {
        let tmp = TempDir::new("no_confirm");
        let active_path = tmp.file("active.kivault");
        let (active_bytes, mut active) = create_test_vault("active_pass", "Active Vault");
        write_vault_atomic(&active_path, &active_bytes).unwrap();

        let (backup_bytes, _backup_unlocked) = create_test_vault("backup_pass", "Backup Vault");

        let res = restore_from_backup(
            &backup_bytes,
            b"backup_pass",
            &mut active,
            &active_path,
            "NO_CONFIRMATION",
        );

        assert!(matches!(
            res,
            Err(AppError::Backup(BackupError::ConfirmationRequired))
        ));
    }

    #[test]
    fn test_restore_success_preserves_active_master_password() {
        let tmp = TempDir::new("restore_success");
        let active_path = tmp.file("active.kivault");

        // 1. Setup active vault with password "active_pass"
        let (active_bytes, mut active) = create_test_vault("active_pass", "Active Vault");
        write_vault_atomic(&active_path, &active_bytes).unwrap();

        // 2. Setup backup vault with password "backup_pass" and distinct data
        let (backup_bytes, _backup_unlocked) =
            create_test_vault("backup_pass", "Restored Backup Data");

        // 3. Restore backup into active vault
        restore_from_backup(
            &backup_bytes,
            b"backup_pass",
            &mut active,
            &active_path,
            RESTORE_CONFIRMATION_TOKEN,
        )
        .unwrap();

        // 4. Verify in-memory database has the backup's data
        let conn = active.db.conn().unwrap();
        let name: String = conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Restored Backup Data");

        // 5. Read the active vault from disk and ensure it unlocks with the ACTIVE password, NOT the backup password
        let on_disk_bytes = read_vault(&active_path).unwrap();

        // Unlocking with active_pass must succeed
        let disk_unlocked = unlock_vault(&on_disk_bytes, b"active_pass")
            .expect("Active password must remain in force");
        let disk_conn = disk_unlocked.db.conn().unwrap();
        let disk_name: String = disk_conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(disk_name, "Restored Backup Data");

        // Unlocking with backup_pass must fail
        assert!(unlock_vault(&on_disk_bytes, b"backup_pass").is_err());
    }

    #[test]
    fn test_restore_failure_leaves_active_vault_unchanged() {
        let tmp = TempDir::new("rollback_on_failure");
        let active_path = tmp.file("active.kivault");

        let (active_bytes, mut active) = create_test_vault("active_pass", "Original Active Vault");
        write_vault_atomic(&active_path, &active_bytes).unwrap();

        // Attempt restore with corrupted backup bytes
        let corrupt_backup = b"not a kivault container";
        let res = restore_from_backup(
            corrupt_backup,
            b"backup_pass",
            &mut active,
            &active_path,
            RESTORE_CONFIRMATION_TOKEN,
        );

        assert!(res.is_err());

        // In-memory data is unchanged
        let conn = active.db.conn().unwrap();
        let name: String = conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Original Active Vault");

        // On-disk file is unchanged and still unlocks with active_pass
        let on_disk_bytes = read_vault(&active_path).unwrap();
        let disk_unlocked = unlock_vault(&on_disk_bytes, b"active_pass").unwrap();
        let disk_conn = disk_unlocked.db.conn().unwrap();
        let disk_name: String = disk_conn
            .query_row("SELECT name FROM vault_metadata LIMIT 1;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(disk_name, "Original Active Vault");
    }
}
