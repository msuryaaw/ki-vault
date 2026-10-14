use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use crate::errors::{Result, StorageError};
use crate::vault::container::parse_container;

/// Global registry tracking active vault write operations in this process to prevent races.
static ACTIVE_OPERATIONS: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Return the canonical staging path for a given destination vault path (§12.1).
///
/// Each vault has its own dedicated staging file based on its filename (e.g. `.<filename>.tmp`)
/// so that multiple vaults within the same directory do not collide.
pub fn staging_path_for(destination: &Path) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    parent.join(format!(".{file_name}.tmp"))
}

/// Return the canonical backup path for a given destination vault path (§12.3).
///
/// Each vault has its own dedicated backup file based on its filename (e.g. `.<filename>.bak`).
pub fn backup_path_for(destination: &Path) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    parent.join(format!(".{file_name}.bak"))
}

/// Return the canonical coordination lock path for a given destination vault path.
pub fn lock_path_for(destination: &Path) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    parent.join(format!(".{file_name}.lock"))
}

/// Normalize path for consistent in-process lookup.
fn normalize_path(path: &Path) -> PathBuf {
    if let Ok(can) = path.canonicalize() {
        can
    } else if let Some(parent) = path.parent() {
        if let Ok(can_parent) = parent.canonicalize() {
            if let Some(file_name) = path.file_name() {
                return can_parent.join(file_name);
            }
        }
        path.to_path_buf()
    } else {
        path.to_path_buf()
    }
}

/// Check if a path is a symlink, reparse point, or directory junction (§12.4, SEC-ST02/ST03).
fn reject_symlink_or_reparse(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        // 1. Rust symlink_metadata check
        if let Ok(meta) = path.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(StorageError::InvalidPath(format!(
                    "Symlinks are rejected for security: {}",
                    path.display()
                ))
                .into());
            }
        }

        // 2. Win32 GetFileAttributesW check (detects NTFS Directory Junctions, Mount Points, etc.)
        let path_w = win32::to_wide(path);
        let attrs = unsafe { win32::GetFileAttributesW(path_w.as_ptr()) };
        if attrs != win32::INVALID_FILE_ATTRIBUTES
            && (attrs & win32::FILE_ATTRIBUTE_REPARSE_POINT) != 0
        {
            return Err(StorageError::InvalidPath(format!(
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
                return Err(StorageError::InvalidPath(format!(
                    "Symlinks are rejected for security: {}",
                    path.display()
                ))
                .into());
            }
        }
    }

    Ok(())
}

/// Validate that neither the destination nor any of its ancestor directories are symlinks or reparse points.
fn validate_path_safety(destination: &Path) -> Result<()> {
    reject_symlink_or_reparse(destination)?;

    // Check all existing parent directories up to root
    let mut current = destination.parent();
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

/// RAII Guard that coordinates save operations both in-process and cross-process.
struct OperationGuard {
    normalized_path: PathBuf,
    lock_path: PathBuf,
    #[cfg(windows)]
    lock_file: Option<std::fs::File>,
}

impl OperationGuard {
    fn acquire(destination: &Path) -> Result<Self> {
        let norm = normalize_path(destination);

        // 1. In-process coordination via ACTIVE_OPERATIONS
        {
            let mut active = ACTIVE_OPERATIONS.lock().map_err(|_| {
                StorageError::ReplacementFailed("Active operations lock poisoned".into())
            })?;
            if !active.insert(norm.clone()) {
                return Err(StorageError::StagingFileExists(format!(
                    "An active save operation is already running for {}",
                    destination.display()
                ))
                .into());
            }
        }

        let lock_path = lock_path_for(destination);

        // 2. Cross-process coordination (Win32 LockFile on Windows)
        #[cfg(windows)]
        let lock_file = {
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
            {
                Ok(f) => f,
                Err(e) => {
                    let mut active = ACTIVE_OPERATIONS.lock().unwrap();
                    active.remove(&norm);
                    return Err(StorageError::Io(e).into());
                }
            };

            use std::os::windows::io::AsRawHandle;
            let handle = file.as_raw_handle();
            let locked = unsafe { win32::LockFile(handle, 0, 0, 1, 0) };
            if locked == 0 {
                // Another process holds the lock
                let mut active = ACTIVE_OPERATIONS.lock().unwrap();
                active.remove(&norm);
                return Err(StorageError::StagingFileExists(format!(
                    "Another process is currently operating on {}",
                    destination.display()
                ))
                .into());
            }
            Some(file)
        };

        Ok(Self {
            normalized_path: norm,
            lock_path,
            #[cfg(windows)]
            lock_file,
        })
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(ref file) = self.lock_file {
            use std::os::windows::io::AsRawHandle;
            let handle = file.as_raw_handle();
            unsafe {
                win32::UnlockFile(handle, 0, 0, 1, 0);
            }
        }

        if let Ok(mut active) = ACTIVE_OPERATIONS.lock() {
            active.remove(&self.normalized_path);
        }

        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Write a `.kivault` container binary to disk atomically (§12).
///
/// Workflow:
/// 1. Reject invalid paths (directories, symlinks, NTFS reparse points/junctions).
/// 2. Validate container structure (`parse_container`) in RAM before touching disk.
/// 3. Acquire exclusive operation lock (both in-process and cross-process).
/// 4. Create the staging file (`.<filename>.tmp`) in the same directory exclusively (`create_new(true)`).
///    If a staging file already exists, fail immediately to prevent race conditions or data loss.
/// 5. Write full container bytes into staging file and call `sync_all()`.
/// 6. Close/drop staging file handle.
/// 7. Perform platform-specific atomic replacement:
///    - Windows: `ReplaceFileW` (if target exists, using `.<filename>.bak` as backup) or
///      `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` (if first creation).
///    - Linux/Unix: `rename(2)` followed by `fsync` on parent directory descriptor.
/// 8. Verify post-replacement container integrity.
pub fn write_vault_atomic(destination: &Path, container_bytes: &[u8]) -> Result<()> {
    // 1. Path safety checks
    validate_path_safety(destination)?;
    if destination.is_dir() {
        return Err(
            StorageError::InvalidPath("Destination path must not be a directory".into()).into(),
        );
    }

    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if parent.exists() && parent.is_dir() {
        reject_symlink_or_reparse(parent)?;
    } else {
        std::fs::create_dir_all(parent)?;
    }

    let staging_path = staging_path_for(destination);
    let backup_path = backup_path_for(destination);

    reject_symlink_or_reparse(&staging_path)?;
    reject_symlink_or_reparse(&backup_path)?;

    // 2. Validate container integrity BEFORE creating staging file
    parse_container(container_bytes).map_err(|e| StorageError::InvalidContainer(e.to_string()))?;

    // 3. Acquire exclusive operation coordination lock
    let _guard = OperationGuard::acquire(destination)?;

    // 4. Create staging file exclusively (§12.1 #6)
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600); // Restrictive user-only permissions
    }

    let mut staging_file = match options.open(&staging_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(StorageError::StagingFileExists(staging_path.display().to_string()).into());
        }
        Err(e) => return Err(StorageError::Io(e).into()),
    };

    // 5. Write complete container and flush to disk (§12.1 #7)
    if let Err(e) = staging_file.write_all(container_bytes) {
        let _ = std::fs::remove_file(&staging_path);
        return Err(StorageError::Io(e).into());
    }

    if let Err(e) = staging_file.sync_all() {
        let _ = std::fs::remove_file(&staging_path);
        return Err(StorageError::Io(e).into());
    }

    // Explicitly close staging handle before atomic replacement
    drop(staging_file);

    // 6. Execute platform-specific atomic replacement
    #[cfg(windows)]
    {
        atomic_replace_windows(&staging_path, destination, &backup_path)?;
    }

    #[cfg(unix)]
    {
        atomic_replace_unix(&staging_path, destination, parent)?;
    }

    #[cfg(not(any(windows, unix)))]
    {
        std::fs::rename(&staging_path, destination)?;
    }

    Ok(())
}

/// Read a `.kivault` container file from disk into memory.
pub fn read_vault(source: &Path) -> Result<Vec<u8>> {
    validate_path_safety(source)?;
    let bytes = std::fs::read(source)?;
    // Validate container integrity before passing to upper layers
    parse_container(&bytes).map_err(|e| StorageError::InvalidContainer(e.to_string()))?;
    Ok(bytes)
}

/// Safely clean up a stale staging file according to §12.4 startup and recovery rules.
///
/// Rules (§12.4):
/// - Never automatically promote staging over an existing primary vault.
/// - If an active save is currently in progress, refuse deletion to protect concurrent work.
/// - If a valid primary exists, leave it untouched; a stale stage can be removed only
///   after safe path checks and after ensuring the primary remains available.
/// - If the primary is missing or invalid and a staging candidate exists, preserve the
///   candidate and enter a recovery flow. Refuse automatic deletion.
pub fn cleanup_stale_staging(destination: &Path) -> Result<bool> {
    let staging_path = staging_path_for(destination);
    let legacy_staging = destination
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".kivault.tmp");

    let target_staging = if staging_path.exists() {
        staging_path
    } else if legacy_staging.exists() {
        legacy_staging
    } else {
        return Ok(false);
    };

    // Coordination check: ensure no active save is currently in progress
    let norm = normalize_path(destination);
    {
        let active = ACTIVE_OPERATIONS.lock().map_err(|_| {
            StorageError::ReplacementFailed("Active operations lock poisoned".into())
        })?;
        if active.contains(&norm) {
            return Err(StorageError::StaleStagingCannotBeCleaned(
                "An active save operation is currently in progress for this vault".into(),
            )
            .into());
        }
    }

    // Cross-process coordination check: verify lock file is not held by another process
    let lock_path = lock_path_for(destination);
    #[cfg(windows)]
    if lock_path.exists() {
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(&lock_path) {
            use std::os::windows::io::AsRawHandle;
            let handle = file.as_raw_handle();
            let locked = unsafe { win32::LockFile(handle, 0, 0, 1, 0) };
            if locked == 0 {
                return Err(StorageError::StaleStagingCannotBeCleaned(
                    "Another process is currently operating on this vault; staging cleanup refused"
                        .into(),
                )
                .into());
            }
            unsafe {
                win32::UnlockFile(handle, 0, 0, 1, 0);
            }
        }
    }

    validate_path_safety(destination)?;
    reject_symlink_or_reparse(&target_staging)?;

    // Destination must exist and be a valid container
    if !destination.exists() {
        return Err(StorageError::StaleStagingCannotBeCleaned(
            "Primary vault is missing; staging candidate preserved for recovery".into(),
        )
        .into());
    }

    let primary_bytes = match std::fs::read(destination) {
        Ok(b) => b,
        Err(e) => {
            return Err(StorageError::StaleStagingCannotBeCleaned(format!(
                "Failed to read primary vault ({e}); staging candidate preserved for recovery"
            ))
            .into());
        }
    };

    if let Err(e) = parse_container(&primary_bytes) {
        return Err(StorageError::StaleStagingCannotBeCleaned(format!(
            "Primary vault is invalid ({e}); staging candidate preserved for recovery"
        ))
        .into());
    }

    // Primary is confirmed intact and valid: safe to delete stale staging
    std::fs::remove_file(&target_staging)?;
    Ok(true)
}

#[cfg(windows)]
mod win32 {
    pub use std::ffi::c_void;
    use std::path::Path;

    pub const MOVEFILE_WRITE_THROUGH: u32 = 0x00000008;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
    pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut c_void,
            lpReserved: *mut c_void,
        ) -> i32;

        pub fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;

        pub fn GetFileAttributesW(lpFileName: *const u16) -> u32;

        pub fn LockFile(
            hFile: *mut c_void,
            dwFileOffsetLow: u32,
            dwFileOffsetHigh: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
        ) -> i32;

        pub fn UnlockFile(
            hFile: *mut c_void,
            dwFileOffsetLow: u32,
            dwFileOffsetHigh: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
        ) -> i32;

        pub fn GetLastError() -> u32;
    }

    pub fn to_wide(path: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(windows)]
fn atomic_replace_windows(staging: &Path, destination: &Path, backup: &Path) -> Result<()> {
    let staging_w = win32::to_wide(staging);
    let dest_w = win32::to_wide(destination);
    let backup_w = win32::to_wide(backup);

    if destination.exists() {
        // Destination exists: use ReplaceFileW with same-volume backup path (§12.3)
        // dwReplaceFlags = 0 (REPLACEFILE_WRITE_THROUGH is unsupported by Windows API)
        let ret = unsafe {
            win32::ReplaceFileW(
                dest_w.as_ptr(),
                staging_w.as_ptr(),
                backup_w.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if ret == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(StorageError::ReplacementFailed(format!(
                "ReplaceFileW failed with Win32 error code {err}"
            ))
            .into());
        }

        // Reopen new primary and verify container integrity
        let primary_bytes = std::fs::read(destination)?;
        if let Err(e) = parse_container(&primary_bytes) {
            // Keep recoverable backup intact (§12.3)
            return Err(StorageError::InvalidContainer(format!(
                "Post-replacement primary verification failed; backup retained at {}: {e}",
                backup.display()
            ))
            .into());
        }

        // Verification succeeded: clean up backup file
        let _ = std::fs::remove_file(backup);
    } else {
        // First creation: destination does not exist yet (§12.3)
        // Use MoveFileExW with MOVEFILE_WRITE_THROUGH (0x8) and WITHOUT MOVEFILE_REPLACE_EXISTING
        // to safely fail if a race introduces a destination file
        let ret = unsafe {
            win32::MoveFileExW(
                staging_w.as_ptr(),
                dest_w.as_ptr(),
                win32::MOVEFILE_WRITE_THROUGH,
            )
        };

        if ret == 0 {
            let err = unsafe { win32::GetLastError() };
            return Err(StorageError::ReplacementFailed(format!(
                "MoveFileExW failed with Win32 error code {err}"
            ))
            .into());
        }

        // Verify primary
        let primary_bytes = std::fs::read(destination)?;
        if let Err(e) = parse_container(&primary_bytes) {
            return Err(StorageError::InvalidContainer(format!(
                "Post-move primary verification failed: {e}"
            ))
            .into());
        }
    }

    Ok(())
}

#[cfg(unix)]
fn atomic_replace_unix(staging: &Path, destination: &Path, parent: &Path) -> Result<()> {
    // 1. Same-filesystem atomic rename (§12.2 #3)
    std::fs::rename(staging, destination)?;

    // 2. Verify primary
    let primary_bytes = std::fs::read(destination)?;
    if let Err(e) = parse_container(&primary_bytes) {
        return Err(StorageError::InvalidContainer(format!(
            "Post-rename primary verification failed: {e}"
        ))
        .into());
    }

    // 3. Parent directory fsync to synchronize directory entry change (§12.2 #4)
    let parent_file = match std::fs::File::open(parent) {
        Ok(f) => f,
        Err(e) => {
            return Err(StorageError::DurabilityUncertain(format!(
                "Failed to open parent directory for fsync: {e}"
            ))
            .into());
        }
    };

    use std::os::unix::io::AsRawFd;
    let fd = parent_file.as_raw_fd();
    let ret = unsafe {
        extern "C" {
            fn fsync(fd: std::os::raw::c_int) -> std::os::raw::c_int;
        }
        fsync(fd)
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // §12.2 #5: "If directory fsync fails after rename succeeds, report that the new file
        // is visible but durability is uncertain; do not claim the old file is still active."
        return Err(StorageError::DurabilityUncertain(format!(
            "Parent directory fsync failed after rename: {err}"
        ))
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::operations::{create_vault, unlock_vault};
    use std::fs::File;
    use std::sync::Arc;

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(name: &str) -> Self {
            let uuid = uuid::Uuid::new_v4();
            let path = std::env::temp_dir().join(format!("kivault_test_{name}_{uuid}"));
            std::fs::create_dir_all(&path).expect("create test temp dir");
            Self { path }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_write_vault_atomic_first_creation() {
        let guard = TempDirGuard::new("first_creation");
        let dest = guard.path.join("vault.kivault");
        let password = b"password123";
        let payload = b"first-creation-test-payload";

        let container_bytes =
            create_vault(password, 1000, 1, 1, payload).expect("create_vault succeeds");

        // Write atomic
        write_vault_atomic(&dest, &container_bytes).expect("write_vault_atomic succeeds");

        // Destination must exist
        assert!(dest.exists());

        // Staging file must be cleaned up
        let staging = staging_path_for(&dest);
        assert!(!staging.exists());

        // Read and unlock
        let read_bytes = read_vault(&dest).expect("read_vault succeeds");
        assert_eq!(read_bytes, container_bytes);

        let unlocked = unlock_vault(&read_bytes, password).expect("unlock_vault succeeds");
        assert_eq!(unlocked.payload_plaintext.as_slice(), payload);
    }

    #[test]
    fn test_write_vault_atomic_replacement() {
        let guard = TempDirGuard::new("replacement");
        let dest = guard.path.join("vault.kivault");
        let password_v1 = b"pass-v1";
        let payload_v1 = b"payload-v1";
        let container_v1 =
            create_vault(password_v1, 1000, 1, 1, payload_v1).expect("create_vault v1");

        write_vault_atomic(&dest, &container_v1).expect("write v1");

        // Prepare v2
        let password_v2 = b"pass-v2";
        let payload_v2 = b"payload-v2-updated";
        let container_v2 =
            create_vault(password_v2, 2000, 1, 1, payload_v2).expect("create_vault v2");

        // Atomically replace
        write_vault_atomic(&dest, &container_v2).expect("write v2 replaces v1");

        // Staging and backup must not linger
        let staging = staging_path_for(&dest);
        let backup = backup_path_for(&dest);
        assert!(!staging.exists());
        assert!(!backup.exists());

        // Read and verify v2
        let read_bytes = read_vault(&dest).expect("read_vault v2");
        assert_eq!(read_bytes, container_v2);

        let unlocked = unlock_vault(&read_bytes, password_v2).expect("unlock v2 succeeds");
        assert_eq!(unlocked.payload_plaintext.as_slice(), payload_v2);

        // v1 password must fail on new file
        assert!(unlock_vault(&read_bytes, password_v1).is_err());
    }

    #[test]
    fn test_write_vault_atomic_rejects_invalid_container() {
        let guard = TempDirGuard::new("invalid_container");
        let dest = guard.path.join("vault.kivault");
        let invalid_bytes = b"NOT_A_VALID_KIVAULT_CONTAINER_BYTES";

        let res = write_vault_atomic(&dest, invalid_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Storage(
                StorageError::InvalidContainer(_)
            ))
        ));

        // Destination and staging must not be created
        assert!(!dest.exists());
        let staging = staging_path_for(&dest);
        assert!(!staging.exists());
    }

    #[test]
    fn test_write_vault_atomic_staging_exists_fails_safely() {
        let guard = TempDirGuard::new("staging_exists");
        let dest = guard.path.join("vault.kivault");
        let staging = staging_path_for(&dest);

        // Pre-create an unexpected staging file
        let mut f = File::create(&staging).expect("create pre-existing staging");
        f.write_all(b"pre-existing-staging-data").unwrap();
        drop(f);

        let container_bytes = create_vault(b"pass", 1000, 1, 1, b"payload").expect("create_vault");

        let res = write_vault_atomic(&dest, &container_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Storage(
                StorageError::StagingFileExists(_)
            ))
        ));

        // Staging file must remain untouched
        let staging_content = std::fs::read(&staging).unwrap();
        assert_eq!(staging_content, b"pre-existing-staging-data");

        // Destination must not be created
        assert!(!dest.exists());
    }

    #[test]
    fn test_write_vault_atomic_preserves_target_on_failure() {
        let guard = TempDirGuard::new("preserve_target");
        let dest = guard.path.join("vault.kivault");
        let password = b"original-pass";
        let payload = b"original-intact-payload";

        let container_original =
            create_vault(password, 1000, 1, 1, payload).expect("create_vault original");
        write_vault_atomic(&dest, &container_original).expect("write original vault");

        // Now pre-create staging file to force failure
        let staging = staging_path_for(&dest);
        let mut f = File::create(&staging).expect("create staging to induce collision");
        f.write_all(b"unrelated staging").unwrap();
        drop(f);

        // Attempt write with new container
        let container_new =
            create_vault(b"new-pass", 2000, 1, 1, b"new-payload").expect("create_vault new");
        let res = write_vault_atomic(&dest, &container_new);
        assert!(res.is_err());

        // Target file MUST be completely preserved and unchanged
        let read_bytes = read_vault(&dest).expect("read original vault");
        assert_eq!(read_bytes, container_original);

        let unlocked = unlock_vault(&read_bytes, password).expect("unlock original vault succeeds");
        assert_eq!(unlocked.payload_plaintext.as_slice(), payload);
    }

    #[test]
    fn test_multi_vault_isolated_staging() {
        let guard = TempDirGuard::new("multi_vault");
        let dest_a = guard.path.join("vault_a.kivault");
        let dest_b = guard.path.join("vault_b.kivault");

        // Staging paths must be distinct
        let staging_a = staging_path_for(&dest_a);
        let staging_b = staging_path_for(&dest_b);
        assert_ne!(staging_a, staging_b);
        assert_eq!(staging_a.file_name().unwrap(), ".vault_a.kivault.tmp");
        assert_eq!(staging_b.file_name().unwrap(), ".vault_b.kivault.tmp");

        // Backup paths must be distinct
        let backup_a = backup_path_for(&dest_a);
        let backup_b = backup_path_for(&dest_b);
        assert_ne!(backup_a, backup_b);

        let container_a = create_vault(b"pass_a", 1000, 1, 1, b"data_a").unwrap();
        let container_b = create_vault(b"pass_b", 2000, 1, 1, b"data_b").unwrap();

        write_vault_atomic(&dest_a, &container_a).unwrap();
        write_vault_atomic(&dest_b, &container_b).unwrap();

        assert_eq!(read_vault(&dest_a).unwrap(), container_a);
        assert_eq!(read_vault(&dest_b).unwrap(), container_b);
    }

    #[test]
    fn test_concurrent_save_coordination() {
        let guard = TempDirGuard::new("concurrent_saves");
        let dest = Arc::new(guard.path.join("vault.kivault"));
        let container = Arc::new(create_vault(b"pass", 1000, 1, 1, b"payload").unwrap());

        let mut handles = Vec::new();
        for _ in 0..4 {
            let dest_clone = Arc::clone(&dest);
            let container_clone = Arc::clone(&container);
            handles.push(std::thread::spawn(move || {
                write_vault_atomic(&dest_clone, &container_clone)
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap());
        }

        // At least one operation succeeded
        assert!(results.iter().any(|r| r.is_ok()));

        // Primary vault must exist and be completely valid
        assert!(dest.exists());
        let read = read_vault(&dest).expect("read vault succeeds");
        assert_eq!(read, *container);
    }

    #[test]
    fn test_cleanup_refused_while_save_in_progress() {
        let guard = TempDirGuard::new("cleanup_while_saving");
        let dest = guard.path.join("vault.kivault");
        let container = create_vault(b"pass", 1000, 1, 1, b"data").unwrap();
        write_vault_atomic(&dest, &container).unwrap();

        // Simulate an ongoing save holding the operation guard
        let _active_guard = OperationGuard::acquire(&dest).expect("acquire guard");

        // Manually place a staging file
        let staging = staging_path_for(&dest);
        std::fs::write(&staging, b"staging data in progress").unwrap();

        // Cleanup MUST be refused because a save operation is in progress
        let res = cleanup_stale_staging(&dest);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Storage(
                StorageError::StaleStagingCannotBeCleaned(_)
            ))
        ));

        // Staging file must NOT be deleted while save is active
        assert!(staging.exists());
    }

    #[test]
    fn test_cleanup_stale_staging_when_primary_valid() {
        let guard = TempDirGuard::new("cleanup_valid");
        let dest = guard.path.join("vault.kivault");
        let container = create_vault(b"pass", 1000, 1, 1, b"data").expect("create_vault");
        write_vault_atomic(&dest, &container).expect("write vault");

        // Manually create stale staging file
        let staging = staging_path_for(&dest);
        std::fs::write(&staging, b"stale data").unwrap();
        assert!(staging.exists());

        // Cleanup should succeed
        let cleaned = cleanup_stale_staging(&dest).expect("cleanup_stale_staging succeeds");
        assert!(cleaned);
        assert!(!staging.exists());
        assert!(dest.exists());
    }

    #[test]
    fn test_cleanup_stale_staging_refuses_when_primary_missing_or_corrupt() {
        let guard = TempDirGuard::new("cleanup_refused");
        let dest = guard.path.join("vault.kivault");
        let staging = staging_path_for(&dest);
        std::fs::write(&staging, b"candidate staging data").unwrap();

        // 1. Primary missing
        assert!(!dest.exists());
        let res1 = cleanup_stale_staging(&dest);
        assert!(matches!(
            res1,
            Err(crate::errors::AppError::Storage(
                StorageError::StaleStagingCannotBeCleaned(_)
            ))
        ));
        assert!(staging.exists(), "staging candidate must be preserved");

        // 2. Primary corrupted
        std::fs::write(&dest, b"corrupted-not-a-vault").unwrap();
        let res2 = cleanup_stale_staging(&dest);
        assert!(matches!(
            res2,
            Err(crate::errors::AppError::Storage(
                StorageError::StaleStagingCannotBeCleaned(_)
            ))
        ));
        assert!(staging.exists(), "staging candidate must be preserved");
    }

    #[test]
    #[cfg(windows)]
    fn test_rejects_directory_junction_on_windows() {
        let guard = TempDirGuard::new("reparse_test");
        let target_dir = guard.path.join("target_dir");
        let junction_dir = guard.path.join("junction_dir");
        std::fs::create_dir_all(&target_dir).unwrap();

        // Create an NTFS Directory Junction via cmd mklink /J
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction_dir.to_str().unwrap(),
                target_dir.to_str().unwrap(),
            ])
            .status()
            .expect("execute mklink /J");

        if status.success() {
            // Attempt to write a vault into the directory junction
            let dest = junction_dir.join("vault.kivault");
            let container = create_vault(b"pass", 1000, 1, 1, b"data").unwrap();
            let res = write_vault_atomic(&dest, &container);

            // Must be rejected with InvalidPath error
            assert!(matches!(
                res,
                Err(crate::errors::AppError::Storage(StorageError::InvalidPath(
                    _
                )))
            ));

            // Clean up junction
            let _ = std::process::Command::new("cmd")
                .args(["/c", "rmdir", junction_dir.to_str().unwrap()])
                .status();
        }
    }
}
