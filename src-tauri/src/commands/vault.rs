//! Vault Lifecycle Tauri Commands
//!
//! Implements typed Tauri commands for vault create, unlock, lock, status query, summary query,
//! and master-password rotation according to `api-contract.md` Section 3.
//!
//! # Security Properties
//! - The frontend **never** receives the VDK, KEK, PEK, plaintext SQLite image, or raw bytes of
//!   any cryptographic secret. All secrets stay exclusively in Rust.
//! - Passwords received from the frontend are zeroized as soon as they are no longer needed.
//! - An opaque vault state machine backed by `Arc<Mutex<VaultState>>` is injected via Tauri
//!   managed state. The frontend has no access to the internal representation.
//! - Every command independently validates the vault state and input before doing any work.
//! - Error messages are sanitised: they must not contain passwords, keys, or sensitive paths.
//!
//! # Vault State Machine
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ VaultState                                                   │
//! │                                                              │
//! │  Initialised ──── create_vault / set_vault_path ──► Locked  │
//! │  Locked      ──── unlock_vault    ──────────────► Unlocked  │
//! │  Unlocked    ──── lock_vault      ──────────────► Locked    │
//! │  Unlocked    ──── change_master_password ────────► Unlocked │
//! └──────────────────────────────────────────────────────────────┘
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::vault::operations::UnlockedVault;
use crate::vault::sqlite::InMemoryDb;
use crate::vault::storage::{read_vault, write_vault_atomic};

// ─── Input length limits (api-contract.md §13) ────────────────────────────────

/// Maximum length of a master password in UTF-8 bytes.
const MAX_PASSWORD_BYTES: usize = 1024;
/// Maximum length of a vault name in UTF-8 bytes.
const MAX_VAULT_NAME_BYTES: usize = 256;

// ─── State ────────────────────────────────────────────────────────────────────

/// Represents the lifecycle state of the single active vault.
///
/// This struct is held behind an `Arc<Mutex<VaultState>>` and registered with Tauri as managed
/// state. The frontend never observes this type directly.
pub enum VaultState {
    /// No vault path is configured yet (app just started).
    Uninitialised,
    /// A vault file path is known but the vault is currently locked.
    Locked { path: PathBuf },
    /// The vault is unlocked and the in-memory database is active.
    Unlocked {
        path: PathBuf,
        vault: Box<UnlockedVault>,
    },
}

impl VaultState {
    /// Returns `true` when the vault is in the `Unlocked` state.
    pub fn is_unlocked(&self) -> bool {
        matches!(self, VaultState::Unlocked { .. })
    }

    /// Returns the vault file path if one is known (i.e., not Uninitialised).
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            VaultState::Uninitialised => None,
            VaultState::Locked { path } | VaultState::Unlocked { path, .. } => Some(path),
        }
    }
}

// Re-export SharedAutoLock from vault::autolock
pub use crate::vault::autolock::SharedAutoLock;

/// Thread-safe shared vault state injected as Tauri managed state.
#[derive(Clone)]
pub struct SharedVaultState(pub Arc<Mutex<VaultState>>);

impl SharedVaultState {
    /// Create a new `SharedVaultState` in the `Uninitialised` state.
    pub fn new() -> Self {
        SharedVaultState(Arc::new(Mutex::new(VaultState::Uninitialised)))
    }
}

impl Default for SharedVaultState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Response types ───────────────────────────────────────────────────────────

/// Serialisable vault status returned by `get_vault_status`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum VaultStatusResponse {
    Uninitialised,
    Locked,
    Unlocked,
}

/// Serialisable vault summary returned by `get_vault_summary`.
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultSummaryResponse {
    /// UUID (16 raw bytes encoded as hex string) uniquely identifying this vault.
    pub vault_id: String,
    /// Human-readable vault name from `vault_metadata` table.
    pub vault_name: String,
    /// Unix timestamp (seconds) when the vault was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the vault was last updated.
    pub updated_at: u64,
}

// ─── Error mapping ────────────────────────────────────────────────────────────

/// Opaque, serialisable command error safe for the frontend.
///
/// The `message` is intentionally vague — it must not expose secrets, internal paths,
/// or cryptographic error details beyond what is necessary for the user to take action.
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandError {
    /// One of the canonical error categories defined in `api-contract.md` §2.
    pub code: &'static str,
    /// User-facing message string. Must never contain secrets or raw keys.
    pub message: String,
}

impl CommandError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        CommandError {
            code,
            message: message.into(),
        }
    }
}

/// Map an internal `AppError` to a safe, frontend-visible `CommandError`.
///
/// # Security Rule
/// This function must NOT propagate internal error strings that could contain secret material.
/// Always sanitise or replace the message.
pub(crate) fn map_error(err: AppError) -> CommandError {
    match err {
        AppError::Crypto(ref e) => {
            use crate::errors::CryptoError;
            match e {
                CryptoError::TagVerificationFailed => CommandError::new(
                    "AuthenticationFailed",
                    "Incorrect password or corrupted vault.",
                ),
                _ => CommandError::new("CryptoFailure", "Cryptographic operation failed."),
            }
        }
        AppError::Vault(ref e) => {
            use crate::errors::VaultError;
            match e {
                VaultError::UnsupportedVersion { .. } => CommandError::new(
                    "UnsupportedVersion",
                    "The vault was created with a newer version of KiVault.",
                ),
                VaultError::InvalidMagic(_) | VaultError::CborDecodeError(_) => CommandError::new(
                    "IntegrityFailure",
                    "The vault file is not a valid KiVault container.",
                ),
                VaultError::FileSizeMismatch { .. }
                | VaultError::CiphertextLengthMismatch { .. }
                | VaultError::HeaderLengthMismatch { .. }
                | VaultError::TrailingContainerBytes(_)
                | VaultError::TrailingHeaderBytes(_) => CommandError::new(
                    "IntegrityFailure",
                    "The vault file appears to be corrupted.",
                ),
                _ => CommandError::new("IntegrityFailure", "The vault file could not be parsed."),
            }
        }
        AppError::Database(ref e) => {
            use crate::errors::DatabaseError;
            match e {
                DatabaseError::UnsupportedSchemaVersion { .. } => CommandError::new(
                    "UnsupportedVersion",
                    "The vault database schema version is not supported.",
                ),
                DatabaseError::ConnectionClosed => {
                    CommandError::new("VaultLocked", "The vault is not unlocked.")
                }
                DatabaseError::NotFound { entity, id } => {
                    CommandError::new("NotFound", format!("{entity} '{id}' not found."))
                }
                DatabaseError::InvalidInput { field, reason } => CommandError::new(
                    "InvalidInput",
                    format!("Invalid value for '{field}': {reason}"),
                ),
                DatabaseError::Conflict(msg) => CommandError::new("Conflict", msg.as_str()),
                _ => CommandError::new("DatabaseFailure", "A database error occurred."),
            }
        }
        AppError::Storage(ref e) => {
            use crate::errors::StorageError;
            match e {
                StorageError::DurabilityUncertain(_) => CommandError::new(
                    "SaveCommitDurabilityUncertain",
                    "The vault was saved but filesystem durability could not be confirmed.",
                ),
                StorageError::StagingFileExists(_) => CommandError::new(
                    "FileOperationFailed",
                    "A concurrent save operation is already in progress.",
                ),
                StorageError::ReplacementFailed(_) => CommandError::new(
                    "FileOperationFailed",
                    "Atomic vault replacement failed. The original vault file is preserved.",
                ),
                StorageError::InvalidPath(_) => CommandError::new(
                    "InvalidInput",
                    "The vault path is invalid or not permitted.",
                ),
                StorageError::InvalidContainer(_) => {
                    CommandError::new("IntegrityFailure", "The vault file could not be validated.")
                }
                StorageError::StaleStagingCannotBeCleaned(_) => CommandError::new(
                    "FileOperationFailed",
                    "A stale staging file was found but could not be removed safely.",
                ),
                StorageError::Io(_) => {
                    CommandError::new("FileOperationFailed", "A file I/O error occurred.")
                }
            }
        }
        AppError::Backup(ref e) => {
            use crate::errors::BackupError;
            match e {
                BackupError::InvalidPath(_) | BackupError::ConfirmationRequired => {
                    CommandError::new("InvalidInput", e.to_string())
                }
                BackupError::InvalidContainer(_) => {
                    CommandError::new("IntegrityFailure", e.to_string())
                }
                BackupError::AuthenticationFailed => CommandError::new(
                    "AuthenticationFailed",
                    "Incorrect backup master password or corrupted backup file.",
                ),
                BackupError::CreationFailed(_) | BackupError::RestoreFailed(_) => {
                    CommandError::new("BackupFailure", e.to_string())
                }
            }
        }
    }
}

// ─── Input validation helpers ─────────────────────────────────────────────────

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

fn validate_vault_name(name: &str) -> std::result::Result<(), CommandError> {
    if name.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Vault name must not be empty.",
        ));
    }
    if name.len() > MAX_VAULT_NAME_BYTES {
        return Err(CommandError::new(
            "InvalidInput",
            format!("Vault name exceeds maximum length of {MAX_VAULT_NAME_BYTES} bytes."),
        ));
    }
    Ok(())
}

fn validate_path(path: &str) -> std::result::Result<PathBuf, CommandError> {
    let p = PathBuf::from(path);
    if p.as_os_str().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Vault path must not be empty.",
        ));
    }
    // Reject paths that are obviously invalid (directory separators only, etc.)
    if path.len() > 4096 {
        return Err(CommandError::new(
            "InvalidInput",
            "Vault path exceeds maximum allowed length.",
        ));
    }
    Ok(p)
}

// ─── Lock guard helper ────────────────────────────────────────────────────────

pub(crate) fn lock_state<'a>(
    state: &'a State<'_, SharedVaultState>,
) -> std::result::Result<std::sync::MutexGuard<'a, VaultState>, CommandError> {
    state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// `create_vault` command (api-contract.md §3).
///
/// Creates a new `.kivault` container at the given path with an initial empty schema v1 database,
/// then transitions the state machine to `Locked` (the vault is not automatically unlocked).
///
/// # Input Validation
/// - `vault_path`: non-empty, ≤ 4096 bytes, valid filesystem path.
/// - `vault_name`: non-empty, ≤ 256 bytes.
/// - `master_password`: non-empty, ≤ 1024 bytes; zeroized immediately after use.
///
/// # Side Effects
/// - Creates the `.kivault` file atomically on disk.
/// - Inserts one row into `vault_metadata` with `id = vault_id`.
/// - Transitions `VaultState` to `Locked`.
#[tauri::command]
pub fn create_vault(
    state: State<'_, SharedVaultState>,
    vault_path: String,
    vault_name: String,
    master_password: String,
) -> std::result::Result<(), CommandError> {
    // 1. Input validation
    let path = validate_path(&vault_path)?;
    validate_vault_name(&vault_name)?;
    validate_password(&master_password)?;

    // 2. Reject overwriting an existing vault file without explicit overwrite flag
    if path.exists() {
        return Err(CommandError::new(
            "VaultAlreadyExists",
            "A vault file already exists at the specified path.",
        ));
    }

    // 3. Wrap password in Zeroizing to ensure it is cleared after use
    let password_bytes = Zeroizing::new(master_password.into_bytes());

    // 4. Create an empty in-memory DB and insert initial vault_metadata row
    let initial_db = InMemoryDb::create_empty().map_err(map_error)?;
    {
        // Generate a vault_id (16-byte UUID represented as hex string)
        let vault_id_bytes = crate::crypto::generate_vault_id().map_err(map_error)?;
        let vault_id_hex = hex_encode(&vault_id_bytes);

        let now_secs = current_unix_timestamp();

        let conn = initial_db.conn().map_err(map_error)?;
        conn.execute(
            "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
            rusqlite::params![vault_id_hex, vault_name, now_secs, now_secs],
        )
        .map_err(|e| map_error(AppError::Database(crate::errors::DatabaseError::Sqlite(e))))?;
    }

    let initial_image = initial_db.to_image().map_err(map_error)?;
    drop(initial_db);

    // 5. Create vault container
    let now_secs = current_unix_timestamp();
    let container_bytes = crate::vault::operations::create_vault(
        &password_bytes,
        now_secs,
        crate::vault::sqlite::SCHEMA_VERSION_V1,
        crate::vault::sqlite::SCHEMA_VERSION_V1,
        &initial_image,
    )
    .map_err(map_error)?;

    // 6. Atomically persist to disk
    write_vault_atomic(&path, &container_bytes).map_err(map_error)?;

    // 7. Transition to Locked
    let mut guard = lock_state(&state)?;
    *guard = VaultState::Locked { path };

    Ok(())
}

/// `unlock_vault` command (api-contract.md §3).
///
/// Decrypts and loads the vault from disk into in-memory SQLite. Requires the vault to be in the
/// `Locked` state (or `Uninitialised` with `vault_path` provided). Transitions to `Unlocked` on success.
///
/// The `master_password` string is zeroized immediately after the KDF call inside `unlock_vault`.
///
/// # Errors
/// - `VaultLocked` — vault is already unlocked or not yet initialised.
/// - `AuthenticationFailed` — wrong password or corrupted VDK ciphertext.
/// - `IntegrityFailure` — container is corrupted or invalid.
/// - `FileOperationFailed` — cannot read the vault file from disk.
#[tauri::command]
pub fn unlock_vault(
    auto_lock: State<'_, SharedAutoLock>,
    state: State<'_, SharedVaultState>,
    master_password: String,
    vault_path: Option<String>,
) -> std::result::Result<(), CommandError> {
    unlock_vault_impl(&auto_lock, &state, master_password, vault_path)
}

pub fn unlock_vault_impl(
    auto_lock: &SharedAutoLock,
    state: &SharedVaultState,
    master_password: String,
    vault_path: Option<String>,
) -> std::result::Result<(), CommandError> {
    validate_password(&master_password)?;

    // Note: Do not acquire state lock yet to avoid holding it during Argon2id / disk read
    let (path, password_bytes) = {
        let guard = state.0.lock().map_err(|_| {
            CommandError::new("Internal", "Internal vault state lock was poisoned.")
        })?;

        let path = match (&*guard, vault_path.as_deref()) {
            (VaultState::Locked { path }, _) => path.clone(),
            (VaultState::Uninitialised, Some(p)) => validate_path(p)?,
            (VaultState::Unlocked { .. }, _) => {
                return Err(CommandError::new(
                    "VaultAlreadyExists",
                    "The vault is already unlocked.",
                ))
            }
            (VaultState::Uninitialised, None) => {
                return Err(CommandError::new(
                    "VaultLocked",
                    "No vault has been configured. Provide vault_path or create a vault first.",
                ))
            }
        };
        (path, Zeroizing::new(master_password.into_bytes()))
    };

    // Read container from disk
    let container_bytes = read_vault(&path).map_err(map_error)?;

    // Decrypt and open
    let vault = crate::vault::operations::unlock_vault(&container_bytes, &password_bytes)
        .map_err(map_error)?;

    // Transition to Unlocked with AutoLockRuntime synchronization
    crate::vault::autolock::complete_unlock(auto_lock, state, path, vault)?;

    Ok(())
}

/// `lock_vault` command (api-contract.md §3).
///
/// Saves the current in-memory database to disk (encrypted), then destroys all runtime secret
/// state. Transitions from `Unlocked` to `Locked`.
///
/// # Failure Safety
/// If the save-to-disk step fails, the vault state remains `Unlocked` — the in-memory data is
/// **not** discarded, preventing data loss. The caller is informed of the error.
///
/// # Errors
/// - `VaultLocked` — vault is not currently unlocked.
/// - `FileOperationFailed`, `SaveCommitDurabilityUncertain` — disk write failed.
#[tauri::command]
pub fn lock_vault(
    auto_lock: State<'_, SharedAutoLock>,
    state: State<'_, SharedVaultState>,
) -> std::result::Result<(), CommandError> {
    lock_vault_impl(&auto_lock, &state)
}

pub fn lock_vault_impl(
    auto_lock: &SharedAutoLock,
    state: &SharedVaultState,
) -> std::result::Result<(), CommandError> {
    crate::vault::autolock::execute_manual_lock(auto_lock, state)
}

/// `get_vault_status` command (api-contract.md §3).
///
/// Returns the current lifecycle state of the vault without revealing any secret material.
/// Available at all times, regardless of vault state.
#[tauri::command]
pub fn get_vault_status(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<VaultStatusResponse, CommandError> {
    let guard = lock_state(&state)?;
    let status = match &*guard {
        VaultState::Uninitialised => VaultStatusResponse::Uninitialised,
        VaultState::Locked { .. } => VaultStatusResponse::Locked,
        VaultState::Unlocked { .. } => VaultStatusResponse::Unlocked,
    };
    Ok(status)
}

/// `get_vault_summary` command (api-contract.md §3).
///
/// Returns non-secret vault metadata. Only available when the vault is unlocked.
///
/// # Errors
/// - `VaultLocked` — vault must be unlocked first.
/// - `DatabaseFailure` — could not query vault_metadata.
/// - `NotFound` — vault_metadata row is missing (should not happen in a well-formed vault).
#[tauri::command]
pub fn get_vault_summary(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<VaultSummaryResponse, CommandError> {
    let guard = lock_state(&state)?;

    let vault = match &*guard {
        VaultState::Unlocked { vault, .. } => vault,
        _ => {
            return Err(CommandError::new(
                "VaultLocked",
                "The vault must be unlocked to read the summary.",
            ))
        }
    };

    let header = &vault.header;
    let vault_id_hex = hex_encode(&header.vault_id);
    let created_at = header.created_at;

    // Query vault_metadata for the name and updated_at
    let conn = vault.db.conn().map_err(map_error)?;
    let (vault_name, updated_at): (String, u64) = conn
        .query_row(
            "SELECT name, updated_at FROM vault_metadata LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| map_error(AppError::Database(crate::errors::DatabaseError::Sqlite(e))))?;

    Ok(VaultSummaryResponse {
        vault_id: vault_id_hex,
        vault_name,
        created_at,
        updated_at,
    })
}

/// `change_master_password` command (api-contract.md §3).
///
/// Re-wraps the VDK under a new KEK derived from `new_master_password`. The vault must be
/// **unlocked**. The payload ciphertext, `vault_id`, `created_at`, `schema_version`, and
/// `header_length` remain strictly identical (§11.4 invariant).
///
/// The on-disk container is updated atomically. On success, the vault remains in the `Unlocked`
/// state. On failure, no disk mutation has occurred.
///
/// # Errors
/// - `VaultLocked` — vault must be unlocked first.
/// - `AuthenticationFailed` — `current_master_password` is incorrect.
/// - `InvalidInput` — password fails length validation.
/// - `FileOperationFailed` — disk write failed.
#[tauri::command]
pub fn change_master_password(
    state: State<'_, SharedVaultState>,
    current_master_password: String,
    new_master_password: String,
) -> std::result::Result<(), CommandError> {
    validate_password(&current_master_password)?;
    validate_password(&new_master_password)?;

    if current_master_password == new_master_password {
        return Err(CommandError::new(
            "InvalidInput",
            "New password must be different from the current password.",
        ));
    }

    let current_bytes = Zeroizing::new(current_master_password.into_bytes());
    let new_bytes = Zeroizing::new(new_master_password.into_bytes());

    let mut guard = lock_state(&state)?;

    let (path, vault) = match &mut *guard {
        VaultState::Unlocked { path, vault } => (path.clone(), vault.as_mut()),
        _ => {
            return Err(CommandError::new(
                "VaultLocked",
                "The vault must be unlocked to change the master password.",
            ))
        }
    };

    // Read the current on-disk container as the rotation source.
    // We use the on-disk state (which is in sync after create/unlock) to perform the VDK re-wrap
    // without touching the active in-memory payload.
    let on_disk_bytes = read_vault(&path).map_err(map_error)?;

    // Re-wrap VDK; payload ciphertext is unchanged
    let rotated_bytes = crate::vault::operations::change_master_password(
        &on_disk_bytes,
        &current_bytes,
        &new_bytes,
    )
    .map_err(map_error)?;

    // Persist atomically — on failure, nothing has changed on disk or in memory
    write_vault_atomic(&path, &rotated_bytes).map_err(map_error)?;

    // Update in-memory header to reflect new kdf_salt / wrap_nonce / wrapped_vdk so that a
    // subsequent lock-save uses the new header fields.
    // Parse the rotated container to extract the new header.
    let rotated_container =
        crate::vault::container::parse_container(&rotated_bytes).map_err(|e| {
            // This indicates a bug; the rotated bytes we just wrote failed to parse.
            CommandError::new(
                "Internal",
                format!("Rotated container failed internal validation: {e}"),
            )
        })?;

    vault.header = rotated_container.header;

    Ok(())
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Encode a byte slice as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the current time as a Unix timestamp in seconds.
///
/// Falls back to 0 if the system clock is unavailable (should not happen on production hardware).
fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_shared_state() -> SharedVaultState {
        SharedVaultState::new()
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let uuid = format!("{:016x}", rand_u64());
            let path = std::env::temp_dir().join(format!("kivault_cmd_test_{tag}_{uuid}"));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn vault_path(&self) -> PathBuf {
            self.path.join("vault.kivault")
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

    // ── Helpers to drive commands directly against SharedVaultState ──────────

    fn do_create(
        shared: &SharedVaultState,
        vault_path: &str,
        vault_name: &str,
        password: &str,
    ) -> std::result::Result<(), CommandError> {
        // Simulate the State<'_, SharedVaultState> by cloning Arc and running logic inline.
        // Since Tauri's `State` cannot be constructed outside Tauri runtime in unit tests,
        // we exercise the underlying business logic functions directly.
        do_create_impl(shared, vault_path, vault_name, password)
    }

    fn do_create_impl(
        shared: &SharedVaultState,
        vault_path: &str,
        vault_name: &str,
        master_password: &str,
    ) -> std::result::Result<(), CommandError> {
        let path = validate_path(vault_path)?;
        validate_vault_name(vault_name)?;
        validate_password(master_password)?;

        if path.exists() {
            return Err(CommandError::new(
                "VaultAlreadyExists",
                "A vault file already exists at the specified path.",
            ));
        }

        let password_bytes = Zeroizing::new(master_password.as_bytes().to_vec());

        let initial_db = InMemoryDb::create_empty().map_err(map_error)?;
        {
            let vault_id_bytes = crate::crypto::generate_vault_id().map_err(map_error)?;
            let vault_id_hex = hex_encode(&vault_id_bytes);
            let now = current_unix_timestamp();
            let conn = initial_db.conn().map_err(map_error)?;
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                rusqlite::params![vault_id_hex, vault_name, now, now],
            )
            .map_err(|e| map_error(AppError::Database(crate::errors::DatabaseError::Sqlite(e))))?;
        }
        let initial_image = initial_db.to_image().map_err(map_error)?;
        drop(initial_db);

        let now = current_unix_timestamp();
        let container_bytes = crate::vault::operations::create_vault(
            &password_bytes,
            now,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            &initial_image,
        )
        .map_err(map_error)?;

        write_vault_atomic(&path, &container_bytes).map_err(map_error)?;

        let mut guard = shared.0.lock().unwrap();
        *guard = VaultState::Locked { path };
        Ok(())
    }

    fn do_unlock(
        shared: &SharedVaultState,
        password: &str,
    ) -> std::result::Result<(), CommandError> {
        do_unlock_with_path(shared, password, None)
    }

    fn do_unlock_with_path(
        shared: &SharedVaultState,
        password: &str,
        vault_path: Option<&str>,
    ) -> std::result::Result<(), CommandError> {
        let auto_lock = SharedAutoLock::new();
        unlock_vault_impl(
            &auto_lock,
            shared,
            password.to_string(),
            vault_path.map(|s| s.to_string()),
        )
    }

    fn do_lock(shared: &SharedVaultState) -> std::result::Result<(), CommandError> {
        let auto_lock = SharedAutoLock::new();
        // Set auto_lock is_locked = false so execute_manual_lock doesn't reject
        {
            let mut al = auto_lock.0.lock().unwrap();
            al.is_locked = false;
        }
        lock_vault_impl(&auto_lock, shared)
    }

    fn do_status(shared: &SharedVaultState) -> VaultStatusResponse {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Uninitialised => VaultStatusResponse::Uninitialised,
            VaultState::Locked { .. } => VaultStatusResponse::Locked,
            VaultState::Unlocked { .. } => VaultStatusResponse::Unlocked,
        }
    }

    fn do_summary(
        shared: &SharedVaultState,
    ) -> std::result::Result<VaultSummaryResponse, CommandError> {
        let guard = shared.0.lock().unwrap();
        let vault = match &*guard {
            VaultState::Unlocked { vault, .. } => vault,
            _ => return Err(CommandError::new("VaultLocked", "Must be unlocked.")),
        };
        let conn = vault.db.conn().map_err(map_error)?;
        let (vault_name, updated_at): (String, u64) = conn
            .query_row(
                "SELECT name, updated_at FROM vault_metadata LIMIT 1;",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| map_error(AppError::Database(crate::errors::DatabaseError::Sqlite(e))))?;
        Ok(VaultSummaryResponse {
            vault_id: hex_encode(&vault.header.vault_id),
            vault_name,
            created_at: vault.header.created_at,
            updated_at,
        })
    }

    fn do_change_password(
        shared: &SharedVaultState,
        current: &str,
        new: &str,
    ) -> std::result::Result<(), CommandError> {
        validate_password(current)?;
        validate_password(new)?;
        if current == new {
            return Err(CommandError::new(
                "InvalidInput",
                "New password must be different from the current password.",
            ));
        }

        let current_bytes = Zeroizing::new(current.as_bytes().to_vec());
        let new_bytes = Zeroizing::new(new.as_bytes().to_vec());

        let mut guard = shared.0.lock().unwrap();
        let (path, vault) = match &mut *guard {
            VaultState::Unlocked { path, vault } => (path.clone(), vault.as_mut()),
            _ => return Err(CommandError::new("VaultLocked", "Must be unlocked.")),
        };

        let on_disk_bytes = read_vault(&path).map_err(map_error)?;
        let rotated_bytes = crate::vault::operations::change_master_password(
            &on_disk_bytes,
            &current_bytes,
            &new_bytes,
        )
        .map_err(map_error)?;
        write_vault_atomic(&path, &rotated_bytes).map_err(map_error)?;

        let rotated_container =
            crate::vault::container::parse_container(&rotated_bytes).map_err(|e| {
                CommandError::new("Internal", format!("Rotated container parse error: {e}"))
            })?;
        vault.header = rotated_container.header;
        Ok(())
    }

    // ── Test 1: create → unlock → lock round-trip ────────────────────────────

    #[test]
    fn test_create_unlock_lock_roundtrip() {
        let tmp = TempDir::new("roundtrip");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        // Initial status must be Uninitialised
        assert_eq!(do_status(&shared), VaultStatusResponse::Uninitialised);

        // Create vault
        do_create(&shared, &path, "My Test Vault", "super-secret-pass-1").unwrap();
        assert!(tmp.vault_path().exists(), "vault file must be created");
        assert_eq!(do_status(&shared), VaultStatusResponse::Locked);

        // Unlock vault
        do_unlock(&shared, "super-secret-pass-1").unwrap();
        assert_eq!(do_status(&shared), VaultStatusResponse::Unlocked);

        // Summary available when unlocked
        let summary = do_summary(&shared).unwrap();
        assert_eq!(summary.vault_name, "My Test Vault");
        assert!(summary.created_at > 0);
        assert!(summary.updated_at >= summary.created_at);
        assert!(!summary.vault_id.is_empty());

        // Lock vault
        do_lock(&shared).unwrap();
        assert_eq!(do_status(&shared), VaultStatusResponse::Locked);

        // Summary unavailable when locked
        assert!(do_summary(&shared).is_err());

        // Can unlock again after lock
        do_unlock(&shared, "super-secret-pass-1").unwrap();
        assert_eq!(do_status(&shared), VaultStatusResponse::Unlocked);
    }

    // ── Test 1b: unlock after restart (Uninitialised state + vault_path) ──────

    #[test]
    fn test_unlock_after_app_restart_with_path() {
        let tmp = TempDir::new("restart");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        // 1. Create and lock
        do_create(&shared, &path, "RestartVault", "pass-restart").unwrap();
        assert_eq!(do_status(&shared), VaultStatusResponse::Locked);

        // 2. Simulate application restart: state resets to Uninitialised
        let restarted_shared = build_shared_state();
        assert_eq!(
            do_status(&restarted_shared),
            VaultStatusResponse::Uninitialised
        );

        // 3. Unlock without path fails because no active vault is known
        let err = do_unlock(&restarted_shared, "pass-restart").unwrap_err();
        assert_eq!(err.code, "VaultLocked");

        // 4. Unlock with path succeeds and transitions to Unlocked
        do_unlock_with_path(&restarted_shared, "pass-restart", Some(&path)).unwrap();
        assert_eq!(do_status(&restarted_shared), VaultStatusResponse::Unlocked);

        let summary = do_summary(&restarted_shared).unwrap();
        assert_eq!(summary.vault_name, "RestartVault");
        assert!(summary.created_at > 0);
        assert!(summary.updated_at > 0);
    }

    // ── Test 2: wrong password rejected ─────────────────────────────────────

    #[test]
    fn test_unlock_wrong_password_rejected() {
        let tmp = TempDir::new("wrong_pass");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "WrongPassVault", "correct-pass").unwrap();

        let err = do_unlock(&shared, "wrong-pass").unwrap_err();
        assert_eq!(
            err.code, "AuthenticationFailed",
            "wrong password must return AuthenticationFailed, got: {:?}",
            err
        );
        // State must remain Locked
        assert_eq!(do_status(&shared), VaultStatusResponse::Locked);
    }

    // ── Test 3: corrupted container rejected on unlock ───────────────────────

    #[test]
    fn test_unlock_corrupted_container_rejected() {
        let tmp = TempDir::new("corrupt");
        let path_buf = tmp.vault_path();
        let path = path_buf.to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "CorruptVault", "pass").unwrap();

        // Corrupt the last byte of the vault file (part of the auth tag)
        let mut bytes = std::fs::read(&path_buf).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Write corrupted bytes directly (bypassing atomic write validation)
        std::fs::write(&path_buf, &bytes).unwrap();

        let err = do_unlock(&shared, "pass").unwrap_err();
        // Either AuthenticationFailed (GCM tag corrupted) or IntegrityFailure (container parse)
        assert!(
            err.code == "AuthenticationFailed" || err.code == "IntegrityFailure",
            "corrupted container must return AuthenticationFailed or IntegrityFailure, got: {:?}",
            err
        );
        assert_eq!(do_status(&shared), VaultStatusResponse::Locked);
    }

    // ── Test 4: master password rotation ────────────────────────────────────

    #[test]
    fn test_change_master_password_roundtrip() {
        let tmp = TempDir::new("rotation");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "RotationVault", "old-password").unwrap();
        do_unlock(&shared, "old-password").unwrap();

        // Capture original vault_id for invariant check
        let summary_before = do_summary(&shared).unwrap();
        let vault_id_before = summary_before.vault_id.clone();

        // Rotate password
        do_change_password(&shared, "old-password", "new-password").unwrap();

        // Old password must fail on re-unlock after lock/unlock cycle
        do_lock(&shared).unwrap();
        let err = do_unlock(&shared, "old-password").unwrap_err();
        assert_eq!(err.code, "AuthenticationFailed");

        // New password must succeed
        do_unlock(&shared, "new-password").unwrap();

        let summary_after = do_summary(&shared).unwrap();
        // vault_id, vault_name, created_at, updated_at must match
        assert_eq!(summary_after.vault_id, vault_id_before);
        assert_eq!(summary_after.vault_name, "RotationVault");
        assert_eq!(summary_after.created_at, summary_before.created_at);
        assert_eq!(summary_after.updated_at, summary_before.updated_at);
    }

    // ── Test 5: lock failure preserves in-memory data ─────────────────────────

    #[test]
    fn test_lock_with_inaccessible_path_preserves_state() {
        let tmp = TempDir::new("lock_fail");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "FailLockVault", "pass").unwrap();
        do_unlock(&shared, "pass").unwrap();
        assert_eq!(do_status(&shared), VaultStatusResponse::Unlocked);

        // Simulate a disk failure by replacing the vault with a directory (cannot overwrite)
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(&path).unwrap(); // path is now a directory — write will fail

        let err = do_lock(&shared).unwrap_err();
        assert_ne!(err.code, "", "lock must report an error when save fails");

        // State must remain Unlocked — in-memory data preserved
        assert_eq!(
            do_status(&shared),
            VaultStatusResponse::Unlocked,
            "state must remain Unlocked when save fails to prevent data loss"
        );

        // Summary still accessible
        let summary = do_summary(&shared).unwrap();
        assert_eq!(summary.vault_name, "FailLockVault");

        // Cleanup: remove the fake directory so TempDir can clean up
        std::fs::remove_dir_all(&path).ok();
    }

    // ── Test 6: create rejects existing file ─────────────────────────────────

    #[test]
    fn test_create_rejects_existing_vault() {
        let tmp = TempDir::new("exists");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "Vault1", "pass1").unwrap();

        let shared2 = build_shared_state();
        // Reset path to Locked so second create triggers the exists check
        {
            let mut g = shared2.0.lock().unwrap();
            *g = VaultState::Uninitialised;
        }

        let err = do_create(&shared2, &path, "Vault2", "pass2").unwrap_err();
        assert_eq!(err.code, "VaultAlreadyExists");
    }

    // ── Test 7: password same-as-old rejected ────────────────────────────────

    #[test]
    fn test_change_password_same_as_old_rejected() {
        let tmp = TempDir::new("same_pass");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "SameVault", "same-pass").unwrap();
        do_unlock(&shared, "same-pass").unwrap();

        let err = do_change_password(&shared, "same-pass", "same-pass").unwrap_err();
        assert_eq!(err.code, "InvalidInput");
    }

    // ── Test 8: empty password rejected ─────────────────────────────────────

    #[test]
    fn test_empty_password_rejected() {
        let tmp = TempDir::new("empty_pass");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        let err = do_create(&shared, &path, "EmptyPassVault", "").unwrap_err();
        assert_eq!(err.code, "InvalidInput");
    }

    // ── Test 9: get_vault_summary locked state error ─────────────────────────

    #[test]
    fn test_summary_unavailable_when_locked() {
        let tmp = TempDir::new("summary_locked");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "LockedSummary", "pass").unwrap();
        // State is Locked after create
        let err = do_summary(&shared).unwrap_err();
        assert_eq!(err.code, "VaultLocked");
    }

    // ── Test 10: concurrent unlock rejected ──────────────────────────────────

    #[test]
    fn test_double_unlock_rejected() {
        let tmp = TempDir::new("double_unlock");
        let path = tmp.vault_path().to_str().unwrap().to_owned();
        let shared = build_shared_state();

        do_create(&shared, &path, "DoubleUnlock", "pass").unwrap();
        do_unlock(&shared, "pass").unwrap();

        // Second unlock attempt while already Unlocked must fail
        let err = do_unlock(&shared, "pass").unwrap_err();
        assert_eq!(err.code, "VaultAlreadyExists");
    }
}
