//! Settings Tauri Commands
//!
//! Implements typed Tauri commands for settings according to `docs/api-contract.md` §11:
//! - `get_settings`
//! - `update_security_settings`
//! - `update_password_generator_settings`
//!
//! # Security Properties
//! - All commands enforce that the vault is unlocked (`VaultLocked` otherwise).
//! - Mutations validate options against allow-lists and rules in Rust.
//! - Mutations automatically persist the vault container to disk atomically.

use tauri::State;

use crate::commands::vault::{map_error, CommandError, SharedVaultState, VaultState};
use crate::settings::{
    PasswordGeneratorSettings, SecuritySettings, SettingsRepository, VaultSettings,
};

pub fn get_settings_impl(
    shared: &SharedVaultState,
) -> std::result::Result<VaultSettings, CommandError> {
    let guard = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = SettingsRepository::new(&vault.db);
            repo.get_all().map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn update_security_settings_impl(
    shared: &SharedVaultState,
    settings: SecuritySettings,
) -> std::result::Result<SecuritySettings, CommandError> {
    let mut guard = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &mut *guard {
        VaultState::Unlocked { path, vault } => {
            let repo = SettingsRepository::new(&vault.db);
            repo.update_security(&settings).map_err(map_error)?;

            // Atomically persist changes to disk
            vault.save_to_file(path).map_err(map_error)?;

            Ok(settings)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn update_password_generator_settings_impl(
    shared: &SharedVaultState,
    settings: PasswordGeneratorSettings,
) -> std::result::Result<PasswordGeneratorSettings, CommandError> {
    let mut guard = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &mut *guard {
        VaultState::Unlocked { path, vault } => {
            let repo = SettingsRepository::new(&vault.db);
            repo.update_password_generator(&settings)
                .map_err(map_error)?;

            // Atomically persist changes to disk
            vault.save_to_file(path).map_err(map_error)?;

            Ok(settings)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// Retrieve all vault settings (`api-contract.md` §11).
#[tauri::command]
pub fn get_settings(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<VaultSettings, CommandError> {
    get_settings_impl(&state)
}

/// Update security settings (auto-lock and clipboard timeouts) (`api-contract.md` §11).
#[tauri::command]
pub fn update_security_settings(
    state: State<'_, SharedVaultState>,
    settings: SecuritySettings,
) -> std::result::Result<SecuritySettings, CommandError> {
    update_security_settings_impl(&state, settings)
}

/// Update password generator default settings (`api-contract.md` §11).
#[tauri::command]
pub fn update_password_generator_settings(
    state: State<'_, SharedVaultState>,
    settings: PasswordGeneratorSettings,
) -> std::result::Result<PasswordGeneratorSettings, CommandError> {
    update_password_generator_settings_impl(&state, settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_salt;
    use crate::vault::operations::{create_vault, unlock_vault};
    use crate::vault::sqlite::InMemoryDb;
    use crate::vault::storage::{read_vault, write_vault_atomic};
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    struct TempVaultFile {
        path: PathBuf,
    }

    impl TempVaultFile {
        fn new() -> Self {
            let salt = generate_salt().unwrap();
            let hex_salt: String = salt[..8].iter().map(|b| format!("{b:02x}")).collect();
            let mut path = std::env::temp_dir();
            path.push(format!("kivault_settings_cmd_test_{}.kivault", hex_salt));
            Self { path }
        }
    }

    impl Drop for TempVaultFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn create_test_vault_on_disk(path: &std::path::Path, password: &[u8]) {
        let initial_db = InMemoryDb::create_empty().unwrap();
        let payload = initial_db.to_image().unwrap();
        let container = create_vault(
            password,
            1000,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            &payload,
        )
        .unwrap();
        write_vault_atomic(path, &container).unwrap();
    }

    #[test]
    fn test_settings_commands_locked_checks() {
        let state = SharedVaultState::new();

        // 1. Uninitialised -> VaultLocked
        assert_eq!(get_settings_impl(&state).unwrap_err().code, "VaultLocked");
        assert_eq!(
            update_security_settings_impl(&state, SecuritySettings::default())
                .unwrap_err()
                .code,
            "VaultLocked"
        );
        assert_eq!(
            update_password_generator_settings_impl(&state, PasswordGeneratorSettings::default())
                .unwrap_err()
                .code,
            "VaultLocked"
        );
    }

    #[test]
    fn test_settings_commands_crud_validation_and_persistence() {
        let temp = TempVaultFile::new();
        let password = b"CorrectPassword123!";
        create_test_vault_on_disk(&temp.path, password);

        // Unlock into SharedVaultState
        let container_bytes = read_vault(&temp.path).unwrap();
        let pw_zero = Zeroizing::new(password.to_vec());
        let unlocked = unlock_vault(&container_bytes, &pw_zero).unwrap();

        let state = SharedVaultState::new();
        {
            let mut g = state.0.lock().unwrap();
            *g = VaultState::Unlocked {
                path: temp.path.clone(),
                vault: Box::new(unlocked),
            };
        }

        // 2. Initial settings should be default
        let initial = get_settings_impl(&state).unwrap();
        assert_eq!(initial.security.auto_lock, "5m");
        assert_eq!(initial.security.clipboard_timeout, 15);
        assert_eq!(initial.password_generator.length, 16);
        assert!(initial.password_generator.use_uppercase);
        assert!(initial.password_generator.use_symbols);

        // 3. Update security settings with invalid inputs
        let err_invalid_autolock = update_security_settings_impl(
            &state,
            SecuritySettings {
                auto_lock: "10m".to_string(), // not in allow-list
                clipboard_timeout: 15,
            },
        )
        .unwrap_err();
        assert_eq!(err_invalid_autolock.code, "InvalidInput");

        let err_invalid_clipboard = update_security_settings_impl(
            &state,
            SecuritySettings {
                auto_lock: "5m".to_string(),
                clipboard_timeout: 45, // not in allow-list
            },
        )
        .unwrap_err();
        assert_eq!(err_invalid_clipboard.code, "InvalidInput");

        // 4. Update security settings with valid inputs
        let updated_sec = update_security_settings_impl(
            &state,
            SecuritySettings {
                auto_lock: "30m".to_string(),
                clipboard_timeout: 60,
            },
        )
        .unwrap();
        assert_eq!(updated_sec.auto_lock, "30m");
        assert_eq!(updated_sec.clipboard_timeout, 60);

        // 5. Update password generator with invalid inputs
        let err_short_len = update_password_generator_settings_impl(
            &state,
            PasswordGeneratorSettings {
                length: 7, // < 8
                use_uppercase: true,
                use_lowercase: true,
                use_numbers: true,
                use_symbols: true,
            },
        )
        .unwrap_err();
        assert_eq!(err_short_len.code, "InvalidInput");

        let err_no_classes = update_password_generator_settings_impl(
            &state,
            PasswordGeneratorSettings {
                length: 16,
                use_uppercase: false,
                use_lowercase: false,
                use_numbers: false,
                use_symbols: false,
            },
        )
        .unwrap_err();
        assert_eq!(err_no_classes.code, "InvalidInput");

        // 6. Update password generator with valid inputs
        let updated_gen = update_password_generator_settings_impl(
            &state,
            PasswordGeneratorSettings {
                length: 24,
                use_uppercase: true,
                use_lowercase: true,
                use_numbers: false,
                use_symbols: false,
            },
        )
        .unwrap();
        assert_eq!(updated_gen.length, 24);
        assert!(!updated_gen.use_numbers);

        // 7. Lock vault and re-unlock to prove persistence on disk
        {
            let mut g = state.0.lock().unwrap();
            let (path, mut vault) = match std::mem::replace(&mut *g, VaultState::Uninitialised) {
                VaultState::Unlocked { path, vault } => (path, vault),
                _ => panic!("Expected unlocked vault"),
            };
            vault.lock();
            *g = VaultState::Locked { path };
        }

        // While locked, get_settings must fail
        assert_eq!(get_settings_impl(&state).unwrap_err().code, "VaultLocked");

        // Re-unlock from disk
        let disk_bytes = read_vault(&temp.path).unwrap();
        let re_unlocked = unlock_vault(&disk_bytes, &pw_zero).unwrap();
        {
            let mut g = state.0.lock().unwrap();
            *g = VaultState::Unlocked {
                path: temp.path.clone(),
                vault: Box::new(re_unlocked),
            };
        }

        // Verify persisted values survived re-unlock from disk
        let persisted = get_settings_impl(&state).unwrap();
        assert_eq!(persisted.security.auto_lock, "30m");
        assert_eq!(persisted.security.clipboard_timeout, 60);
        assert_eq!(persisted.password_generator.length, 24);
        assert!(persisted.password_generator.use_uppercase);
        assert!(persisted.password_generator.use_lowercase);
        assert!(!persisted.password_generator.use_numbers);
        assert!(!persisted.password_generator.use_symbols);
    }
}
