//! Security Center Tauri Commands
//!
//! Implements typed Tauri commands according to `docs/api-contract.md` §10:
//! - `get_security_status`
//! - `get_password_health`
//! - `notify_activity`
//!
//! # Security Properties
//! - All commands enforce that the single active vault is unlocked.
//!   If locked or uninitialised, commands fail-closed with `VaultLocked`.
//! - `get_password_health` returns exclusively aggregated counts (`weak_count`, `reused_count`).
//!   Passwords and account details are never logged, returned, or exposed.
//! - `notify_activity` acknowledges frontend activity for auto-lock bookkeeping.
//!   Rust remains authoritative over the lock deadline.

use tauri::State;

use crate::commands::vault::{
    map_error, CommandError, SharedAutoLock, SharedVaultState, VaultState,
};
use crate::security::{
    calculate_password_health, get_security_status_for_vault, ActivityNotificationResponse,
    PasswordHealthResponse, SecurityStatusResponse,
};

pub fn get_security_status_impl(
    shared: &SharedVaultState,
) -> std::result::Result<SecurityStatusResponse, CommandError> {
    let guard = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            get_security_status_for_vault(&vault.header, &vault.db).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn get_password_health_impl(
    shared: &SharedVaultState,
) -> std::result::Result<PasswordHealthResponse, CommandError> {
    let guard = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            calculate_password_health(&vault.db).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn notify_activity_impl(
    auto_lock: &SharedAutoLock,
    shared: &SharedVaultState,
) -> std::result::Result<ActivityNotificationResponse, CommandError> {
    notify_activity_with_clock(auto_lock, shared, &crate::vault::autolock::SystemClock)
}

pub fn notify_activity_with_clock<C: crate::vault::autolock::Clock>(
    auto_lock: &SharedAutoLock,
    shared: &SharedVaultState,
    clock: &C,
) -> std::result::Result<ActivityNotificationResponse, CommandError> {
    // Follow strict order: AutoLockRuntime -> VaultState
    let mut al = auto_lock.0.lock().map_err(|_| {
        CommandError::new("Internal", "Internal auto-lock runtime lock was poisoned.")
    })?;

    if al.is_locked {
        return Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        ));
    }

    let vs = shared
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;

    match &*vs {
        VaultState::Unlocked { .. } => {
            // Acknowledge user activity and reset deadline
            al.last_activity = clock.now();
            Ok(ActivityNotificationResponse {
                acknowledged: true,
                auto_lock_enforced: al.effective_timeout.is_some(),
            })
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

/// Retrieve security status report (`api-contract.md` §10).
#[tauri::command]
pub fn get_security_status(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<SecurityStatusResponse, CommandError> {
    get_security_status_impl(&state)
}

/// Retrieve password health summary counts (`api-contract.md` §10).
#[tauri::command]
pub fn get_password_health(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<PasswordHealthResponse, CommandError> {
    get_password_health_impl(&state)
}

/// Notify user activity to reset auto-lock deadline (`api-contract.md` §10).
#[tauri::command]
pub fn notify_activity(
    auto_lock: State<'_, SharedAutoLock>,
    state: State<'_, SharedVaultState>,
) -> std::result::Result<ActivityNotificationResponse, CommandError> {
    notify_activity_impl(&auto_lock, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountRepository, CreateAccountParams};
    use crate::platforms::{CreatePlatformParams, PlatformRepository};
    use crate::settings::{SecuritySettings, SettingsRepository};
    use crate::vault::cbor::{VaultHeader, VaultHeaderParams};
    use crate::vault::operations::UnlockedVault;
    use crate::vault::sqlite::InMemoryDb;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    fn build_unlocked_shared_state() -> SharedVaultState {
        let db = InMemoryDb::create_empty().unwrap();
        let header = VaultHeader::new_v1(VaultHeaderParams {
            vault_id: [1u8; 16],
            created_at: 1000,
            schema_version: crate::vault::sqlite::SCHEMA_VERSION_V1,
            minimum_reader: crate::vault::sqlite::SCHEMA_VERSION_V1,
            kdf_salt: [2u8; 32],
            wrap_nonce: [3u8; 12],
            wrapped_vdk: [4u8; 48],
            payload_kdf_salt: [5u8; 32],
            payload_nonce: [6u8; 12],
        })
        .unwrap();

        let unlocked = UnlockedVault {
            header,
            vdk: Zeroizing::new([7u8; 32]),
            db,
        };

        let shared = SharedVaultState::new();
        {
            let mut g = shared.0.lock().unwrap();
            *g = VaultState::Unlocked {
                path: PathBuf::from("test.kivault"),
                vault: Box::new(unlocked),
            };
        }
        shared
    }

    #[test]
    fn test_security_commands_reject_when_locked() {
        let state = SharedVaultState::new();
        let auto_lock = SharedAutoLock::new();

        assert_eq!(
            get_security_status_impl(&state).unwrap_err().code,
            "VaultLocked"
        );
        assert_eq!(
            get_password_health_impl(&state).unwrap_err().code,
            "VaultLocked"
        );
        assert_eq!(
            notify_activity_impl(&auto_lock, &state).unwrap_err().code,
            "VaultLocked"
        );
    }

    #[test]
    fn test_get_security_status_returns_valid_data() {
        let shared = build_unlocked_shared_state();

        // 1. Check default security status
        let status = get_security_status_impl(&shared).unwrap();
        assert_eq!(status.encryption, "AES-256-GCM");
        assert_eq!(status.kdf, "Argon2id");
        assert_eq!(status.vault_state, "Unlocked");
        assert_eq!(status.auto_lock, "5m");
        assert_eq!(status.clipboard_timeout, 15);
        assert_eq!(status.vault_integrity, "OK");

        // 2. Modify settings and verify security status reflects updated settings
        {
            let guard = shared.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let settings_repo = SettingsRepository::new(&vault.db);
                settings_repo
                    .update_security(&SecuritySettings {
                        auto_lock: "15m".to_string(),
                        clipboard_timeout: 30,
                    })
                    .unwrap();
            }
        }

        let updated_status = get_security_status_impl(&shared).unwrap();
        assert_eq!(updated_status.auto_lock, "15m");
        assert_eq!(updated_status.clipboard_timeout, 30);
    }

    #[test]
    fn test_get_password_health_aggregates_and_never_leaks_secrets() {
        let shared = build_unlocked_shared_state();

        // 1. Initial state: 0 accounts -> 0 weak, 0 reused
        let initial_health = get_password_health_impl(&shared).unwrap();
        assert_eq!(initial_health.weak_count, 0);
        assert_eq!(initial_health.reused_count, 0);

        // 2. Insert test platform and accounts
        {
            let guard = shared.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let plat_repo = PlatformRepository::new(&vault.db);
                let p = plat_repo
                    .create(
                        CreatePlatformParams {
                            name: "TestCorp".into(),
                            category: None,
                            website: None,
                            logo_id: None,
                        },
                        1000,
                    )
                    .unwrap();

                let acc_repo = AccountRepository::new(&vault.db);

                // Account 1: Weak password ("short1", <12 chars)
                acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: p.id.clone(),
                            display_name: Some("Acc 1".into()),
                            username: Some("user1".into()),
                            email: None,
                            password: Some("short1".into()),
                            url: None,
                            notes: None,
                            is_favorite: false,
                            tag_ids: vec![],
                            custom_fields: vec![],
                        },
                        1000,
                    )
                    .unwrap();

                // Account 2: Strong password ("StrongP@ssw0rd123!")
                acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: p.id.clone(),
                            display_name: Some("Acc 2".into()),
                            username: Some("user2".into()),
                            email: None,
                            password: Some("StrongP@ssw0rd123!".into()),
                            url: None,
                            notes: None,
                            is_favorite: false,
                            tag_ids: vec![],
                            custom_fields: vec![],
                        },
                        1000,
                    )
                    .unwrap();

                // Account 3: Reused strong password (same as Account 2)
                acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: p.id.clone(),
                            display_name: Some("Acc 3".into()),
                            username: Some("user3".into()),
                            email: None,
                            password: Some("StrongP@ssw0rd123!".into()),
                            url: None,
                            notes: None,
                            is_favorite: false,
                            tag_ids: vec![],
                            custom_fields: vec![],
                        },
                        1000,
                    )
                    .unwrap();

                // Account 4: Reused weak password (same as Account 1: "short1")
                acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: p.id.clone(),
                            display_name: Some("Acc 4".into()),
                            username: Some("user4".into()),
                            email: None,
                            password: Some("short1".into()),
                            url: None,
                            notes: None,
                            is_favorite: false,
                            tag_ids: vec![],
                            custom_fields: vec![],
                        },
                        1000,
                    )
                    .unwrap();

                // Account 5: No password (e.g. OAuth / SSO account)
                acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: p.id.clone(),
                            display_name: Some("Acc 5 SSO".into()),
                            username: Some("user5_sso".into()),
                            email: None,
                            password: None,
                            url: None,
                            notes: None,
                            is_favorite: false,
                            tag_ids: vec![],
                            custom_fields: vec![],
                        },
                        1000,
                    )
                    .unwrap();
            }
        }

        // Expected counts:
        // - Weak: Account 1 ("short1") + Account 4 ("short1") = 2 weak passwords
        // - Reused: "StrongP@ssw0rd123!" used twice (Acc 2 & Acc 3) + "short1" used twice (Acc 1 & Acc 4) = 4 accounts sharing passwords
        let health = get_password_health_impl(&shared).unwrap();
        assert_eq!(health.weak_count, 2);
        assert_eq!(health.reused_count, 4);

        // Security assertion: Serializing PasswordHealthResponse produces zero password strings
        let json = serde_json::to_string(&health).unwrap();
        assert!(!json.contains("short1"));
        assert!(!json.contains("StrongP@ssw0rd123!"));
        assert!(!json.contains("user1"));
        assert!(!json.contains("user2"));
    }

    #[test]
    fn test_notify_activity_acknowledged() {
        let shared = build_unlocked_shared_state();
        let auto_lock = SharedAutoLock::new();
        {
            let mut al = auto_lock.0.lock().unwrap();
            al.is_locked = false;
            al.effective_timeout = Some(std::time::Duration::from_secs(300));
        }
        let res = notify_activity_impl(&auto_lock, &shared).unwrap();
        assert!(res.acknowledged);
        assert!(res.auto_lock_enforced);
    }
}
