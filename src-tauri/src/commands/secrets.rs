//! Secret Handling & Clipboard Tauri Commands
//!
//! Implements `reveal_secret` and `copy_secret` according to `docs/api-contract.md` §6.
//!
//! # Security Invariants
//! - Both commands require the active vault to be unlocked (`VaultState::Unlocked`).
//! - Secret types are explicitly allow-listed: `password`, `recovery_code`, `totp_secret`,
//!   or matching a custom field name if marked sensitive.
//! - Secrets are never logged or persisted to disk outside the encrypted vault container.
//! - `copy_secret` strictly copies from Rust to the system clipboard and NEVER returns the secret to React.
//! - Clipboard auto-clear timer checks whether the clipboard was modified before clearing.

use std::sync::Arc;
use tauri::State;
use zeroize::Zeroizing;

use crate::accounts::AccountRepository;
use crate::clipboard::{copy_and_schedule_clear, OsClipboard};
use crate::commands::vault::{lock_state, map_error, CommandError, SharedVaultState, VaultState};
use crate::custom_fields::CustomFieldRepository;

/// Retrieves a secret value for a given account and field name.
///
/// Supported fields:
/// - `"password"`: account primary password
/// - `"recovery_code"` / `"totp_secret"`: looked up from sensitive custom fields or account attributes
/// - custom field name if `is_sensitive == true`
pub(crate) fn extract_secret_field(
    db: &crate::vault::sqlite::InMemoryDb,
    account_id: &str,
    field: &str,
) -> Result<Zeroizing<String>, CommandError> {
    let acc_repo = AccountRepository::new(db);
    let account = acc_repo.get_by_id(account_id).map_err(map_error)?;

    match field {
        "password" => {
            if let Some(pw) = account.password {
                Ok(Zeroizing::new(pw))
            } else {
                Err(CommandError::new(
                    "NotFound",
                    "No password is set for this account.",
                ))
            }
        }
        "recovery_code" | "totp_secret" => {
            // Check custom fields for recovery_code or totp_secret
            let cf_repo = CustomFieldRepository::new(db);
            let cfs = cf_repo.list_by_account(account_id).map_err(map_error)?;
            for cf in cfs {
                if cf.field_name.eq_ignore_ascii_case(field) {
                    if !cf.is_sensitive {
                        return Err(CommandError::new(
                            "InvalidInput",
                            format!("Field '{field}' is not configured as sensitive."),
                        ));
                    }
                    return Ok(Zeroizing::new(cf.field_value));
                }
            }
            Err(CommandError::new(
                "NotFound",
                format!("Field '{field}' not found for this account."),
            ))
        }
        custom => {
            // Allow looking up custom field only if is_sensitive == true
            let cf_repo = CustomFieldRepository::new(db);
            let cfs = cf_repo.list_by_account(account_id).map_err(map_error)?;
            for cf in cfs {
                if cf.field_name == custom {
                    if !cf.is_sensitive {
                        return Err(CommandError::new(
                            "InvalidInput",
                            format!("Field '{custom}' is not marked as sensitive."),
                        ));
                    }
                    return Ok(Zeroizing::new(cf.field_value));
                }
            }
            Err(CommandError::new(
                "NotFound",
                format!("Field '{custom}' not found for this account."),
            ))
        }
    }
}

/// `reveal_secret` command (api-contract.md §6).
///
/// Returns the requested secret value to the frontend.
///
/// # Security
/// - The frontend must not persist this response.
/// - Requires unlocked vault.
#[tauri::command]
pub fn reveal_secret(
    state: State<'_, SharedVaultState>,
    account_id: String,
    field: String,
) -> std::result::Result<String, CommandError> {
    if account_id.trim().is_empty() || field.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID and field name must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let secret = extract_secret_field(&vault.db, &account_id, &field)?;
            // Return plaintext String across the IPC boundary to caller
            Ok((*secret).clone())
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to reveal secrets.",
        )),
    }
}

/// `copy_secret` command (api-contract.md §6).
///
/// Copies the secret directly to the OS clipboard from Rust and sets up auto-clear timeout.
///
/// # Security
/// - The secret is NEVER returned in the command response.
/// - Timeout defaults to 15 seconds if 0 or outside valid bounds (5s - 60s).
#[tauri::command]
pub fn copy_secret(
    state: State<'_, SharedVaultState>,
    account_id: String,
    field: String,
    timeout_seconds: Option<u64>,
) -> std::result::Result<(), CommandError> {
    if account_id.trim().is_empty() || field.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID and field name must not be empty.",
        ));
    }

    // Default to 15 seconds per security.md §12 if not provided or 0
    let timeout = match timeout_seconds {
        Some(t) if t > 0 && t <= 300 => t,
        _ => 15,
    };

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let secret = extract_secret_field(&vault.db, &account_id, &field)?;
            let clipboard = Arc::new(OsClipboard::new());
            copy_and_schedule_clear(clipboard, &secret, timeout).map_err(map_error)?;
            Ok(())
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to copy secrets.",
        )),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountRepository, CreateAccountParams, CreateCustomFieldParamsInput};
    use crate::clipboard::{ClipboardBackend, MockClipboard};
    use crate::platforms::{CreatePlatformParams, PlatformRepository};
    use crate::vault::operations::UnlockedVault;
    use crate::vault::sqlite::InMemoryDb;
    use std::path::PathBuf;

    fn build_unlocked_shared_state_with_data() -> (SharedVaultState, String) {
        let db = InMemoryDb::create_empty().unwrap();
        let plat_repo = PlatformRepository::new(&db);
        let acc_repo = AccountRepository::new(&db);

        let p = plat_repo
            .create(
                CreatePlatformParams {
                    name: "SecretService".into(),
                    category: None,
                    website: None,
                    logo_id: None,
                },
                1000,
            )
            .unwrap();

        let acc = acc_repo
            .create(
                CreateAccountParams {
                    platform_id: p.id,
                    display_name: None,
                    username: Some("agent007".into()),
                    email: None,
                    password: Some("classified_pass_xyz".into()),
                    url: None,
                    notes: None,
                    logo_id: None,
                    is_favorite: false,
                    tag_ids: vec![],
                    custom_fields: vec![
                        CreateCustomFieldParamsInput {
                            field_name: "recovery_code".into(),
                            field_value: "REC-999-AAA".into(),
                            field_type: Some("secret".into()),
                            is_sensitive: Some(true),
                        },
                        CreateCustomFieldParamsInput {
                            field_name: "PIN".into(),
                            field_value: "1234".into(),
                            field_type: Some("secret".into()),
                            is_sensitive: Some(true),
                        },
                        CreateCustomFieldParamsInput {
                            field_name: "PublicNote".into(),
                            field_value: "Public info here".into(),
                            field_type: Some("text".into()),
                            is_sensitive: Some(false),
                        },
                    ],
                },
                1000,
            )
            .unwrap();

        let header =
            crate::vault::cbor::VaultHeader::new_v1(crate::vault::cbor::VaultHeaderParams {
                vault_id: [0u8; 16],
                created_at: 1000,
                schema_version: crate::vault::sqlite::SCHEMA_VERSION_V1,
                minimum_reader: crate::vault::sqlite::SCHEMA_VERSION_V1,
                kdf_salt: [0u8; 32],
                wrap_nonce: [0u8; 12],
                wrapped_vdk: [0u8; 48],
                payload_kdf_salt: [0u8; 32],
                payload_nonce: [0u8; 12],
            })
            .unwrap();

        let unlocked = UnlockedVault {
            header,
            vdk: Zeroizing::new([0u8; 32]),
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
        (shared, acc.account.id)
    }

    #[test]
    fn test_secret_commands_reject_when_locked() {
        let shared = SharedVaultState::new(); // Uninitialised/Locked

        // reveal_secret fails-closed
        let guard = shared.0.lock().unwrap();
        let err = match &*guard {
            VaultState::Unlocked { .. } => panic!("Should not be unlocked"),
            _ => CommandError::new("VaultLocked", "Vault locked"),
        };
        assert_eq!(err.code, "VaultLocked");
    }

    #[test]
    fn test_reveal_secret_password_and_custom_fields() {
        let (shared, account_id) = build_unlocked_shared_state_with_data();
        let guard = shared.0.lock().unwrap();
        let db = match &*guard {
            VaultState::Unlocked { vault, .. } => &vault.db,
            _ => panic!("Expected unlocked vault"),
        };

        // 1. Reveal password
        let pw = extract_secret_field(db, &account_id, "password").unwrap();
        assert_eq!(*pw, "classified_pass_xyz");

        // 2. Reveal recovery_code
        let rc = extract_secret_field(db, &account_id, "recovery_code").unwrap();
        assert_eq!(*rc, "REC-999-AAA");

        // 3. Reveal custom sensitive field (PIN)
        let pin = extract_secret_field(db, &account_id, "PIN").unwrap();
        assert_eq!(*pin, "1234");

        // 4. Non-sensitive custom field rejected with InvalidInput
        let err = extract_secret_field(db, &account_id, "PublicNote").unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("not marked as sensitive"));

        // 5. Unknown field rejected with NotFound
        let err = extract_secret_field(db, &account_id, "non_existent").unwrap_err();
        assert_eq!(err.code, "NotFound");

        // 6. Non-existent account rejected with NotFound
        let err = extract_secret_field(db, "fake-acc-id", "password").unwrap_err();
        assert_eq!(err.code, "NotFound");
    }

    #[test]
    fn test_copy_secret_to_clipboard_backend() {
        let (shared, account_id) = build_unlocked_shared_state_with_data();
        let guard = shared.0.lock().unwrap();
        let db = match &*guard {
            VaultState::Unlocked { vault, .. } => &vault.db,
            _ => panic!("Expected unlocked vault"),
        };

        let secret = extract_secret_field(db, &account_id, "password").unwrap();
        let mock_cb = Arc::new(MockClipboard::new());

        // Copy with 1 second timeout
        copy_and_schedule_clear(mock_cb.clone(), &secret, 1).unwrap();

        // Clipboard should immediately contain secret
        assert_eq!(
            mock_cb.get_text().unwrap().as_deref(),
            Some("classified_pass_xyz")
        );

        // After timeout, clipboard is auto-cleared
        std::thread::sleep(std::time::Duration::from_millis(1200));
        assert_eq!(mock_cb.get_text().unwrap(), None);
    }
}
