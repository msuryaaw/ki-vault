//! Logo Tauri Commands
//!
//! Implements typed Tauri commands for logos according to `docs/api-contract.md` (§9):
//! - `import_logo`
//! - `list_logos`
//! - `get_logo`
//! - `rename_logo`
//! - `replace_logo`
//! - `delete_logo`
//! - `assign_logo`
//!
//! # Security Properties
//! - All commands enforce that the active vault is unlocked.
//!   If locked or uninitialised, commands fail-closed with `VaultLocked`.
//! - Input validation, MIME check, and size limit (<= 2 MiB) enforced in Rust.
//! - SVG markup is sanitized using `svg_hush` (scripts, event handlers, external URLs, and XXE stripped/rejected).
//! - Platform references are safely managed during assignment and deletion.

use tauri::State;

use crate::commands::vault::{map_error, CommandError, SharedVaultState, VaultState};
use crate::logos::{ImportLogoParams, Logo, LogoRepository, LogoSummary};

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ─── Implementation functions (testable without Tauri State) ─────────────────

pub fn import_logo_impl(
    state: &SharedVaultState,
    name: String,
    mime_type: String,
    image_data: Vec<u8>,
) -> std::result::Result<Logo, CommandError> {
    if name.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo name must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            let params = ImportLogoParams {
                name,
                mime_type,
                image_data,
            };
            repo.import(params, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn list_logos_impl(
    state: &SharedVaultState,
) -> std::result::Result<Vec<LogoSummary>, CommandError> {
    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.list().map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn get_logo_impl(
    state: &SharedVaultState,
    logo_id: String,
) -> std::result::Result<Logo, CommandError> {
    if logo_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo ID must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.get_by_id(&logo_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn rename_logo_impl(
    state: &SharedVaultState,
    logo_id: String,
    new_name: String,
) -> std::result::Result<Logo, CommandError> {
    if logo_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo ID must not be empty.",
        ));
    }

    if new_name.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo name must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.rename(&logo_id, &new_name, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn replace_logo_impl(
    state: &SharedVaultState,
    logo_id: String,
    new_mime_type: String,
    new_image_data: Vec<u8>,
) -> std::result::Result<Logo, CommandError> {
    if logo_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo ID must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.replace_content(
                &logo_id,
                &new_mime_type,
                &new_image_data,
                current_unix_timestamp(),
            )
            .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn delete_logo_impl(
    state: &SharedVaultState,
    logo_id: String,
) -> std::result::Result<(), CommandError> {
    if logo_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Logo ID must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.delete(&logo_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

pub fn assign_logo_impl(
    state: &SharedVaultState,
    platform_id: String,
    logo_id: Option<String>,
) -> std::result::Result<(), CommandError> {
    if platform_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Platform ID must not be empty.",
        ));
    }

    let guard = state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "Internal vault state lock was poisoned."))?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = LogoRepository::new(&vault.db);
            repo.assign_to_platform(&platform_id, logo_id.as_deref(), current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

// ─── Tauri command endpoints ──────────────────────────────────────────────────

/// `import_logo` command (api-contract.md §9).
#[tauri::command]
pub fn import_logo(
    state: State<'_, SharedVaultState>,
    name: String,
    mime_type: String,
    image_data: Vec<u8>,
) -> std::result::Result<Logo, CommandError> {
    import_logo_impl(&state, name, mime_type, image_data)
}

/// `list_logos` command (api-contract.md §9).
#[tauri::command]
pub fn list_logos(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<Vec<LogoSummary>, CommandError> {
    list_logos_impl(&state)
}

/// `get_logo` command (api-contract.md §9).
#[tauri::command]
pub fn get_logo(
    state: State<'_, SharedVaultState>,
    logo_id: String,
) -> std::result::Result<Logo, CommandError> {
    get_logo_impl(&state, logo_id)
}

/// `rename_logo` command (api-contract.md §9).
#[tauri::command]
pub fn rename_logo(
    state: State<'_, SharedVaultState>,
    logo_id: String,
    new_name: String,
) -> std::result::Result<Logo, CommandError> {
    rename_logo_impl(&state, logo_id, new_name)
}

/// `replace_logo` command (api-contract.md §9).
#[tauri::command]
pub fn replace_logo(
    state: State<'_, SharedVaultState>,
    logo_id: String,
    new_mime_type: String,
    new_image_data: Vec<u8>,
) -> std::result::Result<Logo, CommandError> {
    replace_logo_impl(&state, logo_id, new_mime_type, new_image_data)
}

/// `delete_logo` command (api-contract.md §9).
#[tauri::command]
pub fn delete_logo(
    state: State<'_, SharedVaultState>,
    logo_id: String,
) -> std::result::Result<(), CommandError> {
    delete_logo_impl(&state, logo_id)
}

/// `assign_logo` command (api-contract.md §9).
#[tauri::command]
pub fn assign_logo(
    state: State<'_, SharedVaultState>,
    platform_id: String,
    logo_id: Option<String>,
) -> std::result::Result<(), CommandError> {
    assign_logo_impl(&state, platform_id, logo_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    use crate::platforms::{CreatePlatformParams, PlatformRepository};
    use crate::vault::cbor::{VaultHeader, VaultHeaderParams};
    use crate::vault::operations::UnlockedVault;
    use crate::vault::sqlite::InMemoryDb;

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
    fn test_logo_commands_reject_when_locked() {
        let locked_state = SharedVaultState::new();

        let res = list_logos_impl(&locked_state);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = import_logo_impl(&locked_state, "name".into(), "image/png".into(), vec![]);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = get_logo_impl(&locked_state, "logo-id".into());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = rename_logo_impl(&locked_state, "logo-id".into(), "new".into());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = replace_logo_impl(&locked_state, "logo-id".into(), "image/png".into(), vec![]);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = delete_logo_impl(&locked_state, "logo-id".into());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");

        let res = assign_logo_impl(&locked_state, "plat-id".into(), None);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code, "VaultLocked");
    }

    #[test]
    fn test_logo_commands_full_flow() {
        let state = build_unlocked_shared_state();

        // 1. Create a platform
        let plat = {
            let guard = state.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let repo = PlatformRepository::new(&vault.db);
                repo.create(
                    CreatePlatformParams {
                        name: "Google".into(),
                        category: None,
                        website: None,
                        logo_id: None,
                    },
                    100,
                )
                .unwrap()
            } else {
                panic!("Vault not unlocked");
            }
        };

        // 2. Import logo
        let svg_data =
            br#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="50" height="50"/></svg>"#
                .to_vec();
        let imported = import_logo_impl(
            &state,
            "Google Logo".into(),
            "image/svg+xml".into(),
            svg_data,
        )
        .unwrap();

        assert_eq!(imported.name, "Google Logo");

        // 3. List logos
        let list = list_logos_impl(&state).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, imported.id);

        // 4. Get logo
        let fetched = get_logo_impl(&state, imported.id.clone()).unwrap();
        assert_eq!(fetched.id, imported.id);

        // 5. Assign to platform
        assign_logo_impl(&state, plat.id.clone(), Some(imported.id.clone())).unwrap();

        // Verify platform has logo_id
        {
            let guard = state.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let repo = PlatformRepository::new(&vault.db);
                let p = repo.get_by_id(&plat.id).unwrap();
                assert_eq!(p.logo_id, Some(imported.id.clone()));
            }
        }

        // 6. Rename logo
        let renamed =
            rename_logo_impl(&state, imported.id.clone(), "Google New Logo".into()).unwrap();
        assert_eq!(renamed.name, "Google New Logo");

        // 7. Replace logo content
        let new_png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02];
        let replaced =
            replace_logo_impl(&state, imported.id.clone(), "image/png".into(), new_png).unwrap();
        assert_eq!(replaced.mime_type, "image/png");

        // 8. Delete logo and check platform reference nullified
        delete_logo_impl(&state, imported.id.clone()).unwrap();

        {
            let guard = state.0.lock().unwrap();
            if let VaultState::Unlocked { vault, .. } = &*guard {
                let repo = PlatformRepository::new(&vault.db);
                let p = repo.get_by_id(&plat.id).unwrap();
                assert_eq!(p.logo_id, None);
            }
        }
    }
}
