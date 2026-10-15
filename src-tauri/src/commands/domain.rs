//! Domain CRUD Tauri Commands
//!
//! Implements typed Tauri commands for platforms, accounts, and tags
//! according to `docs/api-contract.md` (§4, §5, §8).
//!
//! # Security Properties
//! - All commands enforce that the single active vault is unlocked.
//!   If locked or uninitialised, commands fail-closed with `VaultLocked`.
//! - Secrets, raw keys, and master passwords are never logged or exposed.
//! - Parameter validation occurs in Rust before any database operations.
//! - All operations operate strictly against the in-memory SQLite database.

use tauri::State;

use crate::accounts::{
    Account, AccountDetail, AccountRepository, AccountSummary, CreateAccountParams,
    CreateCustomFieldParamsInput, ListAccountsFilter, SearchFilters, SortOrder,
    UpdateAccountParams,
};
use crate::commands::vault::{lock_state, map_error, CommandError, SharedVaultState, VaultState};
use crate::platforms::{
    CreatePlatformParams, Platform, PlatformRepository, PlatformSummary, UpdatePlatformParams,
};
use crate::tags::{Tag, TagRepository};

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ─── Platform Commands (api-contract.md §4) ───────────────────────────────────

/// `create_platform` command (api-contract.md §4).
#[tauri::command]
pub fn create_platform(
    state: State<'_, SharedVaultState>,
    name: String,
    category: Option<String>,
    website: Option<String>,
    logo_id: Option<String>,
) -> std::result::Result<Platform, CommandError> {
    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
            let params = CreatePlatformParams {
                name,
                category,
                website,
                logo_id,
            };
            repo.create(params, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `list_platforms` command (api-contract.md §4).
#[tauri::command]
pub fn list_platforms(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<Vec<PlatformSummary>, CommandError> {
    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
            repo.list().map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `get_platform` command (api-contract.md §4).
#[tauri::command]
pub fn get_platform(
    state: State<'_, SharedVaultState>,
    platform_id: String,
) -> std::result::Result<Platform, CommandError> {
    if platform_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Platform ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
            repo.get_by_id(&platform_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `update_platform` command (api-contract.md §4).
#[tauri::command]
pub fn update_platform(
    state: State<'_, SharedVaultState>,
    platform_id: String,
    name: Option<String>,
    category: Option<Option<String>>,
    website: Option<Option<String>>,
    logo_id: Option<Option<String>>,
) -> std::result::Result<Platform, CommandError> {
    if platform_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Platform ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
            let params = UpdatePlatformParams {
                name,
                category,
                website,
                logo_id,
            };
            repo.update(&platform_id, params, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `delete_platform` command (api-contract.md §4).
///
/// Must explicitly confirm cascading account deletion via `confirmation_token == platform_id`.
#[tauri::command]
pub fn delete_platform(
    state: State<'_, SharedVaultState>,
    platform_id: String,
    confirmation_token: String,
) -> std::result::Result<(), CommandError> {
    if platform_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Platform ID must not be empty.",
        ));
    }

    if confirmation_token != platform_id {
        return Err(CommandError::new(
            "InvalidInput",
            "Confirmation token does not match the platform ID for cascading deletion.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
            repo.delete(&platform_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

// ─── Account Commands (api-contract.md §5) ────────────────────────────────────

/// `create_account` command (api-contract.md §5).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn create_account(
    state: State<'_, SharedVaultState>,
    platform_id: String,
    display_name: Option<String>,
    username: Option<String>,
    email: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    favorite: bool,
    tags: Option<Vec<String>>,
    custom_fields: Option<Vec<CreateCustomFieldParamsInput>>,
) -> std::result::Result<AccountDetail, CommandError> {
    if platform_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Platform ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            let params = CreateAccountParams {
                platform_id,
                display_name,
                username,
                email,
                password,
                url,
                notes,
                is_favorite: favorite,
                tag_ids: tags.unwrap_or_default(),
                custom_fields: custom_fields.unwrap_or_default(),
            };
            repo.create(params, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `list_accounts` command (api-contract.md §5).
#[tauri::command]
pub fn list_accounts(
    state: State<'_, SharedVaultState>,
    platform_id: Option<String>,
    favorite_only: Option<bool>,
    tag_id: Option<String>,
) -> std::result::Result<Vec<AccountSummary>, CommandError> {
    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            let filter = ListAccountsFilter {
                platform_id,
                favorite_only: favorite_only.unwrap_or(false),
                tag_id,
            };
            repo.list(filter).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `search_accounts` command (api-contract.md §5).
#[tauri::command]
pub fn search_accounts(
    state: State<'_, SharedVaultState>,
    query: String,
    filters: Option<SearchFilters>,
    sort: Option<SortOrder>,
) -> std::result::Result<Vec<AccountSummary>, CommandError> {
    if query.len() > 1024 {
        return Err(CommandError::new(
            "InvalidInput",
            "Search query cannot exceed 1024 characters.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            repo.search(&query, filters, sort).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `get_account_detail` command (api-contract.md §5).
#[tauri::command]
pub fn get_account_detail(
    state: State<'_, SharedVaultState>,
    account_id: String,
) -> std::result::Result<AccountDetail, CommandError> {
    if account_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            repo.get_detail(&account_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `update_account` command (api-contract.md §5).
#[tauri::command]
pub fn update_account(
    state: State<'_, SharedVaultState>,
    account_id: String,
    fields: UpdateAccountParams,
) -> std::result::Result<Account, CommandError> {
    if account_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            repo.update(&account_id, fields, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `delete_account` command (api-contract.md §5).
#[tauri::command]
pub fn delete_account(
    state: State<'_, SharedVaultState>,
    account_id: String,
) -> std::result::Result<(), CommandError> {
    if account_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = AccountRepository::new(&vault.db);
            repo.delete(&account_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

// ─── Tag Commands (api-contract.md §8) ────────────────────────────────────────

/// `create_tag` command (api-contract.md §8).
#[tauri::command]
pub fn create_tag(
    state: State<'_, SharedVaultState>,
    name: String,
) -> std::result::Result<Tag, CommandError> {
    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.create(&name, current_unix_timestamp())
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `list_tags` command (api-contract.md §8).
#[tauri::command]
pub fn list_tags(
    state: State<'_, SharedVaultState>,
) -> std::result::Result<Vec<Tag>, CommandError> {
    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.list().map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `rename_tag` command (api-contract.md §8).
#[tauri::command]
pub fn rename_tag(
    state: State<'_, SharedVaultState>,
    tag_id: String,
    name: String,
) -> std::result::Result<Tag, CommandError> {
    if tag_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Tag ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.rename(&tag_id, &name).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `delete_tag` command (api-contract.md §8).
#[tauri::command]
pub fn delete_tag(
    state: State<'_, SharedVaultState>,
    tag_id: String,
) -> std::result::Result<(), CommandError> {
    if tag_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Tag ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.delete(&tag_id).map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `assign_tag` command (api-contract.md §8).
#[tauri::command]
pub fn assign_tag(
    state: State<'_, SharedVaultState>,
    account_id: String,
    tag_id: String,
) -> std::result::Result<(), CommandError> {
    if account_id.trim().is_empty() || tag_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID and Tag ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.assign_to_account(&account_id, &tag_id)
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

/// `remove_tag` command (api-contract.md §8).
#[tauri::command]
pub fn remove_tag(
    state: State<'_, SharedVaultState>,
    account_id: String,
    tag_id: String,
) -> std::result::Result<(), CommandError> {
    if account_id.trim().is_empty() || tag_id.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "Account ID and Tag ID must not be empty.",
        ));
    }

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = TagRepository::new(&vault.db);
            repo.remove_from_account(&account_id, &tag_id)
                .map_err(map_error)
        }
        _ => Err(CommandError::new(
            "VaultLocked",
            "The vault must be unlocked to perform this operation.",
        )),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::operations::UnlockedVault;
    use crate::vault::sqlite::InMemoryDb;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    fn build_unlocked_shared_state() -> SharedVaultState {
        let db = InMemoryDb::create_empty().unwrap();
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
        shared
    }

    #[test]
    fn test_domain_commands_reject_when_locked() {
        let shared = SharedVaultState::new(); // Uninitialised/Locked

        let err = create_platform_impl(&shared, "GitHub".into(), None, None, None).unwrap_err();
        assert_eq!(err.code, "VaultLocked");

        let err = list_platforms_impl(&shared).unwrap_err();
        assert_eq!(err.code, "VaultLocked");

        let err = create_tag_impl(&shared, "Dev".into()).unwrap_err();
        assert_eq!(err.code, "VaultLocked");
    }

    #[test]
    fn test_platform_and_account_crud_lifecycle() {
        let shared = build_unlocked_shared_state();

        // 1. Create Platform
        let p = create_platform_impl(
            &shared,
            "GitHub".into(),
            Some("Development".into()),
            Some("https://github.com".into()),
            None,
        )
        .unwrap();
        assert_eq!(p.name, "GitHub");

        // 2. List Platforms
        let list = list_platforms_impl(&shared).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "GitHub");
        assert_eq!(list[0].account_count, 0);

        // 3. Create Tag
        let tag = create_tag_impl(&shared, "Work".into()).unwrap();
        assert_eq!(tag.name, "Work");

        // 4. Create Account
        let acc_detail = create_account_impl(
            &shared,
            p.id.clone(),
            Some("Work GitHub".into()),
            Some("octocat".into()),
            Some("octo@github.com".into()),
            Some("super-pass".into()),
            None,
            None,
            true,
            Some(vec![tag.id.clone()]),
            Some(vec![CreateCustomFieldParamsInput {
                field_name: "API Key".into(),
                field_value: "ghp_123456".into(),
                field_type: Some("secret".into()),
                is_sensitive: Some(true),
            }]),
        )
        .unwrap();

        assert_eq!(acc_detail.account.username, Some("octocat".into()));
        assert_eq!(acc_detail.tags.len(), 1);
        assert_eq!(acc_detail.custom_fields.len(), 1);

        // 5. Get Account Detail
        let fetched_detail =
            get_account_detail_impl(&shared, acc_detail.account.id.clone()).unwrap();
        assert_eq!(fetched_detail.account.id, acc_detail.account.id);
        assert_eq!(fetched_detail.tags[0].name, "Work");

        // Verify password is not serialized in JSON payload returned to frontend
        let serialized_json = serde_json::to_string(&fetched_detail).unwrap();
        assert!(
            !serialized_json.contains("super-pass"),
            "Password must never appear in frontend response JSON"
        );
        assert!(
            !serialized_json.contains("\"password\""),
            "Password field must be omitted from frontend response JSON"
        );

        // 6. Delete Platform requires valid confirmation token
        let err = delete_platform_impl(&shared, p.id.clone(), "wrong_token".into()).unwrap_err();
        assert_eq!(err.code, "InvalidInput");

        // Valid confirmation token successfully deletes platform & cascades to accounts
        delete_platform_impl(&shared, p.id.clone(), p.id.clone()).unwrap();

        let list_after = list_platforms_impl(&shared).unwrap();
        assert_eq!(list_after.len(), 0);

        let acc_err = get_account_detail_impl(&shared, acc_detail.account.id).unwrap_err();
        assert_eq!(acc_err.code, "NotFound");
    }

    // Direct helpers to execute command logic against SharedVaultState in tests
    fn create_platform_impl(
        shared: &SharedVaultState,
        name: String,
        category: Option<String>,
        website: Option<String>,
        logo_id: Option<String>,
    ) -> std::result::Result<Platform, CommandError> {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = PlatformRepository::new(&vault.db);
                repo.create(
                    CreatePlatformParams {
                        name,
                        category,
                        website,
                        logo_id,
                    },
                    current_unix_timestamp(),
                )
                .map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    fn list_platforms_impl(
        shared: &SharedVaultState,
    ) -> std::result::Result<Vec<PlatformSummary>, CommandError> {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = PlatformRepository::new(&vault.db);
                repo.list().map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    fn delete_platform_impl(
        shared: &SharedVaultState,
        platform_id: String,
        confirmation_token: String,
    ) -> std::result::Result<(), CommandError> {
        if confirmation_token != platform_id {
            return Err(CommandError::new("InvalidInput", "Token mismatch"));
        }
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = PlatformRepository::new(&vault.db);
                repo.delete(&platform_id).map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    fn create_tag_impl(
        shared: &SharedVaultState,
        name: String,
    ) -> std::result::Result<Tag, CommandError> {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = TagRepository::new(&vault.db);
                repo.create(&name, current_unix_timestamp())
                    .map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_account_impl(
        shared: &SharedVaultState,
        platform_id: String,
        display_name: Option<String>,
        username: Option<String>,
        email: Option<String>,
        password: Option<String>,
        url: Option<String>,
        notes: Option<String>,
        favorite: bool,
        tags: Option<Vec<String>>,
        custom_fields: Option<Vec<CreateCustomFieldParamsInput>>,
    ) -> std::result::Result<AccountDetail, CommandError> {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = AccountRepository::new(&vault.db);
                repo.create(
                    CreateAccountParams {
                        platform_id,
                        display_name,
                        username,
                        email,
                        password,
                        url,
                        notes,
                        is_favorite: favorite,
                        tag_ids: tags.unwrap_or_default(),
                        custom_fields: custom_fields.unwrap_or_default(),
                    },
                    current_unix_timestamp(),
                )
                .map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    fn get_account_detail_impl(
        shared: &SharedVaultState,
        account_id: String,
    ) -> std::result::Result<AccountDetail, CommandError> {
        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = AccountRepository::new(&vault.db);
                repo.get_detail(&account_id).map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    fn search_accounts_impl(
        shared: &SharedVaultState,
        query: String,
        filters: Option<SearchFilters>,
        sort: Option<SortOrder>,
    ) -> std::result::Result<Vec<AccountSummary>, CommandError> {
        if query.len() > 1024 {
            return Err(CommandError::new(
                "InvalidInput",
                "Search query cannot exceed 1024 characters.",
            ));
        }

        let guard = shared.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let repo = AccountRepository::new(&vault.db);
                repo.search(&query, filters, sort).map_err(map_error)
            }
            _ => Err(CommandError::new("VaultLocked", "Vault locked.")),
        }
    }

    #[test]
    fn test_search_accounts_command_locked_rejection_and_query_validation() {
        let shared = SharedVaultState::new();

        // 1. Rejects when locked
        let err = search_accounts_impl(&shared, "test".into(), None, None).unwrap_err();
        assert_eq!(err.code, "VaultLocked");

        // 2. Query exceeding maximum length rejected with InvalidInput
        let long_query = "a".repeat(1025);
        let err = search_accounts_impl(&shared, long_query, None, None).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("cannot exceed 1024"));
    }
}
