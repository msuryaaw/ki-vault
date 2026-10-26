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

// ─── Input length limits (api-contract.md §4, §5, §8) ─────────────────────────

pub const MAX_PLATFORM_NAME_LEN: usize = 256;
pub const MAX_CATEGORY_LEN: usize = 100;
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_ID_LEN: usize = 64;
pub const MAX_ACCOUNT_NAME_LEN: usize = 256;
pub const MAX_PASSWORD_LEN: usize = 1024;
pub const MAX_NOTES_LEN: usize = 10000;
pub const MAX_TAG_NAME_LEN: usize = 100;
pub const MAX_CUSTOM_FIELD_NAME_LEN: usize = 256;
pub const MAX_CUSTOM_FIELD_VALUE_LEN: usize = 4096;
pub const MAX_CUSTOM_FIELD_TYPE_LEN: usize = 50;

fn validate_string_bound(
    val: &str,
    field_name: &str,
    max_len: usize,
    disallow_empty: bool,
) -> std::result::Result<(), CommandError> {
    if disallow_empty && val.trim().is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            format!("{field_name} must not be empty."),
        ));
    }
    if val.len() > max_len {
        return Err(CommandError::new(
            "InvalidInput",
            format!("{field_name} exceeds maximum length of {max_len} bytes."),
        ));
    }
    Ok(())
}

fn validate_opt_string_bound(
    opt: Option<&str>,
    field_name: &str,
    max_len: usize,
) -> std::result::Result<(), CommandError> {
    if let Some(val) = opt {
        if val.len() > max_len {
            return Err(CommandError::new(
                "InvalidInput",
                format!("{field_name} exceeds maximum length of {max_len} bytes."),
            ));
        }
    }
    Ok(())
}

pub fn validate_create_platform_input(
    name: &str,
    category: Option<&str>,
    website: Option<&str>,
    logo_id: Option<&str>,
) -> std::result::Result<(), CommandError> {
    validate_string_bound(name, "Platform name", MAX_PLATFORM_NAME_LEN, true)?;
    validate_opt_string_bound(category, "Category", MAX_CATEGORY_LEN)?;
    validate_opt_string_bound(website, "Website", MAX_URL_LEN)?;
    validate_opt_string_bound(logo_id, "Logo ID", MAX_ID_LEN)?;
    Ok(())
}

pub fn validate_update_platform_input(
    platform_id: &str,
    params: &UpdatePlatformParams,
) -> std::result::Result<(), CommandError> {
    validate_string_bound(platform_id, "Platform ID", MAX_ID_LEN, true)?;
    if let Some(ref n) = params.name {
        validate_string_bound(n, "Platform name", MAX_PLATFORM_NAME_LEN, true)?;
    }
    if let Some(Some(ref cat)) = params.category {
        validate_string_bound(cat, "Category", MAX_CATEGORY_LEN, false)?;
    }
    if let Some(Some(ref web)) = params.website {
        validate_string_bound(web, "Website", MAX_URL_LEN, false)?;
    }
    if let Some(Some(ref logo)) = params.logo_id {
        validate_string_bound(logo, "Logo ID", MAX_ID_LEN, false)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_create_account_input(
    platform_id: &str,
    display_name: Option<&str>,
    username: Option<&str>,
    email: Option<&str>,
    password: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    logo_id: Option<&str>,
    tags: Option<&[String]>,
    custom_fields: Option<&[CreateCustomFieldParamsInput]>,
) -> std::result::Result<(), CommandError> {
    validate_string_bound(platform_id, "Platform ID", MAX_ID_LEN, true)?;
    validate_opt_string_bound(display_name, "Display name", MAX_ACCOUNT_NAME_LEN)?;
    validate_opt_string_bound(username, "Username", MAX_ACCOUNT_NAME_LEN)?;
    validate_opt_string_bound(email, "Email", MAX_ACCOUNT_NAME_LEN)?;
    validate_opt_string_bound(password, "Password", MAX_PASSWORD_LEN)?;
    validate_opt_string_bound(url, "URL", MAX_URL_LEN)?;
    validate_opt_string_bound(notes, "Notes", MAX_NOTES_LEN)?;
    validate_opt_string_bound(logo_id, "Logo ID", MAX_ID_LEN)?;

    if let Some(tags_list) = tags {
        for tag_id in tags_list {
            validate_string_bound(tag_id, "Tag ID", MAX_ID_LEN, true)?;
        }
    }

    if let Some(cfs) = custom_fields {
        for cf in cfs {
            validate_string_bound(
                &cf.field_name,
                "Custom field name",
                MAX_CUSTOM_FIELD_NAME_LEN,
                true,
            )?;
            validate_string_bound(
                &cf.field_value,
                "Custom field value",
                MAX_CUSTOM_FIELD_VALUE_LEN,
                false,
            )?;
            if let Some(ref ft) = cf.field_type {
                validate_string_bound(ft, "Custom field type", MAX_CUSTOM_FIELD_TYPE_LEN, false)?;
            }
        }
    }

    Ok(())
}

pub fn validate_update_account_input(
    account_id: &str,
    fields: &UpdateAccountParams,
) -> std::result::Result<(), CommandError> {
    validate_string_bound(account_id, "Account ID", MAX_ID_LEN, true)?;
    if let Some(ref pid) = fields.platform_id {
        validate_string_bound(pid, "Platform ID", MAX_ID_LEN, true)?;
    }
    if let Some(Some(ref dn)) = fields.display_name {
        validate_string_bound(dn, "Display name", MAX_ACCOUNT_NAME_LEN, false)?;
    }
    if let Some(Some(ref u)) = fields.username {
        validate_string_bound(u, "Username", MAX_ACCOUNT_NAME_LEN, false)?;
    }
    if let Some(Some(ref em)) = fields.email {
        validate_string_bound(em, "Email", MAX_ACCOUNT_NAME_LEN, false)?;
    }
    if let Some(Some(ref pw)) = fields.password {
        validate_string_bound(pw, "Password", MAX_PASSWORD_LEN, false)?;
    }
    if let Some(Some(ref url)) = fields.url {
        validate_string_bound(url, "URL", MAX_URL_LEN, false)?;
    }
    if let Some(Some(ref notes)) = fields.notes {
        validate_string_bound(notes, "Notes", MAX_NOTES_LEN, false)?;
    }
    if let Some(Some(ref logo)) = fields.logo_id {
        validate_string_bound(logo, "Logo ID", MAX_ID_LEN, false)?;
    }
    Ok(())
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
    validate_create_platform_input(
        &name,
        category.as_deref(),
        website.as_deref(),
        logo_id.as_deref(),
    )?;
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
    validate_string_bound(&platform_id, "Platform ID", MAX_ID_LEN, true)?;

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
    let params = UpdatePlatformParams {
        name,
        category,
        website,
        logo_id,
    };
    validate_update_platform_input(&platform_id, &params)?;

    let guard = lock_state(&state)?;
    match &*guard {
        VaultState::Unlocked { vault, .. } => {
            let repo = PlatformRepository::new(&vault.db);
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
    validate_string_bound(&platform_id, "Platform ID", MAX_ID_LEN, true)?;

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
    logo_id: Option<String>,
    favorite: bool,
    tags: Option<Vec<String>>,
    custom_fields: Option<Vec<CreateCustomFieldParamsInput>>,
) -> std::result::Result<AccountDetail, CommandError> {
    validate_create_account_input(
        &platform_id,
        display_name.as_deref(),
        username.as_deref(),
        email.as_deref(),
        password.as_deref(),
        url.as_deref(),
        notes.as_deref(),
        logo_id.as_deref(),
        tags.as_deref(),
        custom_fields.as_deref(),
    )?;

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
                logo_id,
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
    validate_opt_string_bound(platform_id.as_deref(), "Platform ID", MAX_ID_LEN)?;
    validate_opt_string_bound(tag_id.as_deref(), "Tag ID", MAX_ID_LEN)?;

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
    if let Some(ref f) = filters {
        validate_opt_string_bound(f.platform_id.as_deref(), "Platform ID", MAX_ID_LEN)?;
        validate_opt_string_bound(f.tag_id.as_deref(), "Tag ID", MAX_ID_LEN)?;
        validate_opt_string_bound(f.category.as_deref(), "Category", MAX_CATEGORY_LEN)?;
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
    validate_string_bound(&account_id, "Account ID", MAX_ID_LEN, true)?;

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
    validate_update_account_input(&account_id, &fields)?;

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
    validate_string_bound(&account_id, "Account ID", MAX_ID_LEN, true)?;

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
    validate_string_bound(&name, "Tag name", MAX_TAG_NAME_LEN, true)?;

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
    validate_string_bound(&tag_id, "Tag ID", MAX_ID_LEN, true)?;
    validate_string_bound(&name, "Tag name", MAX_TAG_NAME_LEN, true)?;

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
    validate_string_bound(&tag_id, "Tag ID", MAX_ID_LEN, true)?;

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
    validate_string_bound(&account_id, "Account ID", MAX_ID_LEN, true)?;
    validate_string_bound(&tag_id, "Tag ID", MAX_ID_LEN, true)?;

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
    validate_string_bound(&account_id, "Account ID", MAX_ID_LEN, true)?;
    validate_string_bound(&tag_id, "Tag ID", MAX_ID_LEN, true)?;

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
        validate_create_platform_input(
            &name,
            category.as_deref(),
            website.as_deref(),
            logo_id.as_deref(),
        )?;
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
        validate_string_bound(&platform_id, "Platform ID", MAX_ID_LEN, true)?;
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
        validate_string_bound(&name, "Tag name", MAX_TAG_NAME_LEN, true)?;
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
        validate_create_account_input(
            &platform_id,
            display_name.as_deref(),
            username.as_deref(),
            email.as_deref(),
            password.as_deref(),
            url.as_deref(),
            notes.as_deref(),
            None,
            tags.as_deref(),
            custom_fields.as_deref(),
        )?;
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
                        logo_id: None,
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

    #[test]
    fn test_platform_input_length_validation() {
        let shared = build_unlocked_shared_state();

        // 1. Empty platform name disallowed
        let err = create_platform_impl(&shared, "".into(), None, None, None).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Platform name must not be empty"));

        let err = create_platform_impl(&shared, "   ".into(), None, None, None).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Platform name must not be empty"));

        // 2. Exact maximum platform name (256 bytes) allowed
        let exact_name = "p".repeat(MAX_PLATFORM_NAME_LEN);
        let p = create_platform_impl(&shared, exact_name.clone(), None, None, None).unwrap();
        assert_eq!(p.name, exact_name);

        // 3. Exceeding platform name (257 bytes) disallowed
        let over_name = "p".repeat(MAX_PLATFORM_NAME_LEN + 1);
        let err = create_platform_impl(&shared, over_name, None, None, None).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Platform name exceeds maximum length"));

        // 4. Category boundary (100 bytes allowed, 101 bytes rejected)
        let exact_cat = "c".repeat(MAX_CATEGORY_LEN);
        let p2 = create_platform_impl(
            &shared,
            "ValidCatPlatform".into(),
            Some(exact_cat.clone()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(p2.category, Some(exact_cat));

        let over_cat = "c".repeat(MAX_CATEGORY_LEN + 1);
        let err = create_platform_impl(
            &shared,
            "OverCatPlatform".into(),
            Some(over_cat),
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Category exceeds maximum length"));

        // 5. Website URL boundary (2048 bytes allowed, 2049 bytes rejected)
        let exact_url = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN - 20));
        assert_eq!(exact_url.len(), MAX_URL_LEN);
        let p3 = create_platform_impl(
            &shared,
            "ValidUrlPlatform".into(),
            None,
            Some(exact_url.clone()),
            None,
        )
        .unwrap();
        assert_eq!(p3.website, Some(exact_url));

        let over_url = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN - 19));
        assert_eq!(over_url.len(), MAX_URL_LEN + 1);
        let err = create_platform_impl(
            &shared,
            "OverUrlPlatform".into(),
            None,
            Some(over_url),
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Website exceeds maximum length"));

        // 6. Platform ID bound on update
        let over_id = "i".repeat(MAX_ID_LEN + 1);
        let update_params = UpdatePlatformParams {
            name: Some("NewName".into()),
            category: None,
            website: None,
            logo_id: None,
        };
        let err = validate_update_platform_input(&over_id, &update_params).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Platform ID exceeds maximum length"));
    }

    #[test]
    fn test_account_and_custom_field_input_length_validation() {
        let shared = build_unlocked_shared_state();
        let p =
            create_platform_impl(&shared, "AccountTestPlatform".into(), None, None, None).unwrap();

        // 1. Empty platform ID disallowed
        let err = create_account_impl(
            &shared,
            "".into(),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Platform ID must not be empty"));

        // 2. Normal account creation allowed
        let acc = create_account_impl(
            &shared,
            p.id.clone(),
            Some("Personal".into()),
            Some("user1".into()),
            Some("user1@example.com".into()),
            Some("secret123".into()),
            Some("https://example.com".into()),
            Some("Some notes".into()),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(acc.account.username, Some("user1".into()));

        // 3. Username boundary (256 allowed, 257 rejected)
        let exact_user = "u".repeat(MAX_ACCOUNT_NAME_LEN);
        let acc_max = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            Some(exact_user.clone()),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(acc_max.account.username, Some(exact_user));

        let over_user = "u".repeat(MAX_ACCOUNT_NAME_LEN + 1);
        let err = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            Some(over_user),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Username exceeds maximum length"));

        // 4. Password boundary (1024 allowed, 1025 rejected)
        let exact_pw = "p".repeat(MAX_PASSWORD_LEN);
        let acc_pw = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            Some(exact_pw),
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(acc_pw.account.platform_id, p.id);

        let over_pw = "p".repeat(MAX_PASSWORD_LEN + 1);
        let err = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            Some(over_pw),
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Password exceeds maximum length"));

        // 5. Notes boundary (10000 allowed, 10001 rejected)
        let exact_notes = "n".repeat(MAX_NOTES_LEN);
        let acc_notes = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            None,
            None,
            Some(exact_notes),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(acc_notes.account.platform_id, p.id);

        let over_notes = "n".repeat(MAX_NOTES_LEN + 1);
        let err = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            None,
            None,
            Some(over_notes),
            false,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Notes exceeds maximum length"));

        // 6. Custom fields boundary (name <= 256, value <= 4096)
        let exact_cf_name = "k".repeat(MAX_CUSTOM_FIELD_NAME_LEN);
        let exact_cf_val = "v".repeat(MAX_CUSTOM_FIELD_VALUE_LEN);
        let acc_cf = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(vec![CreateCustomFieldParamsInput {
                field_name: exact_cf_name,
                field_value: exact_cf_val,
                field_type: Some("text".into()),
                is_sensitive: Some(false),
            }]),
        )
        .unwrap();
        assert_eq!(acc_cf.custom_fields.len(), 1);

        // Custom field empty name disallowed
        let err = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(vec![CreateCustomFieldParamsInput {
                field_name: "  ".into(),
                field_value: "val".into(),
                field_type: None,
                is_sensitive: None,
            }]),
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Custom field name must not be empty"));

        // Custom field exceeding value disallowed
        let over_cf_val = "v".repeat(MAX_CUSTOM_FIELD_VALUE_LEN + 1);
        let err = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            Some(vec![CreateCustomFieldParamsInput {
                field_name: "valid_name".into(),
                field_value: over_cf_val,
                field_type: None,
                is_sensitive: None,
            }]),
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err
            .message
            .contains("Custom field value exceeds maximum length"));
    }

    #[test]
    fn test_tag_input_length_validation() {
        let shared = build_unlocked_shared_state();

        // 1. Empty tag name disallowed
        let err = create_tag_impl(&shared, "".into()).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Tag name must not be empty"));

        let err = create_tag_impl(&shared, "   ".into()).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Tag name must not be empty"));

        // 2. Exact maximum tag name (100 bytes) allowed
        let exact_tag = "t".repeat(MAX_TAG_NAME_LEN);
        let tag = create_tag_impl(&shared, exact_tag.clone()).unwrap();
        assert_eq!(tag.name, exact_tag);

        // 3. Exceeding tag name (101 bytes) disallowed
        let over_tag = "t".repeat(MAX_TAG_NAME_LEN + 1);
        let err = create_tag_impl(&shared, over_tag).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("Tag name exceeds maximum length"));
    }

    #[test]
    fn test_unicode_multibyte_input_length_validation() {
        let shared = build_unlocked_shared_state();

        // 1. Tag name with 3-byte CJK character '日' (U+65E5 = 3 bytes in UTF-8)
        // 33 characters * 3 bytes = 99 bytes (allowed: <= 100 bytes)
        let exact_under_tag = "日".repeat(33);
        assert_eq!(exact_under_tag.chars().count(), 33);
        assert_eq!(exact_under_tag.len(), 99);
        let tag = create_tag_impl(&shared, exact_under_tag.clone()).unwrap();
        assert_eq!(tag.name, exact_under_tag);

        // 34 characters is only 34 graphemes/chars, but 34 * 3 = 102 bytes (> 100 bytes)
        let over_tag = "日".repeat(34);
        assert_eq!(over_tag.chars().count(), 34);
        assert_eq!(over_tag.len(), 102);
        let err = create_tag_impl(&shared, over_tag).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err
            .message
            .contains("Tag name exceeds maximum length of 100 bytes"));

        // 99 bytes of '日' (33 chars) + 1 byte ASCII 'a' = exact 100 bytes (allowed)
        let exact_100_tag = format!("{}a", "日".repeat(33));
        assert_eq!(exact_100_tag.len(), MAX_TAG_NAME_LEN);
        let tag_100 = create_tag_impl(&shared, exact_100_tag.clone()).unwrap();
        assert_eq!(tag_100.name, exact_100_tag);

        // 2. Platform name with 4-byte Emoji '🔒' (U+1F512 = 4 bytes in UTF-8)
        // 64 emojis = only 64 characters, but 64 * 4 = 256 bytes (exact maximum: allowed)
        let exact_256_platform = "🔒".repeat(64);
        assert_eq!(exact_256_platform.chars().count(), 64);
        assert_eq!(exact_256_platform.len(), MAX_PLATFORM_NAME_LEN);
        let p =
            create_platform_impl(&shared, exact_256_platform.clone(), None, None, None).unwrap();
        assert_eq!(p.name, exact_256_platform);

        // 65 emojis = only 65 characters, but 65 * 4 = 260 bytes (> 256 bytes: rejected)
        let over_256_platform = "🔒".repeat(65);
        assert_eq!(over_256_platform.chars().count(), 65);
        assert_eq!(over_256_platform.len(), 260);
        let err = create_platform_impl(&shared, over_256_platform, None, None, None).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err
            .message
            .contains("Platform name exceeds maximum length of 256 bytes"));

        // 3. Account username with 2-byte Cyrillic 'д' (U+0434 = 2 bytes in UTF-8)
        // 128 chars * 2 = 256 bytes (exact maximum: allowed)
        let exact_256_user = "д".repeat(128);
        assert_eq!(exact_256_user.chars().count(), 128);
        assert_eq!(exact_256_user.len(), MAX_ACCOUNT_NAME_LEN);
        let acc = create_account_impl(
            &shared,
            p.id.clone(),
            None,
            Some(exact_256_user.clone()),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(acc.account.username, Some(exact_256_user));

        // 129 chars = 258 bytes (> 256 bytes: rejected)
        let over_256_user = "д".repeat(129);
        assert_eq!(over_256_user.chars().count(), 129);
        assert_eq!(over_256_user.len(), 258);
        let err = create_account_impl(
            &shared,
            p.id,
            None,
            Some(over_256_user),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err
            .message
            .contains("Username exceeds maximum length of 256 bytes"));
    }
}
