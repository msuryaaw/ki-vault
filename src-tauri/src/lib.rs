pub mod accounts;
pub mod auth;
pub mod backup;
pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod custom_fields;
pub mod database;
pub mod errors;
pub mod logos;
pub mod platforms;
pub mod security;
pub mod settings;
pub mod tags;
pub mod vault;

use commands::backup::{create_backup, restore_backup};
use commands::domain::{
    assign_tag, create_account, create_platform, create_tag, delete_account, delete_platform,
    delete_tag, get_account_detail, get_platform, list_accounts, list_platforms, list_tags,
    remove_tag, rename_tag, search_accounts, update_account, update_platform,
};
use commands::logos::{
    assign_logo, delete_logo, get_logo, import_logo, list_logos, rename_logo, replace_logo,
};
use commands::password::generate_password;
use commands::secrets::{copy_secret, reveal_secret};
use commands::security::{get_password_health, get_security_status, notify_activity};
use commands::settings::{
    get_settings, update_password_generator_settings, update_security_settings,
};
use commands::vault::{
    change_master_password, create_vault, get_vault_status, get_vault_summary, lock_vault,
    unlock_vault, SharedAutoLock, SharedVaultState,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(SharedAutoLock::new())
        .manage(SharedVaultState::new())
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault,
            lock_vault,
            get_vault_status,
            get_vault_summary,
            change_master_password,
            create_platform,
            list_platforms,
            get_platform,
            update_platform,
            delete_platform,
            create_account,
            list_accounts,
            search_accounts,
            get_account_detail,
            update_account,
            delete_account,
            create_tag,
            list_tags,
            rename_tag,
            delete_tag,
            assign_tag,
            remove_tag,
            reveal_secret,
            copy_secret,
            generate_password,
            get_settings,
            update_security_settings,
            update_password_generator_settings,
            get_security_status,
            get_password_health,
            notify_activity,
            import_logo,
            list_logos,
            get_logo,
            rename_logo,
            replace_logo,
            delete_logo,
            assign_logo,
            create_backup,
            restore_backup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
