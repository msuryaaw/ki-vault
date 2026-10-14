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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
