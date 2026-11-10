#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ki_vault_lib::run();
}

#[cfg(all(test, feature = "test-helpers"))]
mod tauri_acl_tests {

    use ki_vault_lib::create_test_app;

    fn get_test_url() -> tauri::Url {
        if cfg!(any(windows, target_os = "android")) {
            "http://tauri.localhost".parse().unwrap()
        } else {
            "tauri://localhost".parse().unwrap()
        }
    }

    #[test]
    fn tauri_acl_rejects_ungranted_generate_password_on_main() {
        let (_app, main_window) = create_test_app();

        let res = tauri::test::get_ipc_response(
            &main_window,
            tauri::webview::InvokeRequest {
                cmd: "generate_password".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: get_test_url(),
                body: tauri::ipc::InvokeBody::Json(serde_json::json!({
                    "request": {
                        "length": 16,
                        "useUppercase": true,
                        "useLowercase": true,
                        "useNumbers": true,
                        "useSymbols": true
                    }
                })),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        );

        assert!(
            res.is_err(),
            "generate_password must be rejected by Tauri ACL for main window"
        );
        let err_val = res.unwrap_err();
        let err_str = serde_json::to_string(&err_val).unwrap_or_else(|_| format!("{:?}", err_val));
        assert!(
            err_str.to_lowercase().contains("not allowed")
                || err_str.to_lowercase().contains("denied"),
            "Expected ACL denial error message containing 'not allowed' or 'denied', got: {}",
            err_str
        );
    }

    #[test]
    fn tauri_acl_rejects_granted_command_from_unprivileged_window() {
        let (app, _main_window) = create_test_app();
        let unprivileged_window =
            tauri::WebviewWindowBuilder::new(&app, "acl-unprivileged", Default::default())
                .build()
                .expect("failed to create unprivileged window");

        let res = tauri::test::get_ipc_response(
            &unprivileged_window,
            tauri::webview::InvokeRequest {
                cmd: "get_vault_status".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: get_test_url(),
                body: tauri::ipc::InvokeBody::Json(serde_json::json!({})),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        );

        assert!(
            res.is_err(),
            "get_vault_status must be rejected by Tauri ACL for unprivileged window"
        );
        let err_val = res.unwrap_err();
        let err_str = serde_json::to_string(&err_val).unwrap_or_else(|_| format!("{:?}", err_val));
        assert!(
            err_str.to_lowercase().contains("not allowed")
                || err_str.to_lowercase().contains("denied"),
            "Expected ACL denial error message containing 'not allowed' or 'denied', got: {}",
            err_str
        );
    }

    #[test]
    fn tauri_acl_permits_granted_command_on_main() {
        let (_app, main_window) = create_test_app();

        let res = tauri::test::get_ipc_response(
            &main_window,
            tauri::webview::InvokeRequest {
                cmd: "get_vault_status".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: get_test_url(),
                body: tauri::ipc::InvokeBody::Json(serde_json::json!({})),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        );

        assert!(
            res.is_ok(),
            "get_vault_status must be permitted by Tauri ACL for main window; got error: {:?}",
            res.err()
        );
    }
}
