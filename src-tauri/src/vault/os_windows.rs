//! Windows-specific OS Idle, Suspend & Session Event Awareness
//!
//! Subclasses the main window to intercept:
//! - `WM_POWERBROADCAST`: `PBT_APMSUSPEND`, `PBT_APMRESUMEAUTOMATIC`, `PBT_APMRESUMESUSPEND`
//! - `WM_WTSSESSION_CHANGE`: `WTS_SESSION_LOCK`, `WTS_SESSION_UNLOCK`
//!
//! Also provides session idle detection using `GetLastInputInfo`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};
use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::Power::{
    RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification, HPOWERNOTIFY,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_WINDOW_HANDLE, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    WM_DESTROY, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
};

use crate::commands::vault::SharedVaultState;
use crate::vault::autolock::{execute_manual_lock, SharedAutoLock};

const KIVAULT_SUBCLASS_ID: usize = 0x4B49_564C; // "KIVL"

/// Context passed to the window subclass procedure.
struct SubclassData {
    auto_lock: SharedAutoLock,
    vault_state: SharedVaultState,
    power_notify: HPOWERNOTIFY,
    wts_registered: bool,
    active: Arc<AtomicBool>,
}

/// Classifies incoming OS messages into domain lifecycle actions.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OsLifecycleEvent {
    Suspend,
    Resume,
    SessionLock,
    SessionUnlock,
    Ignored,
}

/// Maps Win32 message identifiers and wParam parameters to an `OsLifecycleEvent`.
pub fn classify_os_message(msg: u32, wparam: usize) -> OsLifecycleEvent {
    match msg {
        WM_POWERBROADCAST => match wparam as u32 {
            PBT_APMSUSPEND => OsLifecycleEvent::Suspend,
            PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => OsLifecycleEvent::Resume,
            _ => OsLifecycleEvent::Ignored,
        },
        WM_WTSSESSION_CHANGE => match wparam as u32 {
            WTS_SESSION_LOCK => OsLifecycleEvent::SessionLock,
            WTS_SESSION_UNLOCK => OsLifecycleEvent::SessionUnlock,
            _ => OsLifecycleEvent::Ignored,
        },
        _ => OsLifecycleEvent::Ignored,
    }
}

/// Safely handles an `OsLifecycleEvent` by invoking KiVault's transactional lock path.
///
/// Returns `true` if an actual lock transition was attempted.
pub fn handle_os_lifecycle_event(
    event: OsLifecycleEvent,
    auto_lock: &SharedAutoLock,
    vault_state: &SharedVaultState,
) -> bool {
    match event {
        OsLifecycleEvent::Suspend | OsLifecycleEvent::SessionLock | OsLifecycleEvent::Resume => {
            // Idempotent: If already locked, execute_manual_lock safely returns an error (VaultLocked),
            // which we discard without altering state or corrupting memory.
            let _ = execute_manual_lock(auto_lock, vault_state);
            true
        }
        OsLifecycleEvent::SessionUnlock | OsLifecycleEvent::Ignored => {
            // Never automatically unlock or update activity.
            false
        }
    }
}

/// Computes the system-wide idle duration from `GetLastInputInfo`.
///
/// Uses `GetTickCount64()` to completely prevent 32-bit tick-count wraparound (49.7 day limit).
///
/// Returns `Some(Duration)` if `GetLastInputInfo` succeeded, or `None` if it failed.
pub fn get_windows_system_idle() -> Option<Duration> {
    unsafe {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };

        if GetLastInputInfo(&mut lii) == 0 {
            return None;
        }

        let now_tick = GetTickCount64();
        // dwTime is a 32-bit millisecond tick count. We cast both to u32 to handle arithmetic delta safely.
        let elapsed_millis = (now_tick as u32).wrapping_sub(lii.dwTime);
        Some(Duration::from_millis(elapsed_millis as u64))
    }
}

/// Subclass window procedure for handling power and session notifications.
unsafe extern "system" fn kivault_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    uid_subclass: usize,
    ref_data: usize,
) -> LRESULT {
    let data_ptr = ref_data as *mut SubclassData;

    if msg == WM_DESTROY {
        if !data_ptr.is_null() {
            let data = Box::from_raw(data_ptr);
            data.active.store(false, Ordering::SeqCst);
            if data.power_notify != 0 {
                UnregisterSuspendResumeNotification(data.power_notify);
            }
            if data.wts_registered {
                WTSUnRegisterSessionNotification(hwnd);
            }
        }

        RemoveWindowSubclass(hwnd, Some(kivault_subclass_proc), uid_subclass);
        return DefSubclassProc(hwnd, msg, wparam, lparam);
    }

    if !data_ptr.is_null() {
        let data = &*data_ptr;
        let event = classify_os_message(msg, wparam);
        if event != OsLifecycleEvent::Ignored {
            handle_os_lifecycle_event(event, &data.auto_lock, &data.vault_state);
        }
    }

    DefSubclassProc(hwnd, msg, wparam, lparam)
}

/// Installs OS lifecycle event listeners on the specified HWND.
///
/// Subclasses the window to intercept `WM_POWERBROADCAST` and `WM_WTSSESSION_CHANGE`.
///
/// # Safety
/// The caller must ensure `hwnd` is a valid Windows window handle.
pub unsafe fn setup_windows_lifecycle_listener(
    hwnd: HWND,
    auto_lock: SharedAutoLock,
    vault_state: SharedVaultState,
) -> bool {
    // Register for power suspend/resume notifications
    let power_notify =
        RegisterSuspendResumeNotification(hwnd as HANDLE, DEVICE_NOTIFY_WINDOW_HANDLE);

    // Register for session lock/unlock notifications (current session only)
    let wts_ok = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);

    let data = Box::new(SubclassData {
        auto_lock,
        vault_state,
        power_notify,
        wts_registered: wts_ok != 0,
        active: Arc::new(AtomicBool::new(true)),
    });

    let success = SetWindowSubclass(
        hwnd,
        Some(kivault_subclass_proc),
        KIVAULT_SUBCLASS_ID,
        Box::into_raw(data) as usize,
    );

    success != 0
}

/// Integrates the OS event listener with the Tauri application during `setup`.
pub fn init_windows_lifecycle<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(hwnd) = window.hwnd() {
            let auto_lock = app.state::<SharedAutoLock>().inner().clone();
            let vault_state = app.state::<SharedVaultState>().inner().clone();
            unsafe {
                setup_windows_lifecycle_listener(hwnd.0 as HWND, auto_lock, vault_state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vault::VaultState;
    use crate::vault::autolock::{
        evaluate_auto_lock_tick_with_idle, setup_unlocked_vault, AutoLockTickResult, MockClock,
        TempVault,
    };
    use std::path::PathBuf;
    use std::time::Instant;

    struct TestEnvironment {
        auto_lock: SharedAutoLock,
        vault_state: SharedVaultState,
        _temp: TempVault,
    }

    impl TestEnvironment {
        fn new() -> Self {
            let temp = TempVault::new();
            let (auto_lock, vault_state, _) = setup_unlocked_vault(&temp.path);
            Self {
                auto_lock,
                vault_state,
                _temp: temp,
            }
        }
    }

    #[test]
    fn test_event_classification_mappings() {
        assert_eq!(
            classify_os_message(WM_POWERBROADCAST, PBT_APMSUSPEND as usize),
            OsLifecycleEvent::Suspend
        );
        assert_eq!(
            classify_os_message(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize),
            OsLifecycleEvent::Resume
        );
        assert_eq!(
            classify_os_message(WM_POWERBROADCAST, PBT_APMRESUMESUSPEND as usize),
            OsLifecycleEvent::Resume
        );
        assert_eq!(
            classify_os_message(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize),
            OsLifecycleEvent::SessionLock
        );
        assert_eq!(
            classify_os_message(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK as usize),
            OsLifecycleEvent::SessionUnlock
        );
        assert_eq!(
            classify_os_message(WM_POWERBROADCAST, 0xFFFF),
            OsLifecycleEvent::Ignored
        );
        assert_eq!(classify_os_message(0x1234, 0), OsLifecycleEvent::Ignored);
    }

    #[test]
    fn test_unlocked_vault_locks_on_suspend() {
        let env = TestEnvironment::new();

        {
            let al = env.auto_lock.0.lock().unwrap();
            assert!(!al.is_locked);
        }

        let handled =
            handle_os_lifecycle_event(OsLifecycleEvent::Suspend, &env.auto_lock, &env.vault_state);
        assert!(handled);

        let al = env.auto_lock.0.lock().unwrap();
        assert!(al.is_locked);
        let vs = env.vault_state.0.lock().unwrap();
        assert!(matches!(*vs, VaultState::Locked { .. }));
    }

    #[test]
    fn test_unlocked_vault_locks_on_workstation_lock() {
        let env = TestEnvironment::new();

        let handled = handle_os_lifecycle_event(
            OsLifecycleEvent::SessionLock,
            &env.auto_lock,
            &env.vault_state,
        );
        assert!(handled);

        let al = env.auto_lock.0.lock().unwrap();
        assert!(al.is_locked);
    }

    #[test]
    fn test_locked_vault_idempotency_on_repeated_and_resume_events() {
        let env = TestEnvironment::new();

        // Lock on suspend
        handle_os_lifecycle_event(OsLifecycleEvent::Suspend, &env.auto_lock, &env.vault_state);
        let gen_after_first = env.auto_lock.0.lock().unwrap().generation;

        // Duplicate suspend
        handle_os_lifecycle_event(OsLifecycleEvent::Suspend, &env.auto_lock, &env.vault_state);
        assert_eq!(env.auto_lock.0.lock().unwrap().generation, gen_after_first);

        // Resume event must ensure vault remains locked and never unlock
        handle_os_lifecycle_event(OsLifecycleEvent::Resume, &env.auto_lock, &env.vault_state);
        let al = env.auto_lock.0.lock().unwrap();
        assert!(al.is_locked);
        assert_eq!(al.generation, gen_after_first);
    }

    #[test]
    fn test_workstation_unlock_never_triggers_automatic_unlock() {
        let env = TestEnvironment::new();

        handle_os_lifecycle_event(
            OsLifecycleEvent::SessionLock,
            &env.auto_lock,
            &env.vault_state,
        );
        assert!(env.auto_lock.0.lock().unwrap().is_locked);

        // Workstation unlock event arrives
        let handled = handle_os_lifecycle_event(
            OsLifecycleEvent::SessionUnlock,
            &env.auto_lock,
            &env.vault_state,
        );
        assert!(!handled);

        // Vault MUST remain locked
        let al = env.auto_lock.0.lock().unwrap();
        assert!(al.is_locked);
        let vs = env.vault_state.0.lock().unwrap();
        assert!(matches!(*vs, VaultState::Locked { .. }));
    }

    #[test]
    fn test_os_events_do_not_refresh_last_activity() {
        let env = TestEnvironment::new();

        let old_activity = Instant::now() - Duration::from_secs(120);
        {
            let mut al = env.auto_lock.0.lock().unwrap();
            al.last_activity = old_activity;
        }

        // Send unlock event which should be ignored
        handle_os_lifecycle_event(
            OsLifecycleEvent::SessionUnlock,
            &env.auto_lock,
            &env.vault_state,
        );
        let current_activity = env.auto_lock.0.lock().unwrap().last_activity;
        assert_eq!(current_activity, old_activity);
    }

    #[test]
    fn test_windows_idle_below_threshold_does_not_lock() {
        let env = TestEnvironment::new();

        let clock = MockClock::new();
        let gen = env.auto_lock.0.lock().unwrap().generation;

        // Effective timeout is 5m (300s). Inactivity is 60s, OS idle is 100s.
        clock.advance(Duration::from_secs(60));
        let res = evaluate_auto_lock_tick_with_idle(
            &env.auto_lock,
            &env.vault_state,
            &clock,
            gen,
            || Some(Duration::from_secs(100)),
        );

        assert_eq!(res, AutoLockTickResult::NotExpired);
        assert!(!env.auto_lock.0.lock().unwrap().is_locked);
    }

    #[test]
    fn test_windows_idle_at_or_above_threshold_triggers_lock() {
        let env = TestEnvironment::new();

        let clock = MockClock::new();
        let gen = env.auto_lock.0.lock().unwrap().generation;

        // Effective timeout is 300s. Inactivity within app is only 30s, but system OS idle is 305s!
        clock.advance(Duration::from_secs(30));
        let res = evaluate_auto_lock_tick_with_idle(
            &env.auto_lock,
            &env.vault_state,
            &clock,
            gen,
            || Some(Duration::from_secs(305)),
        );

        assert_eq!(res, AutoLockTickResult::LockedSuccessfully);
        assert!(env.auto_lock.0.lock().unwrap().is_locked);
    }

    #[test]
    fn test_windows_idle_api_failure_safely_falls_back_to_watchdog() {
        let env = TestEnvironment::new();

        let clock = MockClock::new();
        let gen = env.auto_lock.0.lock().unwrap().generation;

        // Idle API returns None (failure). Elapsed within app is 100s (< 300s).
        clock.advance(Duration::from_secs(100));
        let res1 = evaluate_auto_lock_tick_with_idle(
            &env.auto_lock,
            &env.vault_state,
            &clock,
            gen,
            || None,
        );
        assert_eq!(res1, AutoLockTickResult::NotExpired);

        // Advance app clock past 300s. Watchdog triggers lock even if OS idle API returns None.
        clock.advance(Duration::from_secs(250));
        let res2 = evaluate_auto_lock_tick_with_idle(
            &env.auto_lock,
            &env.vault_state,
            &clock,
            gen,
            || None,
        );
        assert_eq!(res2, AutoLockTickResult::LockedSuccessfully);
        assert!(env.auto_lock.0.lock().unwrap().is_locked);
    }

    #[test]
    fn test_tick_count_wraparound_arithmetic() {
        // Verify u32 wrapping arithmetic semantics
        let last_input_tick: u32 = 0xFFFF_FFF0; // 16ms before 49.7 day rollover
        let now_tick: u64 = 0x0000_0000_0000_0020; // 32ms after rollover (total delta 48ms)

        let elapsed = (now_tick as u32).wrapping_sub(last_input_tick);
        assert_eq!(elapsed, 48);
    }

    #[test]
    fn test_save_failure_during_os_lock_preserves_unlocked_vault_safely() {
        let env = TestEnvironment::new();

        // Intentionally delete parent dir or make path impossible to save to
        let invalid_path = PathBuf::from("Z:\\nonexistent_dir_12345\\vault.kivault");
        {
            let mut vs = env.vault_state.0.lock().unwrap();
            if let VaultState::Unlocked { ref mut path, .. } = *vs {
                *path = invalid_path.clone();
            }
        }

        // Trigger suspend lock
        handle_os_lifecycle_event(OsLifecycleEvent::Suspend, &env.auto_lock, &env.vault_state);

        // Critical safety invariant: Vault must NOT be destroyed or marked locked if save failed!
        let al = env.auto_lock.0.lock().unwrap();
        assert!(
            !al.is_locked,
            "AutoLock must preserve unlocked on save failure"
        );
        let vs = env.vault_state.0.lock().unwrap();
        assert!(
            matches!(*vs, VaultState::Unlocked { .. }),
            "VaultState must preserve Unlocked on save failure"
        );
    }

    #[test]
    fn test_real_windows_system_idle_api_call() {
        // Direct call to GetLastInputInfo wrapper on Windows host
        let idle_opt = get_windows_system_idle();
        assert!(
            idle_opt.is_some(),
            "GetLastInputInfo should succeed on interactive Windows desktop"
        );
    }
}
