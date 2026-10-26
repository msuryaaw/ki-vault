//! Secure OS Clipboard & Auto-Clear Manager
//!
//! Handles safe interactions with the host OS clipboard and schedules
//! auto-clear timeouts according to `docs/security.md` §12 and `docs/api-contract.md` §6.
//!
//! # Security Invariants
//! - Secrets are never logged or stored in persistent frontend storage.
//! - The auto-clear worker only clears the clipboard if its current content
//!   still matches the secret that was originally copied. If the user copies
//!   another item in the interim, that new content is preserved.
//! - Clipboard operations fail safely if the OS clipboard cannot be opened.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::errors::{AppError, DatabaseError, Result};

/// Trait abstracting OS clipboard operations for testability and portability.
pub trait ClipboardBackend: Send + Sync {
    /// Copies text to the clipboard and returns the clipboard sequence/version number.
    fn set_text(&self, text: &str) -> Result<u64>;
    /// Reads text from the clipboard.
    fn get_text(&self) -> Result<Option<String>>;
    /// Unconditionally clears the clipboard.
    fn clear(&self) -> Result<()>;
    /// Atomically checks whether the clipboard still contains `expected` and (optionally) matches `expected_seq`.
    /// If so, empties the clipboard in the same session without releasing access.
    fn clear_if_matches(&self, expected: &str, expected_seq: Option<u64>) -> Result<bool>;
}

/// Thread-safe in-memory clipboard for testing environments.
#[derive(Default)]
pub struct MockClipboard {
    content: Mutex<Option<String>>,
    seq: std::sync::atomic::AtomicU64,
}

impl MockClipboard {
    pub fn new() -> Self {
        Self {
            content: Mutex::new(None),
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl ClipboardBackend for MockClipboard {
    fn set_text(&self, text: &str) -> Result<u64> {
        let mut g = self.content.lock().unwrap();
        *g = Some(text.to_string());
        let next_seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        Ok(next_seq)
    }

    fn get_text(&self) -> Result<Option<String>> {
        let g = self.content.lock().unwrap();
        Ok(g.clone())
    }

    fn clear(&self) -> Result<()> {
        let mut g = self.content.lock().unwrap();
        *g = None;
        self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn clear_if_matches(&self, expected: &str, expected_seq: Option<u64>) -> Result<bool> {
        let mut g = self.content.lock().unwrap();
        if let Some(s) = expected_seq {
            if self.seq.load(std::sync::atomic::Ordering::SeqCst) != s {
                return Ok(false);
            }
        }
        if g.as_deref() == Some(expected) {
            *g = None;
            self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ─── Windows Native Clipboard Implementation ───────────────────────────────────

#[cfg(windows)]
mod os_clipboard {
    use super::*;
    use std::ffi::c_void;

    pub const CF_UNICODETEXT: u32 = 13;
    pub const GMEM_MOVEABLE: u32 = 0x0002;
    pub const GMEM_ZEROINIT: u32 = 0x0040;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hWndNewOwner: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(uFormat: u32, hMem: *mut c_void) -> *mut c_void;
        fn GetClipboardData(uFormat: u32) -> *mut c_void;
        fn IsClipboardFormatAvailable(uFormat: u32) -> i32;
        fn GetClipboardSequenceNumber() -> u32;
        fn RegisterClipboardFormatW(lpszFormat: *const u16) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> *mut c_void;
        fn GlobalLock(hMem: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(hMem: *mut c_void) -> i32;
        fn GlobalFree(hMem: *mut c_void) -> *mut c_void;
    }

    #[derive(Default)]
    pub struct OsClipboard;

    impl OsClipboard {
        pub fn new() -> Self {
            Self
        }

        fn open_with_retry() -> Result<()> {
            // Clipboard access can intermittently fail if another app is polling/reading
            for _ in 0..10 {
                if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(AppError::Database(DatabaseError::Conflict(
                "Unable to open OS clipboard".to_string(),
            )))
        }

        /// Helper to register a clipboard format name from a UTF-8 string slice.
        pub(crate) fn register_format(name: &str) -> u32 {
            let utf16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { RegisterClipboardFormatW(utf16.as_ptr()) }
        }

        /// Writes a DWORD = 0 format flag to the currently open clipboard.
        ///
        /// Returns `Ok(())` if written or format is 0 (unsupported/unavailable OS),
        /// or an error if memory allocation fails.
        unsafe fn set_clipboard_dword_zero(format_id: u32) -> Result<()> {
            if format_id == 0 {
                return Ok(());
            }

            let h_mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, std::mem::size_of::<u32>());
            if h_mem.is_null() {
                return Err(AppError::Database(DatabaseError::Conflict(
                    "GlobalAlloc failed for clipboard format flag".to_string(),
                )));
            }

            let ptr = GlobalLock(h_mem) as *mut u32;
            if ptr.is_null() {
                GlobalFree(h_mem);
                return Err(AppError::Database(DatabaseError::Conflict(
                    "GlobalLock failed for clipboard format flag".to_string(),
                )));
            }

            std::ptr::write(ptr, 0u32);
            GlobalUnlock(h_mem);

            if SetClipboardData(format_id, h_mem).is_null() {
                GlobalFree(h_mem);
                return Err(AppError::Database(DatabaseError::Conflict(
                    "SetClipboardData failed for clipboard format flag".to_string(),
                )));
            }

            Ok(())
        }

        /// Internal helper to read CF_UNICODETEXT while clipboard is already held open.
        unsafe fn read_unicode_text_held() -> Option<String> {
            if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
                return None;
            }

            let h_mem = GetClipboardData(CF_UNICODETEXT);
            if h_mem.is_null() {
                return None;
            }

            let ptr = GlobalLock(h_mem) as *const u16;
            if ptr.is_null() {
                return None;
            }

            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }

            let slice = std::slice::from_raw_parts(ptr, len);
            let text = String::from_utf16_lossy(slice);

            GlobalUnlock(h_mem);
            Some(text)
        }
    }

    impl ClipboardBackend for OsClipboard {
        fn set_text(&self, text: &str) -> Result<u64> {
            // Register Windows clipboard privacy formats
            let cf_history = Self::register_format("CanIncludeInClipboardHistory");
            let cf_cloud = Self::register_format("CanUploadToCloudClipboard");

            Self::open_with_retry()?;

            let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes_len = utf16.len() * std::mem::size_of::<u16>();

            unsafe {
                EmptyClipboard();

                // 1. Exclude from Windows Clipboard History (Win + V)
                if let Err(e) = Self::set_clipboard_dword_zero(cf_history) {
                    CloseClipboard();
                    return Err(e);
                }

                // 2. Prevent cloud sync across devices
                if let Err(e) = Self::set_clipboard_dword_zero(cf_cloud) {
                    CloseClipboard();
                    return Err(e);
                }

                // 3. Write actual UTF-16 secret text
                let h_mem = GlobalAlloc(GMEM_MOVEABLE, bytes_len);
                if h_mem.is_null() {
                    CloseClipboard();
                    return Err(AppError::Database(DatabaseError::Conflict(
                        "GlobalAlloc failed for clipboard data".to_string(),
                    )));
                }

                let ptr = GlobalLock(h_mem) as *mut u16;
                if ptr.is_null() {
                    GlobalFree(h_mem);
                    CloseClipboard();
                    return Err(AppError::Database(DatabaseError::Conflict(
                        "GlobalLock failed for clipboard data".to_string(),
                    )));
                }

                std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
                GlobalUnlock(h_mem);

                if SetClipboardData(CF_UNICODETEXT, h_mem).is_null() {
                    GlobalFree(h_mem);
                    CloseClipboard();
                    return Err(AppError::Database(DatabaseError::Conflict(
                        "SetClipboardData failed".to_string(),
                    )));
                }

                let seq = GetClipboardSequenceNumber() as u64;
                CloseClipboard();
                Ok(seq)
            }
        }

        fn get_text(&self) -> Result<Option<String>> {
            Self::open_with_retry()?;
            unsafe {
                let res = Self::read_unicode_text_held();
                CloseClipboard();
                Ok(res)
            }
        }

        fn clear(&self) -> Result<()> {
            Self::open_with_retry()?;
            unsafe {
                EmptyClipboard();
                CloseClipboard();
            }
            Ok(())
        }

        fn clear_if_matches(&self, expected: &str, expected_seq: Option<u64>) -> Result<bool> {
            // First check sequence number before acquiring clipboard lock if requested
            if let Some(s) = expected_seq {
                let current_seq = unsafe { GetClipboardSequenceNumber() } as u64;
                if current_seq != s {
                    // Clipboard sequence has changed, skip clearing
                    return Ok(false);
                }
            }

            Self::open_with_retry()?;
            unsafe {
                // If sequence number was requested, verify again under lock
                if let Some(s) = expected_seq {
                    let locked_seq = GetClipboardSequenceNumber() as u64;
                    if locked_seq != s {
                        CloseClipboard();
                        return Ok(false);
                    }
                }

                // Check text and clear in the SAME OpenClipboard session
                let should_clear = match Self::read_unicode_text_held() {
                    Some(ref current) => current == expected,
                    None => false,
                };

                if should_clear {
                    EmptyClipboard();
                    CloseClipboard();
                    Ok(true)
                } else {
                    CloseClipboard();
                    Ok(false)
                }
            }
        }
    }
}

// ─── Default Non-Windows Fallback ──────────────────────────────────────────────

#[cfg(not(windows))]
mod os_clipboard {
    use super::*;

    #[derive(Default)]
    pub struct OsClipboard;

    impl OsClipboard {
        pub fn new() -> Self {
            Self
        }
    }

    impl ClipboardBackend for OsClipboard {
        fn set_text(&self, _text: &str) -> Result<u64> {
            Ok(0)
        }

        fn get_text(&self) -> Result<Option<String>> {
            Ok(None)
        }

        fn clear(&self) -> Result<()> {
            Ok(())
        }

        fn clear_if_matches(&self, _expected: &str, _expected_seq: Option<u64>) -> Result<bool> {
            Ok(false)
        }
    }
}

pub use os_clipboard::OsClipboard;

// ─── Secure Copy with Auto-Clear ───────────────────────────────────────────────

/// Copies a secret directly to the OS clipboard and schedules an auto-clear timeout.
///
/// If the user modifies or copies another value into the clipboard before `timeout_seconds`
/// expires, the auto-clear task detects the change and leaves the new clipboard contents intact.
///
/// Both checking the content and clearing the clipboard are executed within a single `OpenClipboard`
/// session, eliminating the TOCTOU race condition.
pub fn copy_and_schedule_clear<B: ClipboardBackend + 'static>(
    backend: Arc<B>,
    secret: &str,
    timeout_seconds: u64,
) -> Result<()> {
    // 1. Copy to clipboard and capture sequence number
    let initial_seq = backend.set_text(secret)?;

    let expected_secret = Zeroizing::new(secret.to_string());

    // 2. Spawn background thread for timeout
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_seconds));

        // Atomically verify content and sequence, and clear within single session
        let _ = backend.clear_if_matches(&expected_secret, Some(initial_seq));
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_clipboard_roundtrip_and_clear() {
        let cb = MockClipboard::new();
        assert_eq!(cb.get_text().unwrap(), None);

        cb.set_text("test_secret_123").unwrap();
        assert_eq!(cb.get_text().unwrap().as_deref(), Some("test_secret_123"));

        cb.clear().unwrap();
        assert_eq!(cb.get_text().unwrap(), None);
    }

    #[test]
    fn test_auto_clear_clears_if_unchanged() {
        let cb = Arc::new(MockClipboard::new());
        copy_and_schedule_clear(cb.clone(), "my-password", 1).unwrap();

        assert_eq!(cb.get_text().unwrap().as_deref(), Some("my-password"));

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(1200));

        // Clipboard should be empty
        assert_eq!(cb.get_text().unwrap(), None);
    }

    #[test]
    fn test_auto_clear_preserves_new_user_clipboard_content() {
        let cb = Arc::new(MockClipboard::new());
        copy_and_schedule_clear(cb.clone(), "old-secret", 1).unwrap();

        // User copies something else in the meantime
        std::thread::sleep(Duration::from_millis(300));
        cb.set_text("user-copied-article").unwrap();

        // Wait past original timeout
        std::thread::sleep(Duration::from_millis(900));

        // New content must be preserved
        assert_eq!(
            cb.get_text().unwrap().as_deref(),
            Some("user-copied-article")
        );
    }

    #[test]
    fn test_auto_clear_preserves_content_if_user_copied_identical_text_afterwards() {
        let cb = Arc::new(MockClipboard::new());
        // Copy secret with 1 sec timeout
        copy_and_schedule_clear(cb.clone(), "same-secret", 1).unwrap();

        // User copies identical text in the meantime, which advances the sequence number
        std::thread::sleep(Duration::from_millis(300));
        let _new_seq = cb.set_text("same-secret").unwrap();

        // Wait past original timeout
        std::thread::sleep(Duration::from_millis(900));

        // Because the sequence number advanced, the original timer must NOT clear the clipboard
        assert_eq!(cb.get_text().unwrap().as_deref(), Some("same-secret"));
    }

    #[test]
    fn test_clear_if_matches_logic() {
        let cb = MockClipboard::new();
        let seq = cb.set_text("secret-token").unwrap();

        // Wrong expected string -> should return false and not clear
        let cleared = cb.clear_if_matches("wrong-token", Some(seq)).unwrap();
        assert!(!cleared);
        assert_eq!(cb.get_text().unwrap().as_deref(), Some("secret-token"));

        // Wrong sequence number -> should return false and not clear
        let cleared = cb.clear_if_matches("secret-token", Some(seq + 99)).unwrap();
        assert!(!cleared);
        assert_eq!(cb.get_text().unwrap().as_deref(), Some("secret-token"));

        // Correct sequence and content -> clears
        let cleared = cb.clear_if_matches("secret-token", Some(seq)).unwrap();
        assert!(cleared);
        assert_eq!(cb.get_text().unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_clipboard_formats_registration_and_set_text() {
        // Verify format registration generates valid non-zero format IDs on Windows
        let cf_history = OsClipboard::register_format("CanIncludeInClipboardHistory");
        let cf_cloud = OsClipboard::register_format("CanUploadToCloudClipboard");
        assert!(
            cf_history > 0,
            "CanIncludeInClipboardHistory format must be registered"
        );
        assert!(
            cf_cloud > 0,
            "CanUploadToCloudClipboard format must be registered"
        );
        assert_ne!(cf_history, cf_cloud, "Format IDs must be distinct");

        // Verify set_text successfully places text and privacy flags without error
        let cb = OsClipboard::new();
        let seq = cb.set_text("test_privacy_secret").unwrap();
        assert!(seq > 0);

        let retrieved = cb.get_text().unwrap();
        assert_eq!(retrieved.as_deref(), Some("test_privacy_secret"));

        // Clean up
        let _ = cb.clear();
    }
}
