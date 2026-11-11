//! TASK 4.8: Verify SQLite Temporary-Storage & Plaintext-Spill Behavior
//!
//! Windows Native Runtime Verification & Final Remediation:
//! 1. Effective SQLite Temporary Storage Resolution:
//!    - Verifies effective temporary storage directory on Windows using Win32 `GetTempPathW()`,
//!      normalized with `GetLongPathNameW` with strict bounds and dynamic allocation (no silent fallback).
//!    - Verifies absence of SQLite temporary directory overrides (`sqlite3_temp_directory`,
//!      `PRAGMA temp_store_directory`, `SQLITE_TMPDIR`, `SQLITE_TEMP_FILE_DIR`).
//! 2. Win32 ReadDirectoryChangesW Watcher Lifecycle, Overlapped I/O & Error Propagation:
//!    - Asynchronous `ReadDirectoryChangesW` called with `lpBytesReturned = NULL` as required by Win32 contract.
//!    - Manual-reset Win32 event with explicit, checked `ResetEvent()`.
//!    - Dedicated worker cancellation via `CancelIoEx`, draining completion via `GetOverlappedResult`.
//!    - Complete `OVERLAPPED` and buffer lifetime guarantees: worker never exits with pending I/O.
//!    - Complete handling of all `WaitForSingleObject` return codes (`WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED`, unknown).
//!    - Active worker health monitoring and fail-safe error propagation.
//!    - `stop()` joins worker thread prior to closing Win32 handles.
//! 3. Alignment-Safe, Checked FILE_NOTIFY_INFORMATION Parser:
//!    - Zero unaligned struct references; header fields extracted via `u32::from_le_bytes`.
//!    - Checked bounds and arithmetic preventing integer overflows.
//!    - Enforces 4-byte record alignment, even `FileNameLength` (UTF-16LE), and validates `NextEntryOffset`.
//!    - Comprehensive unit regression test suite covering 11 distinct valid and malformed synthetic buffers.
//! 4. Full Positive-Control Event Lifecycle Assertion:
//!    - Executed directly inside the effective temporary directory.
//!    - Bounded polling with explicit deadlines for every lifecycle event (`ADDED`, `MODIFIED`,
//!      `RENAMED_OLD_NAME`, `RENAMED_NEW_NAME`, `REMOVED`).
//!    - Serialized execution across tests via global static mutex to prevent %TEMP% watcher race conditions.
//! 5. Accurate SQLite Candidate File Classification:
//!    - Tailored to SQLite Windows VFS (`os_win.c` `winGetTempname`, `pager.c`, `wal.c`).
//!    - Matches `etilqs_*`, `*-journal`, `*-wal`, `*-shm`, `*.db-journal`, `*.db-wal`, `*.db-shm`,
//!      `*.sqlite-journal`, `*.sqlite-wal`, `*.sqlite-shm`, `*.db`, `*.sqlite`, `*.sqlite3`.
//! 6. Fail-Closed Filesystem Scanning:
//!    - Enumeration fails closed: any error reading the directory or any individual entry aborts the test.
//! 7. Stress Workload with True Temporary Storage & Logical Structures:
//!    - 20,000 synthetic records inserted into explicit `CREATE TEMP TABLE` with `CREATE INDEX` on temp schema.
//!    - Verified temporary schema isolation (`sqlite_temp_master`) and empty backing files (`PRAGMA database_list`).
//!    - Multi-line `EXPLAIN QUERY PLAN` verification for `USE TEMP B-TREE FOR ORDER BY`,
//!      `USE TEMP B-TREE FOR GROUP BY`, `USE TEMP B-TREE FOR DISTINCT`, and `MATERIALIZE` for CTEs.
//!    - In-memory transaction rollback and image serialization under active watcher observation.

#![cfg(windows)]

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ki_vault_lib::vault::sqlite::InMemoryDb;

// Global synchronization mutex to serialize tests that observe the shared %TEMP% directory.
static TEMP_WATCHER_SERIALIZATION_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// WIN32 CONSTANTS & P/INVOKE DEFINITIONS
// ============================================================================

const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x00000004;
const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x00000040;

pub const FILE_ACTION_ADDED: u32 = 0x00000001;
pub const FILE_ACTION_REMOVED: u32 = 0x00000002;
pub const FILE_ACTION_MODIFIED: u32 = 0x00000003;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x00000004;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x00000005;

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;

const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

const ERROR_IO_PENDING: u32 = 997;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_NOT_FOUND: u32 = 1168;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFFFFFF;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
struct OVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub h_event: *mut c_void,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut c_void,
    ) -> *mut c_void;

    fn CreateEventW(
        lpEventAttributes: *mut c_void,
        bManualReset: i32,
        bInitialState: i32,
        lpName: *const u16,
    ) -> *mut c_void;

    fn ResetEvent(hEvent: *mut c_void) -> i32;

    fn ReadDirectoryChangesW(
        hDirectory: *mut c_void,
        lpBuffer: *mut c_void,
        nBufferLength: u32,
        bWatchSubtree: i32,
        dwNotifyFilter: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut c_void,
        lpCompletionRoutine: *mut c_void,
    ) -> i32;

    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;

    fn GetOverlappedResult(
        hFile: *mut c_void,
        lpOverlapped: *mut c_void,
        lpNumberOfBytesTransferred: *mut u32,
        bWait: i32,
    ) -> i32;

    fn CancelIoEx(hFile: *mut c_void, lpOverlapped: *mut c_void) -> i32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn GetLastError() -> u32;
    fn GetTempPathW(nBufferLength: u32, lpBuffer: *mut u16) -> u32;
    fn GetLongPathNameW(lpszShortPath: *const u16, lpszLongPath: *mut u16, cchBuffer: u32) -> u32;
}

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

trait OsStringExt {
    fn from_wide_null(slice: &[u16]) -> Self;
}

impl OsStringExt for std::ffi::OsString {
    fn from_wide_null(slice: &[u16]) -> Self {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(slice)
    }
}

// ============================================================================
// 1. EFFECTIVE SQLITE TEMPORARY DIRECTORY RESOLVER
// ============================================================================

/// Determines the effective Windows temporary directory used by bundled SQLite.
///
/// Follows Win32 GetTempPathW resolution, canonicalizes via GetLongPathNameW,
/// asserts directory existence and accessibility, and fails closed without silent fallback.
pub fn get_effective_sqlite_temp_path() -> Result<PathBuf, String> {
    // 1. Query Win32 GetTempPathW with dynamic buffer allocation
    let mut buf_len = 260u32;
    let mut buf = vec![0u16; buf_len as usize];
    let mut len = unsafe { GetTempPathW(buf_len, buf.as_mut_ptr()) };
    if len > buf_len {
        buf_len = len + 1;
        buf.resize(buf_len as usize, 0);
        len = unsafe { GetTempPathW(buf_len, buf.as_mut_ptr()) };
    }
    if len == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("GetTempPathW failed with Win32 error code {err}"));
    }

    let os_str = std::ffi::OsString::from_wide_null(&buf[..len as usize]);
    let raw_temp = PathBuf::from(os_str);

    // 2. Canonicalize via GetLongPathNameW to normalize 8.3 short name aliasing
    let short_wide = to_wide(&raw_temp);
    let mut long_buf_len = 260u32;
    let mut long_buf = vec![0u16; long_buf_len as usize];
    let mut long_len =
        unsafe { GetLongPathNameW(short_wide.as_ptr(), long_buf.as_mut_ptr(), long_buf_len) };
    if long_len > long_buf_len {
        long_buf_len = long_len + 1;
        long_buf.resize(long_buf_len as usize, 0);
        long_len =
            unsafe { GetLongPathNameW(short_wide.as_ptr(), long_buf.as_mut_ptr(), long_buf_len) };
    }
    let canonical_temp = if long_len == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "GetLongPathNameW failed for '{}' with Win32 error code {err}",
            raw_temp.display()
        ));
    } else {
        let long_os_str = std::ffi::OsString::from_wide_null(&long_buf[..long_len as usize]);
        PathBuf::from(long_os_str)
    };

    // 3. Verify directory existence and accessibility
    if !canonical_temp.exists() {
        return Err(format!(
            "Effective temporary directory '{}' does not exist",
            canonical_temp.display()
        ));
    }
    if !canonical_temp.is_dir() {
        return Err(format!(
            "Effective temporary directory path '{}' is not a directory",
            canonical_temp.display()
        ));
    }

    Ok(canonical_temp)
}

// ============================================================================
// 2. ALIGNMENT-SAFE FILE_NOTIFY_INFORMATION RECORD PARSER
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFileEvent {
    pub action: u32,
    pub action_name: &'static str,
    pub file_name: String,
}

pub fn action_to_name(action: u32) -> &'static str {
    match action {
        FILE_ACTION_ADDED => "ADDED",
        FILE_ACTION_REMOVED => "REMOVED",
        FILE_ACTION_MODIFIED => "MODIFIED",
        FILE_ACTION_RENAMED_OLD_NAME => "RENAMED_OLD",
        FILE_ACTION_RENAMED_NEW_NAME => "RENAMED_NEW",
        _ => "UNKNOWN",
    }
}

/// Parses raw `FILE_NOTIFY_INFORMATION` byte buffers without unaligned struct pointer casts.
///
/// Validates:
/// - Exact buffer boundaries and checked arithmetic preventing integer overflow
/// - 4-byte record alignment
/// - Even `FileNameLength` (UTF-16 code units)
/// - `NextEntryOffset` bounds and minimum record sizing
/// - Strictly rejects `NextEntryOffset` reaching end of buffer without sufficient header for next record
pub fn parse_file_notify_records(
    buffer: &[u8],
    bytes_transferred: usize,
) -> Result<Vec<CapturedFileEvent>, String> {
    if bytes_transferred > buffer.len() {
        return Err(format!(
            "bytes_transferred ({bytes_transferred}) exceeds buffer capacity ({})",
            buffer.len()
        ));
    }

    let mut events = Vec::new();
    let mut offset = 0usize;
    let min_header_size = 12usize; // next_offset (4), action (4), file_name_length (4)

    while offset < bytes_transferred {
        // Enforce 4-byte boundary alignment for record header
        if !offset.is_multiple_of(4) {
            return Err(format!(
                "Unaligned record offset {offset} (must be multiple of 4)"
            ));
        }

        let remaining = bytes_transferred
            .checked_sub(offset)
            .ok_or_else(|| "Offset arithmetic underflow".to_string())?;

        if remaining < min_header_size {
            return Err(format!(
                "Truncated record header at offset {offset}: remaining {remaining} bytes < {min_header_size}"
            ));
        }

        let next_offset = u32::from_le_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .map_err(|e| format!("Slice convert error: {e}"))?,
        ) as usize;

        let action = u32::from_le_bytes(
            buffer[offset + 4..offset + 8]
                .try_into()
                .map_err(|e| format!("Slice convert error: {e}"))?,
        );

        let name_len = u32::from_le_bytes(
            buffer[offset + 8..offset + 12]
                .try_into()
                .map_err(|e| format!("Slice convert error: {e}"))?,
        ) as usize;

        // FileNameLength must be an even number of bytes for valid UTF-16LE
        if !name_len.is_multiple_of(2) {
            return Err(format!(
                "Invalid odd FileNameLength ({name_len}) at offset {offset}"
            ));
        }

        let record_min_end = offset
            .checked_add(min_header_size)
            .and_then(|h| h.checked_add(name_len))
            .ok_or_else(|| "Record boundary overflow".to_string())?;

        if record_min_end > bytes_transferred {
            return Err(format!(
                "FileNameLength {name_len} at offset {offset} overflows transferred bytes ({bytes_transferred})"
            ));
        }

        // Decode UTF-16 filename
        let name_start = offset + min_header_size;
        let name_bytes = &buffer[name_start..name_start + name_len];
        let mut u16_words = Vec::with_capacity(name_len / 2);
        for chunk in name_bytes.as_chunks::<2>().0 {
            u16_words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        let file_name = String::from_utf16_lossy(&u16_words);

        events.push(CapturedFileEvent {
            action,
            action_name: action_to_name(action),
            file_name,
        });

        if next_offset == 0 {
            // Last entry in the buffer
            break;
        }

        // Validate NextEntryOffset
        if !next_offset.is_multiple_of(4) {
            return Err(format!(
                "NextEntryOffset {next_offset} at offset {offset} is not 4-byte aligned"
            ));
        }

        if next_offset < min_header_size + name_len {
            return Err(format!(
                "NextEntryOffset {next_offset} is smaller than minimum record length ({}) at offset {offset}",
                min_header_size + name_len
            ));
        }

        let next_record_start = offset
            .checked_add(next_offset)
            .ok_or_else(|| "Next entry offset arithmetic overflow".to_string())?;

        // If next_offset is nonzero, there MUST be at least a full header (12 bytes) remaining
        let remaining_for_next = bytes_transferred
            .checked_sub(next_record_start)
            .ok_or_else(|| "Next record offset exceeds transferred bytes".to_string())?;

        if remaining_for_next < min_header_size {
            return Err(format!(
                "NextEntryOffset {next_offset} from offset {offset} leaves only {remaining_for_next} bytes (need at least {min_header_size} bytes for next header)"
            ));
        }

        offset = next_record_start;
    }

    Ok(events)
}

// ============================================================================
// 3. OVERLAPPED WIN32 DIRECTORY WATCHER
// ============================================================================

/// Closes both Win32 handles using `Option::take()` so each handle is closed at most once.
///
/// Returns `Err` listing any `CloseHandle` failures; both handles are always attempted.
/// Each handle is passed to the provided `close` closure exactly once; the closure performs
/// the actual `CloseHandle` call in production, or counts attempts in tests.
fn close_handles_with<F>(
    handle_usize: &mut Option<usize>,
    event_usize: &mut Option<usize>,
    mut close: F,
) -> Result<(), String>
where
    F: FnMut(usize) -> Result<(), String>,
{
    let mut errs = Vec::new();
    if let Some(ev) = event_usize.take() {
        if let Err(e) = close(ev) {
            errs.push(e);
        }
    }
    if let Some(h) = handle_usize.take() {
        if let Err(e) = close(h) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// Production wrapper: closes Win32 handles via `CloseHandle`, propagating any error codes.
fn close_handles(
    handle_usize: &mut Option<usize>,
    event_usize: &mut Option<usize>,
) -> Result<(), String> {
    close_handles_with(handle_usize, event_usize, |raw| {
        let res = unsafe { CloseHandle(raw as *mut c_void) };
        if res == 0 {
            let err = unsafe { GetLastError() };
            Err(format!("CloseHandle failed with Win32 error {err}"))
        } else {
            Ok(())
        }
    })
}

/// Internal helper: record a worker error message, recovering from a poisoned `worker_error`
/// mutex when necessary. This is the **single centralized path** for all worker failure recording.
///
/// Sets the error message whether the lock is healthy or poisoned. The message remains
/// observable through the `worker_failed` atomic flag which is set before this call.
fn record_worker_error(worker_error: &Arc<Mutex<Option<String>>>, msg: &str) {
    match worker_error.lock() {
        Ok(mut lock) => *lock = Some(msg.to_string()),
        Err(mut poison) => {
            // The mutex is poisoned. Recover the inner value and overwrite it,
            // so the descriptive error is updated even through the poisoned state.
            **poison.get_mut() = Some(msg.to_string());
        }
    }
}

/// Internal helper: process a successful cancellation-drain completion result.
///
/// Parses `buffer[..bytes]`, appends events to `events_out`, and records any failure
/// (parse error or poisoned event-collection mutex) via `record_worker_error` and
/// `worker_failed`. Factored out so the production worker and regression tests call
/// identical logic â€” no duplication between the two.
fn process_drain_completion(
    buffer: &[u8],
    bytes: usize,
    events_out: &Arc<Mutex<Vec<CapturedFileEvent>>>,
    worker_error_out: &Arc<Mutex<Option<String>>>,
    worker_failed: &Arc<AtomicBool>,
) {
    match parse_file_notify_records(buffer, bytes) {
        Ok(parsed) => match events_out.lock() {
            Ok(mut lock) => lock.extend(parsed),
            Err(poison) => {
                worker_failed.store(true, Ordering::SeqCst);
                let msg = format!(
                    "Event collection mutex poisoned during cancellation drain (held {} events)",
                    poison.into_inner().len()
                );
                record_worker_error(worker_error_out, &msg);
            }
        },
        Err(parse_err) => {
            worker_failed.store(true, Ordering::SeqCst);
            let msg = format!("Parser failure during cancellation drain: {parse_err}");
            record_worker_error(worker_error_out, &msg);
        }
    }
}

pub struct DirectoryWatcher {
    stop_signal: Arc<AtomicBool>,
    /// Independently observable failure flag. Set before recording the descriptive error
    /// message, so failures remain detectable even when `worker_error` is poisoned.
    worker_failed: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<CapturedFileEvent>>>,
    overflow_detected: Arc<AtomicBool>,
    worker_error: Arc<Mutex<Option<String>>>,
    /// Owns the directory handle; `None` once closed via `stop()` or `Drop`.
    handle_usize: Option<usize>,
    /// Owns the event handle; `None` once closed via `stop()` or `Drop`.
    event_usize: Option<usize>,
    worker_handle: Option<thread::JoinHandle<()>>,
}

impl DirectoryWatcher {
    pub fn start(dir: &Path) -> Result<Self, String> {
        let path_w = to_wide(dir);
        let h_dir = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                0x0001, // FILE_LIST_DIRECTORY
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };

        if h_dir == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "CreateFileW failed for '{}' with Win32 error code {err}",
                dir.display()
            ));
        }

        // Create manual-reset event (bManualReset = 1, bInitialState = 0)
        let h_event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if h_event.is_null() {
            unsafe { CloseHandle(h_dir) };
            let err = unsafe { GetLastError() };
            return Err(format!("CreateEventW failed with Win32 error code {err}"));
        }

        let handle_usize = h_dir as usize;
        let event_usize = h_event as usize;
        let stop_signal = Arc::new(AtomicBool::new(false));
        let worker_failed = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let overflow_detected = Arc::new(AtomicBool::new(false));
        let worker_error = Arc::new(Mutex::new(None));

        let stop_clone = Arc::clone(&stop_signal);
        let worker_failed_clone = Arc::clone(&worker_failed);
        let events_clone = Arc::clone(&events);
        let overflow_clone = Arc::clone(&overflow_detected);
        let worker_error_clone = Arc::clone(&worker_error);

        let worker = thread::spawn(move || {
            let h = handle_usize as *mut c_void;
            let ev_handle = event_usize as *mut c_void;
            // 64 KiB buffer to capture notifications reliably
            let mut buffer = vec![0u8; 65536];

            let filter = FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_CREATION;

            while !stop_clone.load(Ordering::Relaxed) {
                // Check and reset event before initiating next overlapped operation
                let reset_res = unsafe { ResetEvent(ev_handle) };
                if reset_res == 0 {
                    let err = unsafe { GetLastError() };
                    worker_failed_clone.store(true, Ordering::SeqCst);
                    record_worker_error(
                        &worker_error_clone,
                        &format!("ResetEvent failed with Win32 error code {err}"),
                    );
                    break;
                }

                let mut overlapped = OVERLAPPED {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    offset_high: 0,
                    h_event: ev_handle,
                };

                // Asynchronous invocation: lpBytesReturned MUST be NULL per Microsoft documentation.
                let res = unsafe {
                    ReadDirectoryChangesW(
                        h,
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len() as u32,
                        0, // non-recursive watch of immediate directory
                        filter,
                        std::ptr::null_mut(),
                        &mut overlapped as *mut OVERLAPPED as *mut c_void,
                        std::ptr::null_mut(),
                    )
                };

                if res == 0 {
                    let err = unsafe { GetLastError() };
                    if err != ERROR_IO_PENDING {
                        worker_failed_clone.store(true, Ordering::SeqCst);
                        record_worker_error(
                            &worker_error_clone,
                            &format!("ReadDirectoryChangesW failed with Win32 error code {err}"),
                        );
                        break;
                    }
                }

                // Poll completion with bounded wait to respond cleanly to stop_signal
                let mut completed = false;
                while !stop_clone.load(Ordering::Relaxed) {
                    let wait_res = unsafe { WaitForSingleObject(ev_handle, 50) };
                    match wait_res {
                        WAIT_OBJECT_0 => {
                            completed = true;
                            break;
                        }
                        WAIT_TIMEOUT => continue,
                        WAIT_FAILED => {
                            let err = unsafe { GetLastError() };
                            worker_failed_clone.store(true, Ordering::SeqCst);
                            record_worker_error(
                                &worker_error_clone,
                                &format!("WaitForSingleObject failed with Win32 error code {err}"),
                            );
                            break;
                        }
                        other => {
                            worker_failed_clone.store(true, Ordering::SeqCst);
                            record_worker_error(
                                &worker_error_clone,
                                &format!("WaitForSingleObject returned unexpected code {other}"),
                            );
                            break;
                        }
                    }
                }

                if !completed {
                    // The worker is the sole owner of cancellation for its own OVERLAPPED.
                    // stop() and Drop NEVER call CancelIoEx. Only the worker does here,
                    // using the specific OVERLAPPED pointer for this operation.
                    let cancel_res =
                        unsafe { CancelIoEx(h, &mut overlapped as *mut OVERLAPPED as *mut c_void) };
                    if cancel_res == 0 {
                        let err = unsafe { GetLastError() };
                        // ERROR_NOT_FOUND means I/O completed naturally before cancel arrived.
                        if err != ERROR_NOT_FOUND {
                            worker_failed_clone.store(true, Ordering::SeqCst);
                            record_worker_error(
                                &worker_error_clone,
                                &format!("CancelIoEx failed with unexpected error code {err}"),
                            );
                        }
                    }

                    // Drain completion via GetOverlappedResult to ensure kernel finishes with OVERLAPPED and buffer.
                    // The buffer and OVERLAPPED must remain alive until this returns.
                    let mut transferred = 0u32;
                    let drain_res = unsafe {
                        GetOverlappedResult(
                            h,
                            &mut overlapped as *mut OVERLAPPED as *mut c_void,
                            &mut transferred,
                            1, // wait until kernel marks completion finished
                        )
                    };
                    if drain_res == 0 {
                        let drain_err = unsafe { GetLastError() };
                        // ERROR_OPERATION_ABORTED is the expected result when CancelIoEx succeeded.
                        if drain_err != ERROR_OPERATION_ABORTED {
                            worker_failed_clone.store(true, Ordering::SeqCst);
                            record_worker_error(
                                &worker_error_clone,
                                &format!(
                                    "GetOverlappedResult during drain returned unexpected error: {drain_err}"
                                ),
                            );
                        }
                    } else if transferred > 0 && !overflow_clone.load(Ordering::Relaxed) {
                        // I/O completed with data just before cancellation arrived.
                        // Process via the shared helper (identical logic used by regression tests).
                        process_drain_completion(
                            &buffer,
                            transferred as usize,
                            &events_clone,
                            &worker_error_clone,
                            &worker_failed_clone,
                        );
                    }
                    break;
                }

                let mut transferred = 0u32;
                let gres = unsafe {
                    GetOverlappedResult(
                        h,
                        &mut overlapped as *mut OVERLAPPED as *mut c_void,
                        &mut transferred,
                        0,
                    )
                };

                if gres == 0 {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_OPERATION_ABORTED && stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    worker_failed_clone.store(true, Ordering::SeqCst);
                    record_worker_error(
                        &worker_error_clone,
                        &format!("GetOverlappedResult failed with Win32 error code {err}"),
                    );
                    break;
                }

                if transferred == 0 {
                    // ReadDirectoryChangesW signals 0 transferred bytes on buffer overflow
                    overflow_clone.store(true, Ordering::SeqCst);
                    continue;
                }

                match parse_file_notify_records(&buffer, transferred as usize) {
                    Ok(parsed) => match events_clone.lock() {
                        Ok(mut lock) => lock.extend(parsed),
                        Err(_) => {
                            worker_failed_clone.store(true, Ordering::SeqCst);
                            record_worker_error(
                                &worker_error_clone,
                                "Event collection mutex poisoned during normal completion",
                            );
                            break;
                        }
                    },
                    Err(parse_err) => {
                        worker_failed_clone.store(true, Ordering::SeqCst);
                        record_worker_error(
                            &worker_error_clone,
                            &format!("Parser failure: {parse_err}"),
                        );
                        break;
                    }
                }
            }
        });

        Ok(Self {
            stop_signal,
            worker_failed,
            events,
            overflow_detected,
            worker_error,
            handle_usize: Some(h_dir as usize),
            event_usize: Some(h_event as usize),
            worker_handle: Some(worker),
        })
    }

    pub fn events(&self) -> Vec<CapturedFileEvent> {
        self.events.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Validates worker health at execution checkpoints.
    ///
    /// Checks the independent `worker_failed` atomic flag first, so failures are
    /// detectable even when the `worker_error` descriptive mutex is poisoned.
    pub fn assert_healthy(&self, checkpoint_desc: &str) {
        if self.worker_failed.load(Ordering::SeqCst) {
            let detail = match self.worker_error.lock() {
                Ok(lock) => lock.clone().unwrap_or_else(|| "(no detail)".to_string()),
                Err(poison) => poison
                    .into_inner()
                    .clone()
                    .unwrap_or_else(|| "(error mutex poisoned, no detail)".to_string()),
            };
            panic!("FATAL: Directory watcher failed at '{checkpoint_desc}': {detail}");
        }
        if self.overflow_detected.load(Ordering::SeqCst) {
            panic!("FATAL: Directory watcher overflowed at '{checkpoint_desc}'");
        }
        if let Some(ref handle) = self.worker_handle {
            if handle.is_finished() && !self.stop_signal.load(Ordering::Relaxed) {
                panic!(
                    "FATAL: Directory watcher worker thread terminated unexpectedly at '{checkpoint_desc}'"
                );
            }
        }
    }

    /// Stops the watcher cleanly, joins the worker thread, closes handles,
    /// and returns the captured events.
    ///
    /// # Shutdown sequence
    /// 1. Set `stop_signal` â€” the worker's poll loop detects it within 50 ms, calls
    ///    `CancelIoEx` on its own specific `OVERLAPPED`, drains completion, and exits.
    ///    **`stop()` itself does NOT call `CancelIoEx`.**
    /// 2. Join the worker â€” guarantees all I/O is complete before handles are closed.
    /// 3. Close handles via `close_handles()` â€” single-close guaranteed by `Option::take()`.
    /// 4. Collect and propagate all errors, including when `worker_error` is poisoned.
    pub fn stop(mut self) -> Result<(Vec<CapturedFileEvent>, bool), String> {
        self.stop_signal.store(true, Ordering::Relaxed);

        // Join worker thread BEFORE closing Win32 handles.
        // The worker owns cancellation of its own OVERLAPPED; stop() does NOT call CancelIoEx.
        let join_res = if let Some(join_handle) = self.worker_handle.take() {
            join_handle
                .join()
                .map_err(|_| "Watcher worker thread panicked".to_string())
        } else {
            Ok(())
        };

        // Close Win32 handles strictly after thread exit, taking ownership to prevent double-close.
        let close_err = close_handles(&mut self.handle_usize, &mut self.event_usize).err();

        // Propagate join error first (worker panic takes priority over other errors).
        join_res?;
        if let Some(msg) = close_err {
            return Err(msg);
        }

        // Check the independent failure flag â€” detectable even when worker_error is poisoned.
        if self.worker_failed.load(Ordering::SeqCst) {
            let detail = match self.worker_error.lock() {
                Ok(mut lock) => lock
                    .take()
                    .unwrap_or_else(|| "(worker failed, no detail available)".to_string()),
                Err(mut poison) => poison
                    .get_mut()
                    .take()
                    .unwrap_or_else(|| "(worker failed, error mutex poisoned)".to_string()),
            };
            return Err(format!("Watcher worker failed: {detail}"));
        }

        // Also check worker_error directly (belt-and-suspenders for any path that recorded
        // an error without setting the flag, e.g. from before the worker_failed field existed).
        if let Ok(mut lock) = self.worker_error.lock() {
            if let Some(worker_err) = lock.take() {
                return Err(format!("Watcher worker failed: {worker_err}"));
            }
        }

        let overflow = self.overflow_detected.load(Ordering::SeqCst);
        let ev = self.events.lock().map(|l| l.clone()).unwrap_or_default();
        Ok((ev, overflow))
    }
}

impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        // No CancelIoEx here â€” the worker detects the stop_signal in its poll loop and
        // cancels its own OVERLAPPED. Drop only joins and closes owned handles.
        if let Some(join_handle) = self.worker_handle.take() {
            let _ = join_handle.join();
        }
        // close_handles uses .take() â€” safe to call even if stop() already closed them.
        let _ = close_handles(&mut self.handle_usize, &mut self.event_usize);
    }
}

// ============================================================================
// 4. ACCURATE SQLITE CANDIDATE FILE CLASSIFIER & SCANNER
// ============================================================================

/// Detects SQLite candidate temporary, journal, WAL, or backing spill files.
///
/// Grounded in SQLite Windows VFS implementation (`os_win.c` `winGetTempname`, `pager.c`, `wal.c`):
/// - Default Windows temp files start with "etilqs_" followed by 15 random alphanumeric chars.
/// - Rollback journals append "-journal" or ".db-journal" / ".sqlite-journal".
/// - Write-Ahead Logs append "-wal" or ".db-wal" / ".sqlite-wal".
/// - Shared memory indexes append "-shm" or ".db-shm" / ".sqlite-shm".
/// - Database files end with ".db", ".sqlite", or ".sqlite3".
pub fn is_sqlite_candidate_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("etilqs_")
        || lower.ends_with("-journal")
        || lower.ends_with("-wal")
        || lower.ends_with("-shm")
        || lower.ends_with(".db-journal")
        || lower.ends_with(".db-wal")
        || lower.ends_with(".db-shm")
        || lower.ends_with(".sqlite-journal")
        || lower.ends_with(".sqlite-wal")
        || lower.ends_with(".sqlite-shm")
        || lower.ends_with(".db")
        || lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite3")
}

/// Scans directory entries and fails closed (returns Err) on any filesystem failure.
pub fn scan_directory_fail_closed(dir: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    let read_dir = fs::read_dir(dir).map_err(|e| {
        format!(
            "Fail-closed scan: failed to read directory '{}': {e}",
            dir.display()
        )
    })?;

    for entry_res in read_dir {
        let entry = entry_res.map_err(|e| {
            format!(
                "Fail-closed scan: failed reading directory entry in '{}': {e}",
                dir.display()
            )
        })?;
        files.push(entry.file_name().to_string_lossy().to_string());
    }

    Ok(files)
}

/// Helper to read all lines of detail from `EXPLAIN QUERY PLAN`.
pub fn get_explain_query_plan(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .expect("prepare explain query plan");
    stmt.query_map([], |row| row.get::<_, String>(3))
        .expect("query explain query plan")
        .map(|r| r.expect("read explain detail"))
        .collect()
}

// ============================================================================
// 5. PARSER UNIT REGRESSION TESTS (11 DISTINCT CONDITIONS)
// ============================================================================

#[test]
fn test_parser_1_single_valid_record() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset = 0
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes()); // Action = 1
    let name_utf16: Vec<u16> = "test_file.txt".encode_utf16().collect();
    let name_len = (name_utf16.len() * 2) as u32;
    buf.extend_from_slice(&name_len.to_le_bytes()); // FileNameLength
    for w in &name_utf16 {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    let events = parse_file_notify_records(&buf, buf.len()).expect("parse valid single record");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, FILE_ACTION_ADDED);
    assert_eq!(events[0].action_name, "ADDED");
    assert_eq!(events[0].file_name, "test_file.txt");
}

#[test]
fn test_parser_2_multiple_valid_records_with_alignment() {
    let mut buf = Vec::new();

    // Record 1: "a.txt" -> UTF-16 is 5 chars = 10 bytes.
    // Total record length = 12 + 10 = 22 bytes. Aligns to next multiple of 4 = 24 bytes.
    let r1_name: Vec<u16> = "a.txt".encode_utf16().collect();
    buf.extend_from_slice(&24u32.to_le_bytes()); // NextEntryOffset = 24
    buf.extend_from_slice(&FILE_ACTION_MODIFIED.to_le_bytes()); // Action = MODIFIED
    buf.extend_from_slice(&((r1_name.len() * 2) as u32).to_le_bytes());
    for w in &r1_name {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf.extend_from_slice(&[0u8, 0u8]); // 2 bytes padding to reach 24 bytes
    assert_eq!(buf.len(), 24);

    // Record 2: "b.txt" -> Last entry (NextEntryOffset = 0)
    let r2_name: Vec<u16> = "b.txt".encode_utf16().collect();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&FILE_ACTION_REMOVED.to_le_bytes()); // Action = REMOVED
    buf.extend_from_slice(&((r2_name.len() * 2) as u32).to_le_bytes());
    for w in &r2_name {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    let events = parse_file_notify_records(&buf, buf.len()).expect("parse multiple records");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].file_name, "a.txt");
    assert_eq!(events[0].action_name, "MODIFIED");
    assert_eq!(events[1].file_name, "b.txt");
    assert_eq!(events[1].action_name, "REMOVED");
}

#[test]
fn test_parser_3_rejects_truncated_header() {
    let buf = vec![0u8; 8]; // Less than min_header_size (12 bytes)
    let err = parse_file_notify_records(&buf, buf.len()).unwrap_err();
    assert!(err.contains("Truncated record header"));
}

#[test]
fn test_parser_4_rejects_odd_filename_length() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&7u32.to_le_bytes()); // Odd length (7 bytes)
    buf.extend_from_slice(&[0u8; 8]);

    let err = parse_file_notify_records(&buf, buf.len()).unwrap_err();
    assert!(err.contains("Invalid odd FileNameLength"));
}

#[test]
fn test_parser_5_rejects_overflowing_filename() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&100u32.to_le_bytes()); // Transferred has only 12 bytes

    let err = parse_file_notify_records(&buf, 12).unwrap_err();
    assert!(err.contains("overflows transferred bytes"));
}

#[test]
fn test_parser_6_rejects_unaligned_next_entry_offset() {
    let mut buf = Vec::new();
    let name: Vec<u16> = "x.txt".encode_utf16().collect();
    buf.extend_from_slice(&23u32.to_le_bytes()); // Not a multiple of 4
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for w in &name {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf.extend_from_slice(&[0u8; 32]);

    let err = parse_file_notify_records(&buf, buf.len()).unwrap_err();
    assert!(err.contains("is not 4-byte aligned"));
}

#[test]
fn test_parser_7_rejects_next_offset_smaller_than_record() {
    let mut buf = Vec::new();
    let name: Vec<u16> = "test.txt".encode_utf16().collect();
    buf.extend_from_slice(&8u32.to_le_bytes()); // Less than 12 + 16 = 28 bytes
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for w in &name {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf.extend_from_slice(&[0u8; 32]);

    let err = parse_file_notify_records(&buf, buf.len()).unwrap_err();
    assert!(err.contains("is smaller than minimum record length"));
}

#[test]
fn test_parser_8_rejects_next_offset_exactly_at_buffer_end() {
    let mut buf = Vec::new();
    let name: Vec<u16> = "test.txt".encode_utf16().collect();
    // 12 header + 16 filename = 28 bytes total.
    buf.extend_from_slice(&28u32.to_le_bytes()); // Points exactly to offset 28
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for w in &name {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(buf.len(), 28);

    // bytes_transferred is 28, so next record start = 28 leaves 0 bytes (need at least 12 bytes header)
    let err = parse_file_notify_records(&buf, 28).unwrap_err();
    assert!(err.contains("leaves only 0 bytes"));
}

#[test]
fn test_parser_9_rejects_next_offset_beyond_buffer() {
    let mut buf = Vec::new();
    let name: Vec<u16> = "test.txt".encode_utf16().collect();
    buf.extend_from_slice(&64u32.to_le_bytes()); // Points beyond transferred 28 bytes
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for w in &name {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(buf.len(), 28);

    let err = parse_file_notify_records(&buf, 28).unwrap_err();
    assert!(err.contains("exceeds transferred bytes"));
}

#[test]
fn test_parser_10_rejects_bytes_transferred_beyond_capacity() {
    let buf = vec![0u8; 16];
    let err = parse_file_notify_records(&buf, 32).unwrap_err();
    assert!(err.contains("exceeds buffer capacity"));
}

#[test]
fn test_parser_11_rejects_large_offset_overflow() {
    let mut buf = Vec::new();
    let name: Vec<u16> = "a.txt".encode_utf16().collect();
    buf.extend_from_slice(&0xFFFFFFFCu32.to_le_bytes()); // Aligned large u32 near boundary
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for w in &name {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    let err = parse_file_notify_records(&buf, buf.len()).unwrap_err();
    assert!(err.contains("exceeds transferred bytes") || err.contains("overflow"));
}

// ============================================================================
// 6. BUNDLED SQLITE RUNTIME & IN-MEMORY PRAGMA ASSERTIONS
// ============================================================================

#[test]
fn test_sqlite_bundled_runtime_identity_and_compile_options() {
    let db = InMemoryDb::create_empty().expect("create empty in-memory db");
    let conn = db.conn().expect("acquire db conn");

    let version: String = conn
        .query_row("SELECT sqlite_version();", [], |row| row.get(0))
        .expect("query sqlite_version");
    let source_id: String = conn
        .query_row("SELECT sqlite_source_id();", [], |row| row.get(0))
        .expect("query sqlite_source_id");

    println!("\n=======================================================");
    println!("TASK 4.8 SQLITE RUNTIME IDENTITY AUDIT");
    println!("=======================================================");
    println!("SQLite Version:   {version}");
    println!("SQLite Source ID: {source_id}");

    // Audit PRAGMA compile_options
    let mut stmt = conn
        .prepare("PRAGMA compile_options;")
        .expect("prepare compile_options");
    let options: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("query compile_options")
        .map(|r| r.expect("row option"))
        .collect();

    println!("Total compile options: {}", options.len());
    let temp_store_opt = options
        .iter()
        .find(|opt| opt.starts_with("TEMP_STORE="))
        .cloned()
        .unwrap_or_else(|| "NONE".to_string());
    println!("TEMP_STORE compile option: \"{temp_store_opt}\"");

    assert!(
        temp_store_opt != "TEMP_STORE=0",
        "SQLite compile options must not disable temp_store override (got: {temp_store_opt})"
    );

    // Audit PRAGMA settings
    let temp_store: i64 = conn
        .query_row("PRAGMA temp_store;", [], |row| row.get(0))
        .expect("query PRAGMA temp_store");
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .expect("query PRAGMA journal_mode");
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .expect("query PRAGMA foreign_keys");
    let cache_spill: i64 = conn
        .query_row("PRAGMA cache_spill;", [], |row| row.get(0))
        .expect("query PRAGMA cache_spill");

    println!("-------------------------------------------------------");
    println!("PRAGMA temp_store:   {temp_store} (Expected: 2 = MEMORY)");
    println!("PRAGMA journal_mode: {journal_mode} (Expected: memory)");
    println!("PRAGMA foreign_keys: {foreign_keys} (Expected: 1 = ON)");
    println!("PRAGMA cache_spill:  {cache_spill}");
    println!("-------------------------------------------------------");

    assert_eq!(
        temp_store, 2,
        "PRAGMA temp_store must evaluate to 2 (MEMORY)"
    );
    assert_eq!(
        journal_mode.to_lowercase(),
        "memory",
        "PRAGMA journal_mode must be 'memory'"
    );
    assert_eq!(foreign_keys, 1, "PRAGMA foreign_keys must be 1 (ON)");

    // Audit PRAGMA database_list
    let mut db_list_stmt = conn
        .prepare("PRAGMA database_list;")
        .expect("prepare database_list");
    let databases: Vec<(i64, String, String)> = db_list_stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query database_list")
        .map(|r| r.expect("read db row"))
        .collect();

    println!("PRAGMA database_list:");
    for (seq, name, file) in &databases {
        println!(" - seq={seq}, name='{name}', file='{file}'");
        if name == "main" || name == "temp" {
            assert!(
                file.is_empty(),
                "Database '{name}' must have empty backing file for in-memory database, got '{file}'"
            );
        }
    }
    println!("=======================================================\n");
}

#[test]
fn test_both_constructors_enforce_in_memory_pragmas() {
    // 1. Validate InMemoryDb::create_empty()
    let empty_db = InMemoryDb::create_empty().expect("create empty in-memory db");
    assert_in_memory_pragmas(&empty_db, "InMemoryDb::create_empty");

    // 2. Validate InMemoryDb::from_image()
    let serialized = empty_db.to_image().expect("serialize empty db image");
    let restored_db =
        InMemoryDb::from_image(&serialized).expect("restore in-memory db from valid image");
    assert_in_memory_pragmas(&restored_db, "InMemoryDb::from_image");
}

fn assert_in_memory_pragmas(db: &InMemoryDb, constructor_name: &str) {
    let conn = db.conn().expect("acquire db conn");

    let temp_store: i64 = conn
        .query_row("PRAGMA temp_store;", [], |row| row.get(0))
        .expect("query PRAGMA temp_store");
    assert_eq!(
        temp_store, 2,
        "PRAGMA temp_store must be 2 (MEMORY) for {constructor_name}"
    );

    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .expect("query PRAGMA journal_mode");
    assert_eq!(
        journal_mode.to_lowercase(),
        "memory",
        "PRAGMA journal_mode must be 'memory' for {constructor_name}"
    );

    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .expect("query PRAGMA foreign_keys");
    assert_eq!(
        foreign_keys, 1,
        "PRAGMA foreign_keys must be 1 for {constructor_name}"
    );

    let db_file: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main';",
            [],
            |row| row.get(0),
        )
        .expect("query database_list file");
    assert!(
        db_file.is_empty(),
        "Database file backing path must be empty string for {constructor_name}, got: '{db_file}'"
    );
}

// ============================================================================
// 7. POSITIVE CONTROL: FULL LIFECYCLE EVENT VERIFICATION WITH BOUNDED POLLING
// ============================================================================

#[test]
fn test_windows_watcher_positive_control_calibration() {
    // Acquire serialization lock to prevent concurrent observation of %TEMP%
    let _guard = TEMP_WATCHER_SERIALIZATION_LOCK.lock().unwrap();

    let sqlite_temp_dir =
        get_effective_sqlite_temp_path().expect("resolve effective SQLite temp dir");
    println!(
        "\nStarting positive-control calibration in: {}",
        sqlite_temp_dir.display()
    );

    let watcher =
        DirectoryWatcher::start(&sqlite_temp_dir).expect("start watcher on SQLite temp dir");
    thread::sleep(Duration::from_millis(50));
    watcher.assert_healthy("after positive control start");

    // Positive control filenames specifically designed NOT to match SQLite candidate filters
    let unique_id = uuid::Uuid::new_v4();
    let control_file_name = format!("kivault_pos_control_{unique_id}.txt");
    let renamed_file_name = format!("kivault_pos_control_{unique_id}_renamed.txt");

    // Assert that positive control files do not collide with SQLite candidate classification
    assert!(!is_sqlite_candidate_file(&control_file_name));
    assert!(!is_sqlite_candidate_file(&renamed_file_name));

    let control_file = sqlite_temp_dir.join(&control_file_name);
    let renamed_file = sqlite_temp_dir.join(&renamed_file_name);

    // 1. ADDED event: create control file and poll with deadline
    fs::write(&control_file, b"positive_control_step_1_create").expect("write control file");
    poll_until_event(
        &watcher,
        &control_file_name,
        FILE_ACTION_ADDED,
        Duration::from_millis(3000),
        "FILE_ACTION_ADDED",
    );
    watcher.assert_healthy("after verified ADDED event");

    // 2. MODIFIED event: modify control file and poll with deadline
    fs::write(&control_file, b"positive_control_step_2_modify").expect("modify control file");
    poll_until_event(
        &watcher,
        &control_file_name,
        FILE_ACTION_MODIFIED,
        Duration::from_millis(3000),
        "FILE_ACTION_MODIFIED",
    );
    watcher.assert_healthy("after verified MODIFIED event");

    // 3. RENAMED_OLD and RENAMED_NEW: rename file and poll with deadline
    fs::rename(&control_file, &renamed_file).expect("rename control file");
    poll_until_event(
        &watcher,
        &control_file_name,
        FILE_ACTION_RENAMED_OLD_NAME,
        Duration::from_millis(3000),
        "FILE_ACTION_RENAMED_OLD_NAME",
    );
    poll_until_event(
        &watcher,
        &renamed_file_name,
        FILE_ACTION_RENAMED_NEW_NAME,
        Duration::from_millis(3000),
        "FILE_ACTION_RENAMED_NEW_NAME",
    );
    watcher.assert_healthy("after verified RENAMED events");

    // 4. REMOVED event: delete renamed file and poll with deadline
    fs::remove_file(&renamed_file).expect("remove control file");
    poll_until_event(
        &watcher,
        &renamed_file_name,
        FILE_ACTION_REMOVED,
        Duration::from_millis(3000),
        "FILE_ACTION_REMOVED",
    );
    watcher.assert_healthy("after verified REMOVED event");

    let (events, overflow) = watcher.stop().expect("stop positive control watcher");
    assert!(
        !overflow,
        "Watcher must not overflow during positive control"
    );

    // Verify all 5 events recorded in final event collection
    let has_add = events
        .iter()
        .any(|e| e.file_name == control_file_name && e.action == FILE_ACTION_ADDED);
    let has_mod = events
        .iter()
        .any(|e| e.file_name == control_file_name && e.action == FILE_ACTION_MODIFIED);
    let has_ren_old = events
        .iter()
        .any(|e| e.file_name == control_file_name && e.action == FILE_ACTION_RENAMED_OLD_NAME);
    let has_ren_new = events
        .iter()
        .any(|e| e.file_name == renamed_file_name && e.action == FILE_ACTION_RENAMED_NEW_NAME);
    let has_rem = events
        .iter()
        .any(|e| e.file_name == renamed_file_name && e.action == FILE_ACTION_REMOVED);

    assert!(has_add, "Missing confirmed FILE_ACTION_ADDED");
    assert!(has_mod, "Missing confirmed FILE_ACTION_MODIFIED");
    assert!(
        has_ren_old,
        "Missing confirmed FILE_ACTION_RENAMED_OLD_NAME"
    );
    assert!(
        has_ren_new,
        "Missing confirmed FILE_ACTION_RENAMED_NEW_NAME"
    );
    assert!(has_rem, "Missing confirmed FILE_ACTION_REMOVED");

    // Cleanup assertions
    assert!(!control_file.exists());
    assert!(!renamed_file.exists());
    println!("Positive-control calibration passed: all 5 actions verified via bounded polling.");
}

fn poll_until_event(
    watcher: &DirectoryWatcher,
    target_file: &str,
    target_action: u32,
    timeout: Duration,
    action_name: &str,
) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        watcher.assert_healthy(&format!("polling for {action_name}"));
        let evs = watcher.events();
        if evs
            .iter()
            .any(|e| e.file_name == target_file && e.action == target_action)
        {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("Timed out waiting for {action_name} on file '{target_file}' after {timeout:?}");
}

// ============================================================================
// 8. RUNTIME STRESS TEST WITH ACTIVE FILESYSTEM OBSERVATION & QUERY PLAN PROOF
// ============================================================================

#[test]
fn test_sqlite_temporary_storage_stress_with_active_watcher() {
    // Acquire serialization lock to prevent concurrent observation of %TEMP%
    let _guard = TEMP_WATCHER_SERIALIZATION_LOCK.lock().unwrap();

    let sqlite_temp_dir =
        get_effective_sqlite_temp_path().expect("resolve effective SQLite temp dir");
    println!("\n=======================================================");
    println!("TASK 4.8 EFFECTIVE SQLITE TEMPORARY DIRECTORY");
    println!("=======================================================");
    println!("Monitored Directory: {}", sqlite_temp_dir.display());

    // Fail-closed baseline scan of candidate temporary files in %TEMP%
    let baseline_candidates: Vec<String> = scan_directory_fail_closed(&sqlite_temp_dir)
        .expect("fail-closed baseline scan of temporary directory")
        .into_iter()
        .filter(|name| is_sqlite_candidate_file(name))
        .collect();

    println!(
        "Baseline SQLite candidate files in %TEMP%: {}",
        baseline_candidates.len()
    );

    // Start Windows native directory watcher directly on effective SQLite temp dir
    let watcher = DirectoryWatcher::start(&sqlite_temp_dir)
        .expect("start directory watcher on SQLite temp dir");
    thread::sleep(Duration::from_millis(50));
    watcher.assert_healthy("checkpoint 1: after watcher start");

    // Open production in-memory database
    let mut db = InMemoryDb::create_empty().expect("create_empty in-memory db");
    watcher.assert_healthy("checkpoint 2: after InMemoryDb::create_empty");

    // STRESS WORKLOAD A: Large TEMP table and TEMP index (20,000 synthetic rows, ~8-12 MiB payload)
    println!("\nExecuting Workload A: Large TEMP table & TEMP index (20,000 rows)...");
    {
        let conn = db.conn_mut().expect("get mut connection");

        // Explicitly create TEMP TABLE and TEMP INDEX on the temp schema
        conn.execute_batch(
            "CREATE TEMP TABLE temp_stress_accounts (
                id TEXT PRIMARY KEY,
                account_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                category TEXT,
                score INTEGER NOT NULL
            );
            CREATE INDEX temp.temp_idx_category_score ON temp_stress_accounts (category, score DESC);",
        )
        .expect("create TEMP table & index");
        watcher.assert_healthy("checkpoint 3: after TEMP table and index creation");

        // Verify table resides in temporary schema (sqlite_temp_master) and NOT in main sqlite_master
        let in_temp_master: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE type = 'table' AND name = 'temp_stress_accounts';",
                [],
                |row| row.get(0),
            )
            .expect("check sqlite_temp_master");
        assert_eq!(
            in_temp_master, 1,
            "temp_stress_accounts MUST reside in sqlite_temp_master"
        );

        let in_main_master: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'temp_stress_accounts';",
                [],
                |row| row.get(0),
            )
            .expect("check sqlite_master");
        assert_eq!(
            in_main_master, 0,
            "temp_stress_accounts MUST NOT reside in main sqlite_master"
        );

        // Verify PRAGMA database_list confirms both main and temp schemas have empty backing paths
        {
            let mut db_list_stmt = conn
                .prepare("PRAGMA database_list;")
                .expect("prepare database_list");
            let dbs: Vec<(String, String)> = db_list_stmt
                .query_map([], |row| Ok((row.get(1)?, row.get(2)?)))
                .expect("query db list")
                .map(|r| r.expect("read db row"))
                .collect();
            for (name, path) in &dbs {
                if name == "main" || name == "temp" {
                    assert!(
                        path.is_empty(),
                        "Schema '{name}' backing file must be empty, found: '{path}'"
                    );
                }
            }
        }

        // Insert 20,000 synthetic rows inside an explicit transaction
        {
            let tx = conn.transaction().expect("begin transaction");
            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO temp_stress_accounts (id, account_name, username, encrypted_payload, category, score)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
                    )
                    .expect("prepare insert");

                let synthetic_blob = vec![0x42u8; 384]; // ~384 bytes payload per row
                for i in 0..20_000 {
                    let id = format!("acc-stress-{i:06}");
                    let acc_name = format!("Account Synthetic Name {:06}", i);
                    let username = format!("user_{:06}@kivault-stress.local", i);
                    let category = match i % 5 {
                        0 => "Finance",
                        1 => "Social",
                        2 => "Work",
                        3 => "Personal",
                        _ => "Cloud",
                    };
                    let score = (i * 17) % 10000;

                    stmt.execute(rusqlite::params![
                        id,
                        acc_name,
                        username,
                        synthetic_blob.as_slice(),
                        category,
                        score
                    ])
                    .expect("insert row into temp table");
                }
            }
            tx.commit().expect("commit transaction");
        }
    }
    watcher.assert_healthy("checkpoint 4: after 20,000-row insertion");

    // Verify row count
    {
        let conn = db.conn().expect("get connection");
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM temp_stress_accounts;", [], |row| {
                row.get(0)
            })
            .expect("count rows");
        assert_eq!(row_count, 20_000);
        println!("Inserted {} rows into TEMP table successfully.", row_count);

        // STRESS WORKLOAD B: Complex queries proving ORDER BY, GROUP BY, DISTINCT, and CTE Materialization
        println!("\nExecuting Workload B: Temporary B-Tree & Materialization Verification...");

        // 1. ORDER BY on unindexed column (username) -> Requires temporary B-tree
        let order_by_sql =
            "SELECT id, username FROM temp_stress_accounts ORDER BY username LIMIT 10;";
        let order_by_plan = get_explain_query_plan(conn, order_by_sql);
        println!("\nORDER BY Query Plan Details:");
        for p in &order_by_plan {
            println!("   [Plan] {}", p);
        }
        assert!(
            order_by_plan
                .iter()
                .any(|line| line.contains("USE TEMP B-TREE FOR ORDER BY")),
            "EXPLAIN QUERY PLAN must confirm temporary B-tree for ORDER BY: {:?}",
            order_by_plan
        );
        let mut order_stmt = conn.prepare(order_by_sql).expect("prepare order query");
        let order_rows: Vec<String> = order_stmt
            .query_map([], |row| row.get(1))
            .expect("query order")
            .map(|r| r.expect("read username"))
            .collect();
        assert_eq!(order_rows.len(), 10);

        // 2. GROUP BY on unindexed column (username) -> Requires temporary B-tree
        let group_by_sql =
            "SELECT username, COUNT(*) FROM temp_stress_accounts GROUP BY username LIMIT 10;";
        let group_by_plan = get_explain_query_plan(conn, group_by_sql);
        println!("\nGROUP BY Query Plan Details:");
        for p in &group_by_plan {
            println!("   [Plan] {}", p);
        }
        assert!(
            group_by_plan
                .iter()
                .any(|line| line.contains("USE TEMP B-TREE FOR GROUP BY")),
            "EXPLAIN QUERY PLAN must confirm temporary B-tree for GROUP BY: {:?}",
            group_by_plan
        );
        let mut group_stmt = conn.prepare(group_by_sql).expect("prepare group query");
        let group_rows: Vec<(String, i64)> = group_stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query group")
            .map(|r| r.expect("read group"))
            .collect();
        assert_eq!(group_rows.len(), 10);

        // 3. DISTINCT on unindexed column (username) -> Requires temporary B-tree
        let distinct_sql = "SELECT DISTINCT username FROM temp_stress_accounts LIMIT 10;";
        let distinct_plan = get_explain_query_plan(conn, distinct_sql);
        println!("\nDISTINCT Query Plan Details:");
        for p in &distinct_plan {
            println!("   [Plan] {}", p);
        }
        assert!(
            distinct_plan
                .iter()
                .any(|line| line.contains("USE TEMP B-TREE FOR DISTINCT")),
            "EXPLAIN QUERY PLAN must confirm temporary B-tree for DISTINCT: {:?}",
            distinct_plan
        );
        let mut distinct_stmt = conn.prepare(distinct_sql).expect("prepare distinct query");
        let distinct_rows: Vec<String> = distinct_stmt
            .query_map([], |row| row.get(0))
            .expect("query distinct")
            .map(|r| r.expect("read distinct"))
            .collect();
        assert_eq!(distinct_rows.len(), 10);

        // 4. Explicit AS MATERIALIZED CTE
        let cte_sql = "WITH cte_accounts AS MATERIALIZED (
            SELECT id, username, score FROM temp_stress_accounts WHERE score > 500
        )
        SELECT COUNT(*), SUM(score) FROM cte_accounts WHERE score < 1500;";
        let cte_plan = get_explain_query_plan(conn, cte_sql);
        println!("\nCTE MATERIALIZED Query Plan Details:");
        for p in &cte_plan {
            println!("   [Plan] {}", p);
        }
        assert!(
            cte_plan.iter().any(|line| line.starts_with("MATERIALIZE")),
            "EXPLAIN QUERY PLAN must confirm CTE materialization: {:?}",
            cte_plan
        );
        let (cte_cnt, cte_sum): (i64, i64) = conn
            .query_row(cte_sql, [], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("execute cte query");
        assert!(cte_cnt > 0);
        assert!(cte_sum > 0);
        println!(
            "CTE Materialized Result: count={}, sum={}",
            cte_cnt, cte_sum
        );
    }
    watcher.assert_healthy("checkpoint 5: after query plan workloads");

    // STRESS WORKLOAD C: Transaction rollback verification with journal_mode = MEMORY
    println!("\nExecuting Workload C: Transaction rollback verification...");
    {
        let conn = db.conn_mut().expect("get mut connection");
        {
            let tx = conn.transaction().expect("begin transaction for rollback");
            tx.execute(
                "DELETE FROM temp_stress_accounts WHERE category = 'Finance';",
                [],
            )
            .expect("delete inside tx");

            let in_tx_count: i64 = tx
                .query_row("SELECT COUNT(*) FROM temp_stress_accounts;", [], |row| {
                    row.get(0)
                })
                .expect("count inside tx");
            assert_eq!(in_tx_count, 16_000);

            // Explicit rollback
            tx.rollback().expect("rollback transaction");
        }

        // Verify state restored completely after rollback
        let restored_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM temp_stress_accounts;", [], |row| {
                row.get(0)
            })
            .expect("count after rollback");
        assert_eq!(
            restored_count, 20_000,
            "Transaction rollback must restore all rows under journal_mode=MEMORY"
        );
        println!(
            "Rollback verified: row count fully restored to {}.",
            restored_count
        );
    }
    watcher.assert_healthy("checkpoint 6: after rollback");

    // STRESS WORKLOAD D: Serialize in-memory database to verify clean image generation
    let image = db.to_image().expect("serialize in-memory db to image");
    assert!(image.len() > 100);
    assert!(image.starts_with(b"SQLite format 3\0"));
    println!(
        "\nDatabase image serialized cleanly ({} bytes).",
        image.len()
    );
    watcher.assert_healthy("checkpoint 7: after serialization");

    // Clean drop of database
    drop(db);

    // Allow brief grace period for any lingering filesystem events
    thread::sleep(Duration::from_millis(150));
    watcher.assert_healthy("checkpoint 8: after database drop");

    // STOP WATCHER AND EVALUATE FILESYSTEM EVENTS
    let (events, overflow) = watcher.stop().expect("stop watcher without errors");
    assert!(
        !overflow,
        "CRITICAL ERROR: Directory watcher overflowed (events lost)"
    );

    println!("\n=======================================================");
    println!("TASK 4.8 FILESYSTEM MONITORING RESULTS ON %TEMP%");
    println!("=======================================================");
    println!("Monitored Directory: {}", sqlite_temp_dir.display());
    println!("Total Captured Events in %TEMP%: {}", events.len());

    let mut sqlite_candidate_events = Vec::new();
    for ev in &events {
        if is_sqlite_candidate_file(&ev.file_name) {
            sqlite_candidate_events.push(ev.clone());
            println!(
                " [!] SQLite Candidate Event: {:<12} File: {}",
                ev.action_name, ev.file_name
            );
        }
    }

    // CRITICAL ACCEPTANCE INVARIANT:
    // Zero SQLite file creation, journal, WAL, SHM, or etilqs_* events must be produced by production SQLite.
    assert!(
        sqlite_candidate_events.is_empty(),
        "FATAL INVARIANT VIOLATION: SQLite produced temporary or spill files on disk: {:?}",
        sqlite_candidate_events
    );

    println!("SQLite candidate events detected: 0");

    // FAIL-CLOSED POST-TEST SCAN FOR LEFTOVER CANDIDATES IN %TEMP%
    let post_test_all = scan_directory_fail_closed(&sqlite_temp_dir)
        .expect("fail-closed post-test scan of temporary directory");

    let post_test_candidates: Vec<String> = post_test_all
        .into_iter()
        .filter(|name| is_sqlite_candidate_file(name) && !baseline_candidates.contains(name))
        .collect();

    assert!(
        post_test_candidates.is_empty(),
        "Leftover SQLite candidate temporary files found in %TEMP%: {:?}",
        post_test_candidates
    );
    println!("Post-test SQLite candidate scan in %TEMP%: 0 leftover files.");
    println!("=======================================================\n");
}

// ============================================================================
// BLOCKER-A REGRESSION: No CancelIoEx in stop() or Drop; worker is sole owner
// ============================================================================

/// Verifies that stop() completes successfully without calling CancelIoEx from stop() or Drop.
///
/// The worker detects the stop_signal in its bounded poll loop, calls CancelIoEx on its
/// own OVERLAPPED, drains completion, and exits. stop() only sets the signal, joins, and
/// closes handles. If the worker's self-cancellation is broken, this test would hang until
/// the test harness times out.
#[test]
fn test_watcher_stop_does_not_call_broad_cancelioex() {
    let _lock = TEMP_WATCHER_SERIALIZATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let temp_dir = get_effective_sqlite_temp_path()
        .expect("resolve effective sqlite temp path for cancellation ownership test");

    let watcher =
        DirectoryWatcher::start(&temp_dir).expect("start watcher for cancellation ownership test");

    watcher.assert_healthy("after start â€” cancellation ownership test");

    // stop() sets stop_signal only. The worker detects it within <= 50ms, cancels its own
    // OVERLAPPED, and exits. stop() then joins and closes handles.
    let result = watcher.stop();
    assert!(
        result.is_ok(),
        "stop() must succeed; worker self-cancellation failed: {:?}",
        result.err()
    );
}

/// Verifies that Drop performs cleanup without broad CancelIoEx.
///
/// When a DirectoryWatcher is dropped without calling stop(), Drop sets the stop_signal,
/// joins the worker (which performs self-cancellation), then closes handles.
#[test]
fn test_watcher_drop_without_stop_cleans_up_safely() {
    let _lock = TEMP_WATCHER_SERIALIZATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let temp_dir = get_effective_sqlite_temp_path()
        .expect("resolve effective sqlite temp path for drop-without-stop test");

    // Drop the watcher immediately without calling stop()
    let watcher = DirectoryWatcher::start(&temp_dir).expect("start watcher for drop test");
    watcher.assert_healthy("before implicit drop â€” drop-without-stop test");
    drop(watcher);
    // If we reach here without a panic or hang, Drop cleaned up correctly.
}

// ============================================================================
// FIX-B REGRESSION: Single-close ownership via injectable close_handles_with
// ============================================================================

/// Verifies that close_handles_with() calls the closer exactly twice for two owned handles,
/// and zero times on retry — using an atomic attempt counter injected via the closure.
///
/// Does NOT pass fake Win32 handles to CloseHandle. The injectable closure counts attempts;
/// the production close_handles() wrapping real CloseHandle is exercised by lifecycle tests.
#[test]
fn test_close_handles_with_counts_attempts_exactly() {
    use std::sync::atomic::AtomicUsize;
    let attempt_count = Arc::new(AtomicUsize::new(0));

    let mut handle_usize: Option<usize> = Some(0x1001);
    let mut event_usize: Option<usize> = Some(0x1002);

    let count_clone = Arc::clone(&attempt_count);
    let result = close_handles_with(&mut handle_usize, &mut event_usize, |_raw| {
        count_clone.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    assert!(
        result.is_ok(),
        "close_handles_with must return Ok when closer succeeds"
    );
    assert_eq!(
        attempt_count.load(Ordering::SeqCst),
        2,
        "closer must be called exactly twice for two owned handles"
    );
    assert!(
        handle_usize.is_none(),
        "handle_usize must be None after first call"
    );
    assert!(
        event_usize.is_none(),
        "event_usize must be None after first call"
    );

    // Second call: both options are None — closer must NOT be called again.
    let count_clone2 = Arc::clone(&attempt_count);
    let result2 = close_handles_with(&mut handle_usize, &mut event_usize, |_raw| {
        count_clone2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    assert!(
        result2.is_ok(),
        "second call on None options must return Ok"
    );
    assert_eq!(
        attempt_count.load(Ordering::SeqCst),
        2,
        "closer must NOT be called again when both options are already None"
    );
}

/// Verifies that close_handles_with() attempts BOTH handles even when the first fails,
/// accumulates all errors, and sets both Option fields to None regardless.
#[test]
fn test_close_handles_with_attempts_both_on_first_error() {
    use std::sync::atomic::AtomicUsize;
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let call_num = Arc::new(AtomicUsize::new(0));

    let mut handle_usize: Option<usize> = Some(0x2001);
    let mut event_usize: Option<usize> = Some(0x2002);

    let count_clone = Arc::clone(&attempt_count);
    let call_clone = Arc::clone(&call_num);

    let result = close_handles_with(&mut handle_usize, &mut event_usize, |_raw| {
        count_clone.fetch_add(1, Ordering::SeqCst);
        let n = call_clone.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Err("simulated CloseHandle error on first handle".to_string())
        } else {
            Ok(())
        }
    });

    assert!(
        result.is_err(),
        "must return Err when at least one close fails"
    );
    assert_eq!(
        attempt_count.load(Ordering::SeqCst),
        2,
        "closer must be called for BOTH handles even when the first fails"
    );
    assert!(
        handle_usize.is_none(),
        "handle_usize must be None regardless of close error"
    );
    assert!(
        event_usize.is_none(),
        "event_usize must be None regardless of close error"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("simulated CloseHandle error"),
        "error must include close failure detail: '{err_msg}'"
    );
}
// ============================================================================
// BLOCKER-B REGRESSION: worker_failed atomic is independently observable
// ============================================================================

/// Verifies that process_drain_completion() propagates a parse error to both
/// worker_failed and worker_error when given a malformed buffer.
///
/// This exercises the exact same helper called by the production worker on the
/// cancellation drain path, so it proves the production logic â€” not a copy.
#[test]
fn test_drain_completion_parse_error_sets_worker_failed() {
    let events: Arc<Mutex<Vec<CapturedFileEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let worker_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let worker_failed = Arc::new(AtomicBool::new(false));

    // Malformed buffer: FileNameLength = 200 but only 12 bytes of content.
    let mut buf = vec![0u8; 12];
    // NextEntryOffset = 0, Action = ADDED, FileNameLength = 200 (overflows)
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4..8].copy_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    buf[8..12].copy_from_slice(&200u32.to_le_bytes());

    process_drain_completion(&buf, 12, &events, &worker_error, &worker_failed);

    assert!(
        worker_failed.load(Ordering::SeqCst),
        "worker_failed must be set after parse error in process_drain_completion"
    );
    let err_msg = worker_error
        .lock()
        .expect("worker_error mutex must not be poisoned in this test")
        .clone()
        .expect("worker_error must contain a descriptive message after parse failure");
    assert!(
        err_msg.contains("cancellation drain"),
        "error message must mention 'cancellation drain', got: '{err_msg}'"
    );
    assert!(
        err_msg.contains("Parser failure"),
        "error message must mention 'Parser failure', got: '{err_msg}'"
    );
}

/// Verifies that process_drain_completion() successfully collects valid events.
///
/// Uses a well-formed single-record buffer and confirms events are appended
/// without setting worker_failed.
#[test]
fn test_drain_completion_valid_buffer_collects_events() {
    let events: Arc<Mutex<Vec<CapturedFileEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let worker_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let worker_failed = Arc::new(AtomicBool::new(false));

    // Build a valid single-record buffer for "drain_test.txt"
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset = 0
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    let name_utf16: Vec<u16> = "drain_test.txt".encode_utf16().collect();
    buf.extend_from_slice(&((name_utf16.len() * 2) as u32).to_le_bytes());
    for w in &name_utf16 {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    process_drain_completion(&buf, buf.len(), &events, &worker_error, &worker_failed);

    assert!(
        !worker_failed.load(Ordering::SeqCst),
        "worker_failed must NOT be set after a successful drain completion"
    );
    let collected = events
        .lock()
        .expect("events mutex must not be poisoned")
        .clone();
    assert_eq!(collected.len(), 1, "exactly 1 event must be collected");
    assert_eq!(collected[0].file_name, "drain_test.txt");
    assert_eq!(collected[0].action_name, "ADDED");
}

/// Verifies that process_drain_completion() marks failure when the events mutex is poisoned.
///
/// A thread panics while holding the events mutex, poisoning it. The helper must set
/// worker_failed and record an error rather than silently discarding the events.
#[test]
fn test_drain_completion_poisoned_events_mutex_marks_failed() {
    let events: Arc<Mutex<Vec<CapturedFileEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let worker_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let worker_failed = Arc::new(AtomicBool::new(false));

    // Poison the events mutex
    let events_clone_for_poison = Arc::clone(&events);
    let _ = thread::spawn(move || {
        let _guard = events_clone_for_poison.lock().unwrap();
        panic!("deliberate poison for test_drain_completion_poisoned_events_mutex_marks_failed");
    })
    .join(); // Join to ensure the panic has occurred before we proceed

    assert!(
        events.is_poisoned(),
        "events mutex must be poisoned at this point"
    );

    // Build a valid record so the parse succeeds â€” the failure must come from mutex poisoning
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&FILE_ACTION_ADDED.to_le_bytes());
    let name_utf16: Vec<u16> = "poison_test.txt".encode_utf16().collect();
    buf.extend_from_slice(&((name_utf16.len() * 2) as u32).to_le_bytes());
    for w in &name_utf16 {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    process_drain_completion(&buf, buf.len(), &events, &worker_error, &worker_failed);

    assert!(
        worker_failed.load(Ordering::SeqCst),
        "worker_failed must be set when events mutex is poisoned"
    );
    let err_msg = worker_error
        .lock()
        .expect("worker_error must not be poisoned in this test")
        .clone()
        .expect("worker_error must contain a descriptive message after mutex poisoning");
    assert!(
        err_msg.contains("mutex poisoned"),
        "error message must mention 'mutex poisoned', got: '{err_msg}'"
    );
}

// ============================================================================
// BLOCKER-B REGRESSION: worker_error mutex poisoning is itself fail-closed
// ============================================================================

/// Verifies that record_worker_error() can record an error even through a poisoned mutex.
///
/// The function uses `into_inner()` to recover the poisoned state and overwrite the value.
/// After calling record_worker_error on a poisoned mutex, the descriptive error must be
/// readable via lock().into_inner() (acknowledging the poison).
#[test]
fn test_record_worker_error_recovers_through_poisoned_mutex() {
    let worker_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Poison the mutex
    let we_clone = Arc::clone(&worker_error);
    let _ = thread::spawn(move || {
        let _guard = we_clone.lock().unwrap();
        panic!("deliberate poison for test_record_worker_error_recovers_through_poisoned_mutex");
    })
    .join();

    assert!(
        worker_error.is_poisoned(),
        "worker_error mutex must be poisoned before this test proceeds"
    );

    // record_worker_error must succeed despite poisoning
    record_worker_error(&worker_error, "poison-recovery test message");

    // Verify the message is now stored (readable through the poisoned state)
    let stored = match worker_error.lock() {
        Ok(lock) => lock.clone(),
        Err(poison) => poison.into_inner().clone(),
    };
    assert_eq!(
        stored,
        Some("poison-recovery test message".to_string()),
        "record_worker_error must store the message even through a poisoned mutex"
    );
}

// ============================================================================
// BLOCKER-B REGRESSION: stop() returns Err when worker_failed is set
// ============================================================================

/// Verifies that stop() returns Err when worker_failed is true, even if worker_error
/// mutex is healthy and worker_error contains the message.
#[test]
fn test_watcher_stop_returns_err_when_worker_failed() {
    let _lock = TEMP_WATCHER_SERIALIZATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let temp_dir = get_effective_sqlite_temp_path()
        .expect("resolve effective sqlite temp path for worker_failed stop test");

    let watcher = DirectoryWatcher::start(&temp_dir).expect("start watcher for worker_failed test");

    // Directly simulate a worker failure by setting the flag and error message
    // before stop() is called (simulates what the worker would do on a real failure).
    watcher.worker_failed.store(true, Ordering::SeqCst);
    record_worker_error(&watcher.worker_error, "injected failure for stop test");

    let result = watcher.stop();
    assert!(
        result.is_err(),
        "stop() must return Err when worker_failed is set"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("injected failure for stop test"),
        "stop() error must include the descriptive worker error, got: '{err_msg}'"
    );
}

// ============================================================================
// BLOCKER-B REGRESSION: Normal stop lifecycle does not false-positive worker_failed
// ============================================================================

/// Verifies that a clean stop() does not set worker_failed or leave an error message.
#[test]
fn test_watcher_normal_stop_does_not_set_worker_failed() {
    let _lock = TEMP_WATCHER_SERIALIZATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let temp_dir = get_effective_sqlite_temp_path()
        .expect("resolve effective sqlite temp path for normal stop test");

    let watcher = DirectoryWatcher::start(&temp_dir).expect("start watcher for normal stop test");
    watcher.assert_healthy("before clean stop");

    let result = watcher.stop();
    assert!(
        result.is_ok(),
        "clean stop() must return Ok, got: {:?}",
        result.err()
    );
    // No assertion about worker_failed directly (the watcher is consumed by stop()),
    // but the Ok result proves it was not set during a normal lifecycle.
}

// ============================================================================
// FIX-C REGRESSION: stop() returns Err when worker_error mutex is poisoned
// ============================================================================

/// Integration test: verifies that stop() returns Err when worker_error mutex is
/// deliberately poisoned and worker_failed is set — proving poison cannot hide failures.
///
/// Uses a real DirectoryWatcher with the actual stop() path. The worker_error mutex
/// is poisoned via a thread panic while holding the lock. Even with the mutex poisoned,
/// stop() must return Err because worker_failed atomic flag is set independently.
#[test]
fn test_stop_with_poisoned_worker_error_returns_err() {
    let _lock = TEMP_WATCHER_SERIALIZATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let temp_dir = get_effective_sqlite_temp_path()
        .expect("resolve effective sqlite temp path for poisoned-mutex stop test");

    let watcher = DirectoryWatcher::start(&temp_dir)
        .expect("start watcher for poisoned worker_error stop test");

    // Step 1: Set worker_failed BEFORE poisoning (atomic is always readable).
    watcher.worker_failed.store(true, Ordering::SeqCst);

    // Step 2: Poison the worker_error mutex by panicking while holding it.
    let we_clone = Arc::clone(&watcher.worker_error);
    let _ = thread::spawn(move || {
        let _guard = we_clone.lock().unwrap();
        panic!("deliberate poison for test_stop_with_poisoned_worker_error_returns_err");
    })
    .join(); // join() so panic has completed before we call stop()

    assert!(
        watcher.worker_error.is_poisoned(),
        "worker_error mutex must be poisoned before calling stop()"
    );

    // Step 3: Call stop() — must return Err despite poisoned mutex,
    // because worker_failed atomic flag is set.
    let result = watcher.stop();
    assert!(
        result.is_err(),
        "stop() must return Err when worker_failed is set, even when worker_error mutex is poisoned"
    );
    // The error message will reference the worker failure (or the poisoned fallback).
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("worker failed")
            || err_msg.contains("mutex poisoned")
            || err_msg.contains("Watcher worker"),
        "stop() error must reflect the worker failure, got: '{err_msg}'"
    );
}
