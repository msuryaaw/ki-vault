//! Auto-lock Runtime Module
//!
//! Provides the runtime state machine, clock abstraction, background worker,
//! and synchronization helpers for KiVault automatic locking.
//!
//! # Concurrency Invariants
//! - **Strict Mutex Acquisition Order**:
//!   `SharedAutoLock` -> `SharedVaultState`
//!   Never acquire `SharedAutoLock` while already holding `SharedVaultState`.
//! - **Generation Counter**:
//!   Incremented upon every successful `unlock` and `lock`. Stale timers
//!   terminate when `local_gen != current_gen`.
//! - **Transactional Failure Safety**:
//!   If saving to disk during lock fails, `AutoLockRuntime` state is preserved
//!   and not marked as locked.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::commands::vault::{map_error, CommandError, SharedVaultState, VaultState};
use crate::settings::SettingsRepository;
use crate::vault::operations::UnlockedVault;

/// Clock trait for deterministic time injection.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// System clock implementation using `std::time::Instant::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Runtime state for auto-lock bookkeeping.
#[derive(Debug)]
pub struct AutoLockRuntime {
    /// Incremented on every unlock/lock transition.
    pub generation: u64,
    /// Indicates whether the vault is locked from the runtime's perspective.
    pub is_locked: bool,
    /// Timestamp of last user or system activity.
    pub last_activity: Instant,
    /// Effective timeout duration, or `None` if "never".
    pub effective_timeout: Option<Duration>,
}

impl AutoLockRuntime {
    pub fn new() -> Self {
        Self {
            generation: 0,
            is_locked: true,
            last_activity: Instant::now(),
            effective_timeout: Some(Duration::from_secs(300)),
        }
    }
}

impl Default for AutoLockRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared auto-lock runtime managed by Tauri.
#[derive(Clone)]
pub struct SharedAutoLock(pub Arc<Mutex<AutoLockRuntime>>);

impl SharedAutoLock {
    pub fn new() -> Self {
        SharedAutoLock(Arc::new(Mutex::new(AutoLockRuntime::new())))
    }
}

impl Default for SharedAutoLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses an auto-lock duration string according to allowed options:
/// "1m", "5m", "15m", "30m", "never".
pub fn parse_auto_lock_duration(s: &str) -> Option<Duration> {
    match s {
        "1m" => Some(Duration::from_secs(60)),
        "5m" => Some(Duration::from_secs(300)),
        "15m" => Some(Duration::from_secs(900)),
        "30m" => Some(Duration::from_secs(1800)),
        "never" => None,
        _ => Some(Duration::from_secs(300)), // fallback to default
    }
}

/// Outcome of evaluating an auto-lock tick.
#[derive(Debug, PartialEq, Eq)]
pub enum AutoLockTickResult {
    /// Worker generation is stale; worker should terminate.
    StaleGeneration,
    /// Vault is already locked; worker should terminate.
    AlreadyLocked,
    /// Vault is currently unlocked with setting "never"; worker sleeps.
    Never,
    /// Activity deadline has not been reached yet; worker sleeps.
    NotExpired,
    /// Activity deadline reached and vault was successfully locked; worker terminates.
    LockedSuccessfully,
    /// Lock failed due to save error; state rolled back, worker continues.
    LockFailed(String),
}

/// Atomically evaluates whether auto-lock should trigger for the given worker generation.
///
/// Follows the strict mutex hierarchy:
/// 1. Acquire `AutoLockRuntime` lock.
/// 2. If expired, acquire `VaultState` lock.
pub fn evaluate_auto_lock_tick<C: Clock>(
    auto_lock: &SharedAutoLock,
    vault_state: &SharedVaultState,
    clock: &C,
    local_gen: u64,
) -> AutoLockTickResult {
    let mut al = match auto_lock.0.lock() {
        Ok(guard) => guard,
        Err(_) => return AutoLockTickResult::LockFailed("AutoLock lock poisoned".into()),
    };

    if al.generation != local_gen {
        return AutoLockTickResult::StaleGeneration;
    }

    if al.is_locked {
        return AutoLockTickResult::AlreadyLocked;
    }

    let timeout = match al.effective_timeout {
        Some(t) => t,
        None => return AutoLockTickResult::Never,
    };

    let now = clock.now();
    let elapsed = now.duration_since(al.last_activity);
    if elapsed < timeout {
        return AutoLockTickResult::NotExpired;
    }

    // Deadline reached! Acquire VaultState lock following hierarchy
    let mut vs = match vault_state.0.lock() {
        Ok(guard) => guard,
        Err(_) => return AutoLockTickResult::LockFailed("VaultState lock poisoned".into()),
    };

    // Re-verify under both locks
    if al.generation != local_gen || al.is_locked {
        return AutoLockTickResult::StaleGeneration;
    }

    // Check if new activity arrived just before acquiring vs lock
    let re_elapsed = clock.now().duration_since(al.last_activity);
    if re_elapsed < timeout {
        return AutoLockTickResult::NotExpired;
    }

    let (path, mut vault) = match std::mem::replace(&mut *vs, VaultState::Uninitialised) {
        VaultState::Unlocked { path, vault } => (path, vault),
        other => {
            *vs = other;
            al.is_locked = true;
            return AutoLockTickResult::AlreadyLocked;
        }
    };

    // Attempt save to disk
    if let Err(e) = vault.save_to_file(&path) {
        // Rollback state: restore Unlocked, do NOT advance generation, reset activity to prevent tight spin
        *vs = VaultState::Unlocked { path, vault };
        al.last_activity = clock.now();
        return AutoLockTickResult::LockFailed(format!("{e:?}"));
    }

    // Success: advance generation, mark locked, zeroize vault
    al.generation += 1;
    al.is_locked = true;
    vault.lock();
    *vs = VaultState::Locked { path };

    AutoLockTickResult::LockedSuccessfully
}

/// Executes manual lock with transactional consistency across `AutoLockRuntime` and `VaultState`.
pub fn execute_manual_lock(
    auto_lock: &SharedAutoLock,
    vault_state: &SharedVaultState,
) -> Result<(), CommandError> {
    let mut al = auto_lock
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "AutoLock lock poisoned."))?;

    let mut vs = vault_state
        .0
        .lock()
        .map_err(|_| CommandError::new("Internal", "VaultState lock poisoned."))?;

    let (path, mut vault) = match std::mem::replace(&mut *vs, VaultState::Uninitialised) {
        VaultState::Unlocked { path, vault } => (path, vault),
        other => {
            *vs = other;
            return Err(CommandError::new(
                "VaultLocked",
                "The vault is not currently unlocked.",
            ));
        }
    };

    // Save before zeroizing
    if let Err(e) = vault.save_to_file(&path) {
        // Rollback
        *vs = VaultState::Unlocked { path, vault };
        return Err(map_error(e));
    }

    // Save succeeded: update runtime and zeroize
    al.generation += 1;
    al.is_locked = true;
    vault.lock();
    *vs = VaultState::Locked { path };

    Ok(())
}

/// Completes vault unlock transition and initializes `AutoLockRuntime`.
/// Spawns background worker loop for the new generation.
pub fn complete_unlock(
    auto_lock: &SharedAutoLock,
    vault_state: &SharedVaultState,
    path: PathBuf,
    unlocked_vault: UnlockedVault,
) -> Result<(), CommandError> {
    let local_gen = {
        let mut al = auto_lock
            .0
            .lock()
            .map_err(|_| CommandError::new("Internal", "AutoLock lock poisoned."))?;

        let mut vs = vault_state
            .0
            .lock()
            .map_err(|_| CommandError::new("Internal", "VaultState lock poisoned."))?;

        // Read initial auto_lock setting from DB
        let repo = SettingsRepository::new(&unlocked_vault.db);
        let current_setting = repo
            .get_all()
            .map(|s| s.security.auto_lock)
            .unwrap_or_else(|_| "5m".to_string());

        al.generation += 1;
        al.is_locked = false;
        al.last_activity = Instant::now();
        al.effective_timeout = parse_auto_lock_duration(&current_setting);

        let new_gen = al.generation;

        *vs = VaultState::Unlocked {
            path,
            vault: Box::new(unlocked_vault),
        };

        new_gen
    };

    // Spawn background worker thread for this unlock session
    spawn_auto_lock_worker(auto_lock.clone(), vault_state.clone(), local_gen);

    Ok(())
}

/// Spawns background auto-lock worker with standard 5-second check intervals.
pub fn spawn_auto_lock_worker(
    auto_lock: SharedAutoLock,
    vault_state: SharedVaultState,
    local_gen: u64,
) {
    std::thread::Builder::new()
        .name(format!("kivault-autolock-gen-{local_gen}"))
        .spawn(move || {
            let clock = SystemClock;
            loop {
                std::thread::sleep(Duration::from_secs(5));
                match evaluate_auto_lock_tick(&auto_lock, &vault_state, &clock, local_gen) {
                    AutoLockTickResult::StaleGeneration
                    | AutoLockTickResult::AlreadyLocked
                    | AutoLockTickResult::LockedSuccessfully => break,
                    AutoLockTickResult::Never
                    | AutoLockTickResult::NotExpired
                    | AutoLockTickResult::LockFailed(_) => continue,
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;

    use crate::commands::settings::update_security_settings_impl;
    use crate::crypto::generate_salt;
    use crate::settings::SecuritySettings;
    use crate::vault::sqlite::InMemoryDb;
    use crate::vault::storage::write_vault_atomic;
    use zeroize::Zeroizing;

    /// Mock clock allowing instant, thread-safe time advancement without real-world sleep.
    pub struct MockClock {
        start: Instant,
        offset_millis: AtomicU64,
    }

    impl MockClock {
        pub fn new() -> Self {
            Self {
                start: Instant::now(),
                offset_millis: AtomicU64::new(0),
            }
        }

        pub fn advance(&self, duration: Duration) {
            self.offset_millis
                .fetch_add(duration.as_millis() as u64, Ordering::SeqCst);
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            self.start + Duration::from_millis(self.offset_millis.load(Ordering::SeqCst))
        }
    }

    struct TempVault {
        path: PathBuf,
    }

    impl TempVault {
        fn new() -> Self {
            let salt = generate_salt().unwrap();
            let hex_salt: String = salt[..8].iter().map(|b| format!("{b:02x}")).collect();
            let mut path = std::env::temp_dir();
            path.push(format!("kivault_autolock_test_{}.kivault", hex_salt));
            Self { path }
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn setup_unlocked_vault(path: &std::path::Path) -> (SharedAutoLock, SharedVaultState, u64) {
        let db = InMemoryDb::create_empty().unwrap();
        // Insert initial vault_metadata row
        {
            let conn = db.conn().unwrap();
            conn.execute(
                "INSERT INTO vault_metadata (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4);",
                rusqlite::params!["0123456789abcdef0123456789abcdef", "AutoLockTest", 1000, 1000],
            )
            .unwrap();
        }

        // Save container to disk using create_vault
        let image = db.to_image().unwrap();
        let password_bytes = Zeroizing::new(b"TestPassword123!".to_vec());
        let container = crate::vault::operations::create_vault(
            &password_bytes,
            1000,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            crate::vault::sqlite::SCHEMA_VERSION_V1,
            &image,
        )
        .unwrap();
        write_vault_atomic(path, &container).unwrap();

        // Unlock using genuine unlock_vault logic so VDK / header match container
        let unlocked = crate::vault::operations::unlock_vault(&container, &password_bytes).unwrap();

        let auto_lock = SharedAutoLock::new();
        let vault_state = SharedVaultState::new();

        // Initialize state via complete_unlock
        complete_unlock(&auto_lock, &vault_state, path.to_path_buf(), unlocked).unwrap();

        let gen = auto_lock.0.lock().unwrap().generation;
        (auto_lock, vault_state, gen)
    }

    // ── Test 1: Race Condition Prevention (notify_activity vs auto-lock tick) ──

    #[test]
    fn test_notify_activity_race_condition_prevents_lock() {
        let temp = TempVault::new();
        let (auto_lock, vault_state, gen) = setup_unlocked_vault(&temp.path);
        let clock = MockClock::new();

        // Set effective timeout to 1m (production valid option)
        {
            let mut al = auto_lock.0.lock().unwrap();
            al.last_activity = clock.now();
            al.effective_timeout = Some(Duration::from_secs(60));
        }

        // Advance clock by 61 seconds (deadline expired)
        clock.advance(Duration::from_secs(61));

        // Right before or concurrently with evaluating tick, notify_activity is called with clock
        crate::commands::security::notify_activity_with_clock(&auto_lock, &vault_state, &clock)
            .unwrap();

        // Evaluate tick
        let res = evaluate_auto_lock_tick(&auto_lock, &vault_state, &clock, gen);
        assert_eq!(res, AutoLockTickResult::NotExpired);

        // Vault must remain Unlocked
        let vs = vault_state.0.lock().unwrap();
        assert!(matches!(&*vs, VaultState::Unlocked { .. }));
    }

    // ── Test 2: Two-way setting transitions (1m <-> never) without re-unlock ──

    #[test]
    fn test_two_way_setting_transitions_without_reunlock() {
        let temp = TempVault::new();
        let (auto_lock, vault_state, gen) = setup_unlocked_vault(&temp.path);
        let clock = MockClock::new();

        {
            let mut al = auto_lock.0.lock().unwrap();
            al.last_activity = clock.now();
        }

        // 1. Transition to "never"
        update_security_settings_impl(
            &auto_lock,
            &vault_state,
            SecuritySettings {
                auto_lock: "never".to_string(),
                clipboard_timeout: 15,
            },
        )
        .unwrap();

        // Advance time by 10 minutes (600s)
        clock.advance(Duration::from_secs(600));

        let res = evaluate_auto_lock_tick(&auto_lock, &vault_state, &clock, gen);
        assert_eq!(res, AutoLockTickResult::Never);
        {
            let vs = vault_state.0.lock().unwrap();
            assert!(matches!(&*vs, VaultState::Unlocked { .. }));
        }

        // 2. Transition from "never" -> "1m" (preserving existing idle time)
        update_security_settings_impl(
            &auto_lock,
            &vault_state,
            SecuritySettings {
                auto_lock: "1m".to_string(),
                clipboard_timeout: 15,
            },
        )
        .unwrap();

        // Idle time was 600s, which is > 60s ("1m"). Tick immediately locks!
        let res = evaluate_auto_lock_tick(&auto_lock, &vault_state, &clock, gen);
        assert_eq!(res, AutoLockTickResult::LockedSuccessfully);

        // Vault is now Locked
        {
            let vs = vault_state.0.lock().unwrap();
            assert!(matches!(&*vs, VaultState::Locked { .. }));
        }
    }

    // ── Test 3: Generation counter prevents stale timer after manual lock & re-unlock ──

    #[test]
    fn test_generation_counter_prevents_stale_timer() {
        let temp = TempVault::new();
        let (auto_lock, vault_state, gen1) = setup_unlocked_vault(&temp.path);
        let clock = MockClock::new();

        // Manual lock
        execute_manual_lock(&auto_lock, &vault_state).unwrap();
        let gen2 = auto_lock.0.lock().unwrap().generation;
        assert!(gen2 > gen1);

        // Re-unlock
        let container_bytes = crate::vault::storage::read_vault(&temp.path).unwrap();
        let pw_zero = Zeroizing::new(b"TestPassword123!".to_vec());
        let re_unlocked =
            crate::vault::operations::unlock_vault(&container_bytes, &pw_zero).unwrap();
        complete_unlock(&auto_lock, &vault_state, temp.path.clone(), re_unlocked).unwrap();

        let gen3 = auto_lock.0.lock().unwrap().generation;
        assert!(gen3 > gen2);

        // Advance clock past any timeout
        clock.advance(Duration::from_secs(3600));

        // Stale timer from gen1 tries to evaluate tick
        let res = evaluate_auto_lock_tick(&auto_lock, &vault_state, &clock, gen1);
        assert_eq!(res, AutoLockTickResult::StaleGeneration);

        // Active vault for gen3 remains Unlocked!
        let vs = vault_state.0.lock().unwrap();
        assert!(matches!(&*vs, VaultState::Unlocked { .. }));
    }

    // ── Test 4: Barrier-synchronized concurrency (1m -> never vs tick) ──

    #[test]
    fn test_barrier_synchronized_1m_to_never_under_concurrent_tick() {
        let temp = TempVault::new();
        let (auto_lock, vault_state, gen) = setup_unlocked_vault(&temp.path);
        let clock = Arc::new(MockClock::new());

        // Set to 1m
        {
            let mut al = auto_lock.0.lock().unwrap();
            al.last_activity = clock.now();
            al.effective_timeout = Some(Duration::from_secs(60));
        }

        // Advance past 1m
        clock.advance(Duration::from_secs(70));

        let barrier = Arc::new(Barrier::new(2));

        let b1 = barrier.clone();
        let al1 = auto_lock.clone();
        let vs1 = vault_state.clone();
        let cl1 = clock.clone();

        let handle = std::thread::spawn(move || {
            // Wait for both threads to be ready
            b1.wait();
            // Evaluate tick
            evaluate_auto_lock_tick(&al1, &vs1, &*cl1, gen)
        });

        // Thread 2 updates settings to "never"
        barrier.wait();
        let _ = update_security_settings_impl(
            &auto_lock,
            &vault_state,
            SecuritySettings {
                auto_lock: "never".to_string(),
                clipboard_timeout: 15,
            },
        );

        let tick_res = handle.join().unwrap();

        // Either:
        // 1. Settings update won the mutex race -> tick observed "never" or did not lock.
        // 2. Tick won the race -> vault locked, update returned Err("VaultLocked").
        // Both cases are strictly consistent and safe (no corruption, no deadlock).
        let vs = vault_state.0.lock().unwrap();
        match tick_res {
            AutoLockTickResult::Never | AutoLockTickResult::NotExpired => {
                assert!(matches!(&*vs, VaultState::Unlocked { .. }));
            }
            AutoLockTickResult::LockedSuccessfully => {
                assert!(matches!(&*vs, VaultState::Locked { .. }));
            }
            other => panic!("Unexpected tick result: {other:?}"),
        }
    }

    // ── Test 5: Manual lock failure rollback preserves state consistency ──

    #[test]
    fn test_lock_failure_rollback_preserves_runtime_consistency() {
        let temp = TempVault::new();
        let (auto_lock, vault_state, gen_before) = setup_unlocked_vault(&temp.path);

        // Intentionally point vault path to an invalid directory to make save_to_file fail
        {
            let mut vs = vault_state.0.lock().unwrap();
            if let VaultState::Unlocked { path, .. } = &mut *vs {
                // Point to a non-existent directory path that cannot be written
                *path = PathBuf::from("Z:\\invalid_non_existent_drive\\vault.kivault");
            }
        }

        // Attempt manual lock — must fail because save_to_file fails
        let res = execute_manual_lock(&auto_lock, &vault_state);
        assert!(res.is_err());

        // Runtime state must NOT be marked locked and generation must NOT advance
        let al = auto_lock.0.lock().unwrap();
        assert!(!al.is_locked);
        assert_eq!(al.generation, gen_before);

        // Vault state must be restored to Unlocked
        let vs = vault_state.0.lock().unwrap();
        assert!(matches!(&*vs, VaultState::Unlocked { .. }));
    }
}
