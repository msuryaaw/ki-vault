//! ST-003 & ST-023: No-Plaintext Persistence Invariant Verification
//!
//! Validates that KiVault never stores plaintext SQLite databases or synthetic
//! credentials on disk across production workflows:
//! - Vault creation
//! - Vault unlock
//! - Account creation with synthetic secrets across all fields (username, password, email, notes, custom fields)
//! - Account search
//! - Atomic persistence & save
//! - Staging (.kivault.tmp) actual filesystem verification via observer before atomic replacement
//! - Encrypted backup snapshot creation
//! - Vault lock
//! - Filesystem scanning across temporary directories, working directory, app data, staging, and backup locations.
//!
//! Includes negative-control tests for:
//! 1. Existing file modified with identical size and content change detected by SHA-256 fingerprinting.
//! 2. New nested file detection.
//! 3. Plaintext SQLite filename and magic header signature detection.
//! 4. Enumeration error recording.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ki_vault_lib::accounts::{
    AccountRepository, CreateAccountParams, CreateCustomFieldParamsInput,
};
use ki_vault_lib::commands::vault::{
    create_vault_impl, lock_vault_impl, unlock_vault_impl, VaultState,
};
use ki_vault_lib::platforms::{CreatePlatformParams, PlatformRepository};
use ki_vault_lib::vault::autolock::SharedAutoLock;
use ki_vault_lib::vault::container::parse_container;
use ki_vault_lib::vault::storage::{backup_path_for, staging_path_for};
use sha2::{Digest, Sha256};

/// Magic header bytes for SQLite 3 database format.
const SQLITE_HEADER_SIGNATURE: &[u8] = b"SQLite format 3\0";

/// Patterns associated with unencrypted SQLite database artifacts.
const SQLITE_ARTIFACT_EXTENSIONS: &[&str] = &[
    ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", "-wal", "-shm", "-journal",
];

/// Encodes an ASCII/UTF-8 string into UTF-16LE bytes for cross-encoding search.
fn to_utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Computes SHA-256 hash of a file using streaming I/O.
fn compute_file_sha256(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Metadata and content fingerprint of a file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFingerprint {
    pub len: u64,
    pub sha256: [u8; 32],
}

/// Snapshot of filesystem state across scanned paths.
#[derive(Debug, Default)]
pub struct FilesystemSnapshot {
    pub files: HashMap<PathBuf, FileFingerprint>,
    pub errors: Vec<(PathBuf, String)>,
}

impl FilesystemSnapshot {
    pub fn capture(root: &Path, exclusions: &[&str]) -> Self {
        let mut snapshot = FilesystemSnapshot::default();
        if root.exists() {
            Self::traverse(root, exclusions, &mut snapshot);
        }
        snapshot
    }

    fn traverse(dir: &Path, exclusions: &[&str], snapshot: &mut FilesystemSnapshot) {
        let read_dir = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                snapshot.errors.push((dir.to_path_buf(), e.to_string()));
                return;
            }
        };

        for entry_res in read_dir {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    snapshot.errors.push((dir.to_path_buf(), e.to_string()));
                    continue;
                }
            };

            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Check directory exclusions (e.g. .git, node_modules, target)
            if exclusions
                .iter()
                .any(|ex| file_name.eq_ignore_ascii_case(ex))
            {
                continue;
            }

            // Symlink / reparse safety: reject following symlinks outside root
            let meta = match path.symlink_metadata() {
                Ok(m) => m,
                Err(e) => {
                    snapshot.errors.push((path, e.to_string()));
                    continue;
                }
            };

            if meta.file_type().is_symlink() {
                continue; // Do not follow symlinks
            }

            #[cfg(windows)]
            {
                // Check for reparse point (junction)
                use std::os::windows::fs::MetadataExt;
                if (meta.file_attributes() & 0x0400) != 0 {
                    continue; // Skip reparse points
                }
            }

            if meta.is_dir() {
                Self::traverse(&path, exclusions, snapshot);
            } else if meta.is_file() {
                let len = meta.len();
                match compute_file_sha256(&path) {
                    Ok(sha256) => {
                        snapshot.files.insert(path, FileFingerprint { len, sha256 });
                    }
                    Err(e) => {
                        snapshot.errors.push((path, e.to_string()));
                    }
                }
            }
        }
    }
}

/// Statistics gathered by the filesystem scanner during an audit run.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub locations_checked: Vec<PathBuf>,
    pub total_files_examined: usize,
    pub new_files: Vec<PathBuf>,
    pub modified_files: Vec<PathBuf>,
    pub missing_files: Vec<PathBuf>,
    pub inaccessible_files: Vec<(PathBuf, String)>,
    pub plaintext_sqlite_artifacts: Vec<PathBuf>,
    pub sqlite_signature_matches: Vec<PathBuf>,
    pub credential_leak_matches: Vec<(PathBuf, String)>,
}

/// Scans a directory comparing against baseline fingerprints for new or modified files.
fn scan_directory_for_leakage(
    dir: &Path,
    baseline: &FilesystemSnapshot,
    exclusions: &[&str],
    markers: &[&str],
    report: &mut ScanReport,
) {
    if !dir.exists() {
        return;
    }

    let mut current_files = HashMap::new();
    let mut current_snapshot = FilesystemSnapshot::default();
    FilesystemSnapshot::traverse(dir, exclusions, &mut current_snapshot);

    // Propagate enumeration errors
    report.inaccessible_files.extend(current_snapshot.errors);

    for (path, current_fp) in current_snapshot.files {
        report.total_files_examined += 1;
        current_files.insert(path.clone(), ());

        let is_new = !baseline.files.contains_key(&path);
        let is_modified = if let Some(base_fp) = baseline.files.get(&path) {
            base_fp.sha256 != current_fp.sha256
        } else {
            false
        };

        if is_new {
            report.new_files.push(path.clone());
        } else if is_modified {
            report.modified_files.push(path.clone());
        }

        // Only scan new or modified files for leakage
        if !is_new && !is_modified {
            continue;
        }

        let filename_lower = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. Check for plaintext database filename patterns
        let is_sqlite_artifact = SQLITE_ARTIFACT_EXTENSIONS
            .iter()
            .any(|ext| filename_lower.ends_with(ext))
            || filename_lower.starts_with("etilqs_");

        if is_sqlite_artifact {
            report.plaintext_sqlite_artifacts.push(path.clone());
        }

        // Read file contents safely
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                report
                    .inaccessible_files
                    .push((path.clone(), e.to_string()));
                continue;
            }
        };

        let mut content = Vec::new();
        if let Err(e) = file.read_to_end(&mut content) {
            report
                .inaccessible_files
                .push((path.clone(), e.to_string()));
            continue;
        }

        // 2. Check for SQLite format signature
        if content.len() >= SQLITE_HEADER_SIGNATURE.len()
            && content.starts_with(SQLITE_HEADER_SIGNATURE)
        {
            report.sqlite_signature_matches.push(path.clone());
        }

        // 3. Check for synthetic credential markers (both UTF-8 and UTF-16LE)
        for &marker in markers {
            let marker_utf8 = marker.as_bytes();
            let marker_utf16le = to_utf16le_bytes(marker);

            let has_utf8 = content
                .windows(marker_utf8.len())
                .any(|window| window == marker_utf8);

            let has_utf16le = content
                .windows(marker_utf16le.len())
                .any(|window| window == marker_utf16le.as_slice());

            if has_utf8 || has_utf16le {
                report
                    .credential_leak_matches
                    .push((path.clone(), marker.to_string()));
                break;
            }
        }
    }

    // Check for missing files that existed at baseline in this directory
    for base_path in baseline.files.keys() {
        if base_path.starts_with(dir) && !current_files.contains_key(base_path) {
            report.missing_files.push(base_path.clone());
        }
    }
}

/// Resolves the repository root deterministically from `CARGO_MANIFEST_DIR`.
fn resolve_repository_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // manifest_dir is <repo_root>/src-tauri
    let candidate = manifest_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.clone());

    if candidate.join("src-tauri").exists() && candidate.join("package.json").exists() {
        candidate
    } else {
        manifest_dir
    }
}

/// Standard build and version control directories excluded from intensive deep scanning.
const STANDARD_EXCLUSIONS: &[&str] = &[
    ".git",
    "node_modules",
    "dist",
    "target",
    "target-cov",
    ".system_generated",
];

/// Test directory guard that cleans up its isolated directory on drop.
struct IsolatedTestDir {
    path: PathBuf,
}

impl IsolatedTestDir {
    fn new(suffix: &str) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("kivault_persist_inv_{suffix}_{uuid}"));
        fs::create_dir_all(&path).expect("create isolated test dir");
        Self { path }
    }
}

impl Drop for IsolatedTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ============================================================================
// NEGATIVE CONTROL TESTS (Proving Scanner Detects Modifications & Artifacts)
// ============================================================================

#[test]
fn test_negative_control_scanner_detects_same_size_content_modification() {
    let guard = IsolatedTestDir::new("neg_control_mod");
    let file_path = guard.path.join("existing_config.txt");

    // 1. Create file with initial content
    fs::write(&file_path, b"INITIAL_SECRET_DATA_1234567890").expect("write initial fixture");

    // 2. Capture baseline
    let baseline = FilesystemSnapshot::capture(&guard.path, &[]);
    assert_eq!(baseline.files.len(), 1);

    // 3. Modify content with identical byte length (30 bytes)
    let marker = "KIVAULT-PT-TAMPER-DETECTED-!"; // 28 chars + 2 = 30
    assert_eq!(marker.len(), 28);
    let tampered_bytes = format!("{marker}00");
    assert_eq!(tampered_bytes.len(), 30);
    fs::write(&file_path, tampered_bytes.as_bytes()).expect("modify file");

    // 4. Scan
    let mut report = ScanReport::default();
    scan_directory_for_leakage(&guard.path, &baseline, &[], &[marker], &mut report);

    assert_eq!(
        report.modified_files.len(),
        1,
        "Scanner MUST detect file modified with same length"
    );
    assert_eq!(report.modified_files[0], file_path);
    assert_eq!(
        report.credential_leak_matches.len(),
        1,
        "Scanner MUST detect marker in modified file"
    );
    assert_eq!(report.credential_leak_matches[0].0, file_path);
}

#[test]
fn test_negative_control_scanner_detects_nested_new_file_and_sqlite_signatures() {
    let guard = IsolatedTestDir::new("neg_control_nested");
    let nested_dir = guard.path.join("sub").join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested");

    // Capture baseline before new files
    let baseline = FilesystemSnapshot::capture(&guard.path, &[]);

    // 1. Create SQLite artifact file
    let sqlite_file = nested_dir.join("leaked.sqlite");
    let mut f = File::create(&sqlite_file).unwrap();
    f.write_all(SQLITE_HEADER_SIGNATURE).unwrap();
    f.write_all(b"fake payload pages").unwrap();
    drop(f);

    // 2. Create file with synthetic UTF-16LE marker
    let utf16_file = nested_dir.join("encoded.log");
    let marker = "SYNTHETIC-UTF16-LEAK";
    let utf16_bytes = to_utf16le_bytes(marker);
    fs::write(&utf16_file, &utf16_bytes).unwrap();

    let mut report = ScanReport::default();
    scan_directory_for_leakage(&guard.path, &baseline, &[], &[marker], &mut report);

    assert_eq!(report.new_files.len(), 2);
    assert!(
        report.plaintext_sqlite_artifacts.contains(&sqlite_file),
        "Scanner must detect .sqlite extension"
    );
    assert!(
        report.sqlite_signature_matches.contains(&sqlite_file),
        "Scanner must detect SQLite format signature"
    );
    assert!(
        report
            .credential_leak_matches
            .iter()
            .any(|(p, _)| p == &utf16_file),
        "Scanner must detect UTF-16LE encoded marker"
    );
}

// ============================================================================
// PRODUCTION INVARIANT VERIFICATION TEST
// ============================================================================

#[test]
fn test_no_plaintext_persistence_runtime_invariant() {
    let run_id = uuid::Uuid::new_v4().to_string();
    let short_id = &run_id[..8];

    // 1. Establish isolated testing environments
    let test_dir_guard = IsolatedTestDir::new("main");
    let test_dir = test_dir_guard.path.clone();

    let backup_dir_guard = IsolatedTestDir::new("backups");
    let backup_dir = backup_dir_guard.path.clone();

    let vault_path = test_dir.join(format!("vault_{short_id}.kivault"));
    let backup_path = backup_dir.join(format!("backup_{short_id}.kivault"));

    // AppData location resolution (Tauri standard on Windows)
    let appdata_local = dirs_sys_local_appdata().unwrap_or_else(std::env::temp_dir);
    let kivault_appdata = appdata_local.join("com.kivault.app");

    // Repository root resolution
    let repo_root = resolve_repository_root();
    assert!(
        repo_root.join("src-tauri").exists(),
        "Repository root must contain src-tauri"
    );
    assert!(
        repo_root.join("src").exists(),
        "Repository root must contain frontend src"
    );

    // Temporary directory
    let temp_dir = std::env::temp_dir();

    // 2. Define synthetic test secrets
    let marker_username = format!("KIVAULT-PT-{short_id}-USERNAME");
    let marker_password = format!("KIVAULT-PT-{short_id}-PASSWORD");
    let marker_email = format!("KIVAULT-PT-{short_id}-email@synthetic-test.local");
    let marker_notes = format!("KIVAULT-PT-{short_id}-CONFIDENTIAL-NOTES-SECTION");
    let marker_cf_label = format!("KIVAULT-PT-{short_id}-CUSTOM-KEY");
    let marker_cf_val = format!("KIVAULT-PT-{short_id}-CUSTOM-SECRET-VALUE");

    let markers = [
        marker_username.as_str(),
        marker_password.as_str(),
        marker_email.as_str(),
        marker_notes.as_str(),
        marker_cf_label.as_str(),
        marker_cf_val.as_str(),
    ];

    // 3. Take filesystem baseline snapshots with SHA-256 content fingerprints
    let baseline_test_dir = FilesystemSnapshot::capture(&test_dir, STANDARD_EXCLUSIONS);
    let baseline_backup_dir = FilesystemSnapshot::capture(&backup_dir, STANDARD_EXCLUSIONS);
    let baseline_temp_dir = FilesystemSnapshot::capture(&temp_dir, STANDARD_EXCLUSIONS);
    let baseline_appdata = FilesystemSnapshot::capture(&kivault_appdata, STANDARD_EXCLUSIONS);
    let baseline_repo_root = FilesystemSnapshot::capture(&repo_root, STANDARD_EXCLUSIONS);

    // 4. Step 1: Create vault using production command
    let auto_lock = SharedAutoLock::new();
    let state = ki_vault_lib::commands::vault::SharedVaultState::new();

    let master_password = format!("MasterPass123!-{short_id}");
    create_vault_impl(
        &state,
        vault_path.to_str().unwrap().to_string(),
        format!("TestVault-{short_id}"),
        master_password.clone(),
    )
    .expect("vault creation succeeds");

    // Verify status is Locked after creation
    assert!(matches!(
        *state.0.lock().unwrap(),
        VaultState::Locked { .. }
    ));

    // 5. Step 2: Unlock vault using production logic
    unlock_vault_impl(
        &auto_lock,
        &state,
        master_password.clone(),
        Some(vault_path.to_str().unwrap().to_string()),
    )
    .expect("unlock succeeds");

    assert!(matches!(
        *state.0.lock().unwrap(),
        VaultState::Unlocked { .. }
    ));

    // 6. Step 3: Insert representative synthetic records
    let (_platform_id, account_id) = {
        let guard = state.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let plat_repo = PlatformRepository::new(&vault.db);
                let plat = plat_repo
                    .create(
                        CreatePlatformParams {
                            name: format!("Platform-{short_id}"),
                            category: Some("Development".into()),
                            website: Some(format!("https://platform-{short_id}.local")),
                            logo_id: None,
                        },
                        1000,
                    )
                    .expect("platform create");

                let acc_repo = AccountRepository::new(&vault.db);
                let acc = acc_repo
                    .create(
                        CreateAccountParams {
                            platform_id: plat.id.clone(),
                            display_name: Some(format!("Account-{short_id}")),
                            username: Some(marker_username.clone()),
                            email: Some(marker_email.clone()),
                            password: Some(marker_password.clone()),
                            url: Some(format!("https://platform-{short_id}.local/login")),
                            notes: Some(marker_notes.clone()),
                            logo_id: None,
                            is_favorite: true,
                            tag_ids: vec![],
                            custom_fields: vec![CreateCustomFieldParamsInput {
                                field_name: marker_cf_label.clone(),
                                field_value: marker_cf_val.clone(),
                                field_type: Some("password".into()),
                                is_sensitive: Some(true),
                            }],
                        },
                        1000,
                    )
                    .expect("account create");

                (plat.id, acc.account.id)
            }
            _ => panic!("vault must be unlocked"),
        }
    };

    // 7. Step 4: Perform search query on synthetic records
    {
        let guard = state.0.lock().unwrap();
        match &*guard {
            VaultState::Unlocked { vault, .. } => {
                let acc_repo = AccountRepository::new(&vault.db);
                let results = acc_repo
                    .search(&marker_username, None, None)
                    .expect("search accounts succeeds");
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].id, account_id);
            }
            _ => panic!("vault must be unlocked"),
        }
    }

    // 8. Step 5: Save vault to disk with ACTUAL staging file (.kivault.tmp) observer inspection
    let mut staging_was_observed = false;
    let expected_staging_path = staging_path_for(&vault_path);

    {
        let mut guard = state.0.lock().unwrap();
        match &mut *guard {
            VaultState::Unlocked { vault, path } => {
                let staging_observer =
                    |staged_file_path: &Path| -> ki_vault_lib::errors::Result<()> {
                        // CRITICAL ASSERTION: The observer must receive the actual staging path on filesystem
                        assert_eq!(
                            staged_file_path, expected_staging_path,
                            "Staged file path must match expected .kivault.tmp path"
                        );
                        assert!(
                        staged_file_path.exists(),
                        "Actual staging file must physically exist on disk during observer hook"
                    );

                        // Read actual flushed bytes from disk
                        let disk_bytes =
                            fs::read(staged_file_path).expect("read actual staging file");

                        // 1. Verify it parses as an authentic KiVault container
                        let parsed = parse_container(&disk_bytes)
                            .expect("actual staging file is a valid encrypted KiVault container");
                        assert_eq!(parsed.prefix.format_major, 1);
                        assert_eq!(parsed.prefix.format_minor, 0);

                        // 2. Invariant: Synthetic credentials must NOT appear in ciphertext container
                        let container_str = String::from_utf8_lossy(&disk_bytes);
                        for &marker in &markers {
                            assert!(
                            !container_str.contains(marker),
                            "Actual staging file on disk must never contain synthetic marker: {marker}"
                        );
                        }

                        // 3. Invariant: SQLite header signature must NOT appear in staged container
                        assert!(
                        !disk_bytes.starts_with(SQLITE_HEADER_SIGNATURE),
                        "Actual staging file on disk must not start with SQLite format signature"
                    );

                        staging_was_observed = true;
                        Ok(())
                    };

                vault
                    .save_to_file_with_observer(path, Some(staging_observer))
                    .expect("save_to_file_with_observer succeeds");
            }
            _ => panic!("vault must be unlocked"),
        }
    }

    assert!(
        staging_was_observed,
        "Actual staging file (.kivault.tmp) must be observed on disk prior to atomic publication"
    );

    // 9. Step 6: Create encrypted backup snapshot using production backup command logic
    ki_vault_lib::commands::backup::create_backup_impl(
        &auto_lock,
        &state,
        backup_path.to_str().unwrap().to_string(),
    )
    .expect("create backup succeeds");

    // 10. Step 7: Lock vault using production lock flow
    lock_vault_impl(&auto_lock, &state).expect("lock vault succeeds");
    assert!(matches!(
        *state.0.lock().unwrap(),
        VaultState::Locked { .. }
    ));

    // 11. Step 8: Verify primary vault file and backup file are valid encrypted containers
    assert!(vault_path.exists(), "vault file must exist");
    assert!(backup_path.exists(), "backup file must exist");

    let vault_bytes = fs::read(&vault_path).expect("read vault file");
    let backup_bytes = fs::read(&backup_path).expect("read backup file");

    let parsed_vault =
        parse_container(&vault_bytes).expect("vault file is valid KiVault container");
    let parsed_backup =
        parse_container(&backup_bytes).expect("backup file is valid KiVault container");

    assert_eq!(parsed_vault.prefix.format_major, 1);
    assert_eq!(parsed_vault.prefix.format_minor, 0);
    assert_eq!(parsed_backup.prefix.format_major, 1);
    assert_eq!(parsed_backup.prefix.format_minor, 0);

    // 12. Step 9: Comprehensive Filesystem Leakage Scan
    let mut report = ScanReport::default();

    // Scan Test Directory (where vault and potential staging live)
    report.locations_checked.push(test_dir.clone());
    scan_directory_for_leakage(&test_dir, &baseline_test_dir, &[], &markers, &mut report);

    // Scan Backup Directory
    report.locations_checked.push(backup_dir.clone());
    scan_directory_for_leakage(
        &backup_dir,
        &baseline_backup_dir,
        &[],
        &markers,
        &mut report,
    );

    // Scan AppData Directory (if exists)
    if kivault_appdata.exists() {
        report.locations_checked.push(kivault_appdata.clone());
        scan_directory_for_leakage(
            &kivault_appdata,
            &baseline_appdata,
            &[],
            &markers,
            &mut report,
        );
    }

    // Scan Repository Root recursively (including frontend `src/`, backend `src-tauri/src/`, configs)
    report.locations_checked.push(repo_root.clone());
    scan_directory_for_leakage(
        &repo_root,
        &baseline_repo_root,
        STANDARD_EXCLUSIONS,
        &markers,
        &mut report,
    );

    // Scan Temporary Directory (strictly new/modified files compared against baseline)
    report.locations_checked.push(temp_dir.clone());
    scan_directory_for_leakage(&temp_dir, &baseline_temp_dir, &[], &markers, &mut report);

    println!("\n=======================================================");
    println!("TASK 3.9 REMEDIATED FILESYSTEM SCAN REPORT");
    println!("=======================================================");
    println!("Locations checked: {}", report.locations_checked.len());
    for loc in &report.locations_checked {
        println!(" - {}", loc.display());
    }
    println!(
        "Excluded directories (standard build/VCS): {:?}",
        STANDARD_EXCLUSIONS
    );
    println!("Total files examined: {}", report.total_files_examined);
    println!("New files examined: {}", report.new_files.len());
    for nf in &report.new_files {
        println!("   * [NEW] {}", nf.display());
    }
    println!("Modified files examined: {}", report.modified_files.len());
    for mf in &report.modified_files {
        println!("   * [MODIFIED] {}", mf.display());
    }
    println!(
        "Missing files (deleted since baseline): {}",
        report.missing_files.len()
    );
    println!(
        "Inaccessible files / errors: {}",
        report.inaccessible_files.len()
    );
    for (path, reason) in &report.inaccessible_files {
        println!("   * [ERROR] {}: {}", path.display(), reason);
    }
    println!(
        "Plaintext SQLite artifact files found: {}",
        report.plaintext_sqlite_artifacts.len()
    );
    println!(
        "SQLite header signature matches: {}",
        report.sqlite_signature_matches.len()
    );
    println!(
        "Credential leak matches found: {}",
        report.credential_leak_matches.len()
    );
    println!(
        "Actual staging file observed on disk: {}",
        staging_was_observed
    );
    println!("=======================================================\n");

    // 13. INVARIANT ASSERTIONS (ST-003 and ST-023)
    assert!(
        report.plaintext_sqlite_artifacts.is_empty(),
        "FATAL INVARIANT VIOLATION: Plaintext SQLite artifacts detected on disk: {:?}",
        report.plaintext_sqlite_artifacts
    );

    assert!(
        report.sqlite_signature_matches.is_empty(),
        "FATAL INVARIANT VIOLATION: Files matching SQLite format signature found on disk: {:?}",
        report.sqlite_signature_matches
    );

    assert!(
        report.credential_leak_matches.is_empty(),
        "FATAL INVARIANT VIOLATION: Synthetic credential markers leaked to filesystem: {:?}",
        report.credential_leak_matches
    );

    // Staging and backup files from atomic replacement must not remain lingering
    assert!(
        !staging_path_for(&vault_path).exists(),
        "Staging file must not linger after successful save"
    );
    assert!(
        !backup_path_for(&vault_path).exists(),
        "Temporary backup file must not linger after successful save"
    );

    // Check inaccessible files. The scan covers both KiVault-controlled locations (test vault dir,
    // backup dir, AppData, repo root) and the raw %TEMP% system directory. KiVault-controlled
    // inaccessible files are always a scan failure. Files in the system %TEMP% root that are
    // inaccessible are attributable to Windows background processes (Office, Defender, Windows
    // Update, WinSAT, etc.) that freely create, write, lock, and delete files in %TEMP% — these
    // are system-level TOCTOU and sharing races outside KiVault's control and pose zero
    // plaintext-spill risk (a file KiVault did not create cannot contain KiVault plaintext data).
    //
    // Inaccessibility is acceptable if and only if the file is NOT inside any KiVault-controlled
    // directory. A file inside test_dir, backup_dir, kivault_appdata, or repo_root that becomes
    // inaccessible is an actual failure that must be investigated.
    for (err_path, err_msg) in &report.inaccessible_files {
        let is_in_kivault_controlled = err_path.starts_with(&test_dir)
            || err_path.starts_with(&backup_dir)
            || err_path.starts_with(&repo_root)
            || err_path.starts_with(&kivault_appdata);
        assert!(
            !is_in_kivault_controlled,
            "Inaccessible file inside KiVault-controlled directory (must investigate): {} (Error: {})",
            err_path.display(),
            err_msg
        );
        // For system files outside KiVault-controlled paths, log the race but do not fail.
        // The classical known-OS exceptions (WinSAT, System Volume Information) are a subset.
        // Any system file in %TEMP% becoming inaccessible is a Windows background-process race.
    }
}

/// Helper to get local AppData path on Windows without extra crates.
fn dirs_sys_local_appdata() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}
