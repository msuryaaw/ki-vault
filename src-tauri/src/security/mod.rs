//! Security Domain Service & Health Analysis
//!
//! Implements logic for security status aggregation and password health calculation
//! in accordance with `docs/api-contract.md` §10 and `docs/ui-ux-spec.md` §13.
//!
//! # Security Invariants
//! - Never returns passwords, plaintext secrets, or lists of affected accounts.
//! - Aggregates counts strictly in Rust.

use serde::{Deserialize, Serialize};

use crate::errors::Result;
use crate::settings::SettingsRepository;
use crate::vault::cbor::VaultHeader;
use crate::vault::sqlite::InMemoryDb;

/// Status report returned by `get_security_status` (`api-contract.md` §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityStatusResponse {
    pub encryption: String,
    pub kdf: String,
    pub vault_state: String,
    pub auto_lock: String,
    pub clipboard_timeout: u32,
    pub vault_integrity: String,
}

/// Password health summary returned by `get_password_health` (`api-contract.md` §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHealthResponse {
    pub weak_count: u32,
    pub reused_count: u32,
}

/// Activity notification response returned by `notify_activity` (`api-contract.md` §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityNotificationResponse {
    pub acknowledged: bool,
    pub auto_lock_enforced: bool,
}

/// Minimum length for a password to NOT be considered weak.
///
/// In KiVault, the password generator enforces 8 to 256 characters.
/// Consistent with industry standards and PRD complexity requirements,
/// passwords with fewer than 12 characters, or lacking character variety,
/// are classified as weak.
pub const WEAK_PASSWORD_MIN_LENGTH: usize = 12;

/// Checks whether a password string is considered weak.
///
/// A password is weak if:
/// 1. Its length in characters is less than 12.
/// 2. Or it contains characters from fewer than 3 of the 4 basic pools:
///    - uppercase ASCII
///    - lowercase ASCII
///    - ASCII digits
///    - punctuation / symbols
pub fn is_weak_password(password: &str) -> bool {
    if password.chars().count() < WEAK_PASSWORD_MIN_LENGTH {
        return true;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    let category_count =
        (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_symbol as u8);

    category_count < 3
}

/// Evaluates password health across all accounts in the database.
///
/// Returns only aggregate counts of weak and reused passwords.
/// Passwords are never logged or leaked.
pub fn calculate_password_health(db: &InMemoryDb) -> Result<PasswordHealthResponse> {
    let conn = db.conn()?;
    let mut stmt = conn.prepare("SELECT password FROM accounts WHERE password IS NOT NULL;")?;
    let mut rows = stmt.query([])?;

    let mut passwords: Vec<String> = Vec::new();
    let mut weak_count: u32 = 0;

    while let Some(row) = rows.next()? {
        let pw: String = row.get(0)?;
        if is_weak_password(&pw) {
            weak_count += 1;
        }
        passwords.push(pw);
    }

    // Calculate reused passwords count.
    // An account's password is counted as "reused" if more than one account shares the exact same password.
    use std::collections::HashMap;
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for pw in &passwords {
        *counts.entry(pw.as_str()).or_insert(0) += 1;
    }

    let mut reused_count: u32 = 0;
    for &count in counts.values() {
        if count > 1 {
            reused_count += count;
        }
    }

    Ok(PasswordHealthResponse {
        weak_count,
        reused_count,
    })
}

/// Evaluates security status for an unlocked vault.
pub fn get_security_status_for_vault(
    header: &VaultHeader,
    db: &InMemoryDb,
) -> Result<SecurityStatusResponse> {
    let settings_repo = SettingsRepository::new(db);
    let settings = settings_repo.get_all()?;

    // Perform an in-memory SQLite quick_check
    let conn = db.conn()?;
    let quick_check: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
    let vault_integrity = if quick_check == "ok" {
        "OK".to_string()
    } else {
        "Degraded".to_string()
    };

    Ok(SecurityStatusResponse {
        encryption: header.payload_algorithm.clone(),
        kdf: header.kdf_algorithm.clone(),
        vault_state: "Unlocked".to_string(),
        auto_lock: settings.security.auto_lock,
        clipboard_timeout: settings.security.clipboard_timeout,
        vault_integrity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_weak_password() {
        // Less than 12 chars
        assert!(is_weak_password(""));
        assert!(is_weak_password("Short1!"));
        assert!(is_weak_password("12345678901")); // 11 chars

        // 12 chars but only 1 or 2 categories
        assert!(is_weak_password("alllowercaseletters"));
        assert!(is_weak_password("ALLUPPERCASE12345")); // upper + digit (2 categories)
        assert!(is_weak_password("lowercaseand12345")); // lower + digit (2 categories)

        // 12+ chars with 3 or 4 categories -> strong
        assert!(!is_weak_password("StrongPassword1")); // upper + lower + digit (3)
        assert!(!is_weak_password("StrongPass123!")); // upper + lower + digit + symbol (4)
        assert!(is_weak_password("correct-horse-battery")); // lower + symbol (only 2 categories -> weak)
        assert!(!is_weak_password("Correct-Horse-Battery")); // upper + lower + symbol (3 categories -> strong)
    }
}
