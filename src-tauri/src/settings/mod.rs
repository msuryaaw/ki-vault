//! Settings Domain Repository
//!
//! Handles reading and updating vault configuration in the `settings` table (§11 of `database.md`).

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, DatabaseError, Result};
use crate::vault::sqlite::InMemoryDb;

pub const KEY_AUTO_LOCK: &str = "security.auto_lock";
pub const KEY_CLIPBOARD_TIMEOUT: &str = "security.clipboard_timeout";
pub const KEY_GEN_LENGTH: &str = "generator.length";
pub const KEY_GEN_UPPERCASE: &str = "generator.uppercase";
pub const KEY_GEN_LOWERCASE: &str = "generator.lowercase";
pub const KEY_GEN_NUMBERS: &str = "generator.numbers";
pub const KEY_GEN_SYMBOLS: &str = "generator.symbols";

pub const DEFAULT_AUTO_LOCK: &str = "5m";
pub const DEFAULT_CLIPBOARD_TIMEOUT: u32 = 15;
pub const DEFAULT_GEN_LENGTH: usize = 16;
pub const DEFAULT_GEN_UPPERCASE: bool = true;
pub const DEFAULT_GEN_LOWERCASE: bool = true;
pub const DEFAULT_GEN_NUMBERS: bool = true;
pub const DEFAULT_GEN_SYMBOLS: bool = true;

pub const ALLOWED_AUTO_LOCK: &[&str] = &["1m", "5m", "15m", "30m", "never"];
pub const ALLOWED_CLIPBOARD_TIMEOUT: &[u32] = &[5, 15, 30, 60];

/// Security settings (auto-lock and clipboard timeouts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub auto_lock: String,
    pub clipboard_timeout: u32,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            auto_lock: DEFAULT_AUTO_LOCK.to_string(),
            clipboard_timeout: DEFAULT_CLIPBOARD_TIMEOUT,
        }
    }
}

/// Password generator default preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordGeneratorSettings {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl Default for PasswordGeneratorSettings {
    fn default() -> Self {
        Self {
            length: DEFAULT_GEN_LENGTH,
            use_uppercase: DEFAULT_GEN_UPPERCASE,
            use_lowercase: DEFAULT_GEN_LOWERCASE,
            use_numbers: DEFAULT_GEN_NUMBERS,
            use_symbols: DEFAULT_GEN_SYMBOLS,
        }
    }
}

/// Combined vault settings returned by `get_settings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VaultSettings {
    pub security: SecuritySettings,
    pub password_generator: PasswordGeneratorSettings,
}

/// Repository for managing settings in the SQLite database.
pub struct SettingsRepository<'a> {
    db: &'a InMemoryDb,
}

impl<'a> SettingsRepository<'a> {
    pub fn new(db: &'a InMemoryDb) -> Self {
        Self { db }
    }

    /// Read raw string value for a key, or None if not set.
    pub fn get_raw(&self, key: &str) -> Result<Option<String>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1;")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            let val: String = row.get(0)?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Set a raw string value for a key (upsert).
    pub fn set_raw(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            params![key, value],
        )?;
        Ok(())
    }

    /// Retrieve all vault settings, falling back to defaults if not set.
    pub fn get_all(&self) -> Result<VaultSettings> {
        let auto_lock = self
            .get_raw(KEY_AUTO_LOCK)?
            .unwrap_or_else(|| DEFAULT_AUTO_LOCK.to_string());

        let clipboard_timeout = self
            .get_raw(KEY_CLIPBOARD_TIMEOUT)?
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_CLIPBOARD_TIMEOUT);

        let length = self
            .get_raw(KEY_GEN_LENGTH)?
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_GEN_LENGTH);

        let use_uppercase = self
            .get_raw(KEY_GEN_UPPERCASE)?
            .map(|s| s == "true" || s == "1")
            .unwrap_or(DEFAULT_GEN_UPPERCASE);

        let use_lowercase = self
            .get_raw(KEY_GEN_LOWERCASE)?
            .map(|s| s == "true" || s == "1")
            .unwrap_or(DEFAULT_GEN_LOWERCASE);

        let use_numbers = self
            .get_raw(KEY_GEN_NUMBERS)?
            .map(|s| s == "true" || s == "1")
            .unwrap_or(DEFAULT_GEN_NUMBERS);

        let use_symbols = self
            .get_raw(KEY_GEN_SYMBOLS)?
            .map(|s| s == "true" || s == "1")
            .unwrap_or(DEFAULT_GEN_SYMBOLS);

        Ok(VaultSettings {
            security: SecuritySettings {
                auto_lock,
                clipboard_timeout,
            },
            password_generator: PasswordGeneratorSettings {
                length,
                use_uppercase,
                use_lowercase,
                use_numbers,
                use_symbols,
            },
        })
    }

    /// Validates and updates security settings.
    pub fn update_security(&self, settings: &SecuritySettings) -> Result<()> {
        if !ALLOWED_AUTO_LOCK.contains(&settings.auto_lock.as_str()) {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "auto_lock",
                reason: format!(
                    "Invalid auto_lock timeout '{}'. Allowed: {:?}",
                    settings.auto_lock, ALLOWED_AUTO_LOCK
                ),
            }));
        }

        if !ALLOWED_CLIPBOARD_TIMEOUT.contains(&settings.clipboard_timeout) {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "clipboard_timeout",
                reason: format!(
                    "Invalid clipboard_timeout '{}'. Allowed: {:?}",
                    settings.clipboard_timeout, ALLOWED_CLIPBOARD_TIMEOUT
                ),
            }));
        }

        self.set_raw(KEY_AUTO_LOCK, &settings.auto_lock)?;
        self.set_raw(
            KEY_CLIPBOARD_TIMEOUT,
            &settings.clipboard_timeout.to_string(),
        )?;

        Ok(())
    }

    /// Validates and updates password generator settings.
    pub fn update_password_generator(&self, settings: &PasswordGeneratorSettings) -> Result<()> {
        if settings.length < crate::commands::password::MIN_PASSWORD_LENGTH
            || settings.length > crate::commands::password::MAX_PASSWORD_LENGTH
        {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "length",
                reason: format!(
                    "Password generator length must be between {} and {}.",
                    crate::commands::password::MIN_PASSWORD_LENGTH,
                    crate::commands::password::MAX_PASSWORD_LENGTH
                ),
            }));
        }

        if !settings.use_uppercase
            && !settings.use_lowercase
            && !settings.use_numbers
            && !settings.use_symbols
        {
            return Err(AppError::Database(DatabaseError::InvalidInput {
                field: "character_classes",
                reason: "At least one character class must be enabled.".to_string(),
            }));
        }

        self.set_raw(KEY_GEN_LENGTH, &settings.length.to_string())?;
        self.set_raw(
            KEY_GEN_UPPERCASE,
            if settings.use_uppercase {
                "true"
            } else {
                "false"
            },
        )?;
        self.set_raw(
            KEY_GEN_LOWERCASE,
            if settings.use_lowercase {
                "true"
            } else {
                "false"
            },
        )?;
        self.set_raw(
            KEY_GEN_NUMBERS,
            if settings.use_numbers {
                "true"
            } else {
                "false"
            },
        )?;
        self.set_raw(
            KEY_GEN_SYMBOLS,
            if settings.use_symbols {
                "true"
            } else {
                "false"
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_defaults_and_upsert() {
        let db = InMemoryDb::create_empty().unwrap();
        let repo = SettingsRepository::new(&db);

        // 1. Initially empty -> defaults
        let s = repo.get_all().unwrap();
        assert_eq!(s.security.auto_lock, "5m");
        assert_eq!(s.security.clipboard_timeout, 15);
        assert_eq!(s.password_generator.length, 16);
        assert!(s.password_generator.use_uppercase);
        assert!(s.password_generator.use_lowercase);
        assert!(s.password_generator.use_numbers);
        assert!(s.password_generator.use_symbols);

        // 2. Update security settings valid
        repo.update_security(&SecuritySettings {
            auto_lock: "15m".to_string(),
            clipboard_timeout: 30,
        })
        .unwrap();

        let s2 = repo.get_all().unwrap();
        assert_eq!(s2.security.auto_lock, "15m");
        assert_eq!(s2.security.clipboard_timeout, 30);

        // 3. Update security settings invalid
        assert!(repo
            .update_security(&SecuritySettings {
                auto_lock: "2m".to_string(),
                clipboard_timeout: 30,
            })
            .is_err());
        assert!(repo
            .update_security(&SecuritySettings {
                auto_lock: "15m".to_string(),
                clipboard_timeout: 25,
            })
            .is_err());

        // 4. Update generator settings valid
        repo.update_password_generator(&PasswordGeneratorSettings {
            length: 32,
            use_uppercase: true,
            use_lowercase: false,
            use_numbers: true,
            use_symbols: false,
        })
        .unwrap();

        let s3 = repo.get_all().unwrap();
        assert_eq!(s3.password_generator.length, 32);
        assert!(s3.password_generator.use_uppercase);
        assert!(!s3.password_generator.use_lowercase);
        assert!(s3.password_generator.use_numbers);
        assert!(!s3.password_generator.use_symbols);

        // 5. Update generator settings invalid length
        assert!(repo
            .update_password_generator(&PasswordGeneratorSettings {
                length: 5, // < 8
                use_uppercase: true,
                use_lowercase: true,
                use_numbers: true,
                use_symbols: true,
            })
            .is_err());

        assert!(repo
            .update_password_generator(&PasswordGeneratorSettings {
                length: 300, // > 256
                use_uppercase: true,
                use_lowercase: true,
                use_numbers: true,
                use_symbols: true,
            })
            .is_err());

        // 6. Update generator settings all false
        assert!(repo
            .update_password_generator(&PasswordGeneratorSettings {
                length: 16,
                use_uppercase: false,
                use_lowercase: false,
                use_numbers: false,
                use_symbols: false,
            })
            .is_err());
    }
}
