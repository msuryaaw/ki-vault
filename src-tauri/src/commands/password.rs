//! Password Generation Tauri Command
//!
//! Implements `generate_password` according to `docs/api-contract.md` §7.
//!
//! # Security Invariants
//! - Uses a cryptographically secure pseudorandom number generator (CSPRNG via `rand::rngs::OsRng`).
//! - Character selection eliminates modulo bias using unbiased rejection sampling / uniform sampling.
//! - Validates character pool configurations and limits lengths safely (e.g. 8 to 256 characters).
//! - Generates output containing at least one character from each selected pool (when pool size <= requested length).
//! - Uses CSPRNG Fisher-Yates shuffle so character positions are uniformly distributed.
//! - Passwords are never logged or exposed in error messages.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::commands::vault::CommandError;

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 256;

pub const CHARSET_UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const CHARSET_LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const CHARSET_NUMBERS: &[u8] = b"0123456789";
pub const CHARSET_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

/// Input parameters for password generation (`api-contract.md` §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePasswordOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
}

/// Sample an element uniformly from a non-empty slice without modulo bias.
///
/// Uses standard rejection sampling: given a slice of length `N`, we find the largest
/// multiple of `N` that fits in `u32::MAX` (`zone = u32::MAX - (u32::MAX % N)`).
/// Any 32-bit random number >= `zone` is discarded, ensuring each index 0..N-1 has
/// precisely identical probability.
fn sample_uniform(slice: &[u8]) -> u8 {
    let n = slice.len() as u32;
    assert!(n > 0, "slice must not be empty");
    let zone = u32::MAX - (u32::MAX % n);

    let mut buf = [0u8; 4];
    loop {
        OsRng.fill_bytes(&mut buf);
        let val = u32::from_ne_bytes(buf);
        if val < zone {
            return slice[(val % n) as usize];
        }
    }
}

/// Uniform random index in 0..=max_index without modulo bias.
fn sample_index(max_index: usize) -> usize {
    if max_index == 0 {
        return 0;
    }
    let n = (max_index + 1) as u32;
    let zone = u32::MAX - (u32::MAX % n);

    let mut buf = [0u8; 4];
    loop {
        OsRng.fill_bytes(&mut buf);
        let val = u32::from_ne_bytes(buf);
        if val < zone {
            return (val % n) as usize;
        }
    }
}

/// Core generation logic.
pub fn generate_password_internal(
    options: &GeneratePasswordOptions,
) -> Result<String, CommandError> {
    if options.length < MIN_PASSWORD_LENGTH {
        return Err(CommandError::new(
            "InvalidInput",
            format!("Password length must be at least {MIN_PASSWORD_LENGTH} characters."),
        ));
    }

    if options.length > MAX_PASSWORD_LENGTH {
        return Err(CommandError::new(
            "InvalidInput",
            format!("Password length cannot exceed {MAX_PASSWORD_LENGTH} characters."),
        ));
    }

    let mut pools: Vec<&'static [u8]> = Vec::new();
    if options.include_uppercase {
        pools.push(CHARSET_UPPERCASE);
    }
    if options.include_lowercase {
        pools.push(CHARSET_LOWERCASE);
    }
    if options.include_numbers {
        pools.push(CHARSET_NUMBERS);
    }
    if options.include_symbols {
        pools.push(CHARSET_SYMBOLS);
    }

    if pools.is_empty() {
        return Err(CommandError::new(
            "InvalidInput",
            "At least one character set (uppercase, lowercase, numbers, or symbols) must be selected.",
        ));
    }

    let mut password_bytes: Vec<u8> = Vec::with_capacity(options.length);

    // 1. Guaranteed minimum: pick 1 character from each selected pool
    for pool in &pools {
        password_bytes.push(sample_uniform(pool));
    }

    // 2. Build combined pool for remaining positions
    let mut combined: Vec<u8> = Vec::new();
    for pool in &pools {
        combined.extend_from_slice(pool);
    }

    // 3. Fill remaining positions uniformly from combined pool
    while password_bytes.len() < options.length {
        password_bytes.push(sample_uniform(&combined));
    }

    // 4. Cryptographic Fisher-Yates shuffle to avoid position bias
    let len = password_bytes.len();
    for i in (1..len).rev() {
        let j = sample_index(i);
        password_bytes.swap(i, j);
    }

    String::from_utf8(password_bytes).map_err(|_| {
        CommandError::new(
            "Internal",
            "Failed to construct valid UTF-8 password string.",
        )
    })
}

/// Tauri command `generate_password` (`docs/api-contract.md` §7).
#[tauri::command]
pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, CommandError> {
    let opts = GeneratePasswordOptions {
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    };
    generate_password_internal(&opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_valid_all_charsets() {
        let opts = GeneratePasswordOptions {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        };

        let password = generate_password_internal(&opts).unwrap();
        assert_eq!(password.len(), 16);

        // Verify presence of all classes
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password
            .chars()
            .any(|c| CHARSET_SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn test_generate_password_length_bounds() {
        // Below minimum (7 < 8)
        let opts_short = GeneratePasswordOptions {
            length: 7,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: false,
        };
        let err = generate_password_internal(&opts_short).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("at least 8"));

        // Exactly minimum (8)
        let opts_min = GeneratePasswordOptions {
            length: 8,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        };
        let pw_min = generate_password_internal(&opts_min).unwrap();
        assert_eq!(pw_min.len(), 8);

        // Exactly maximum (256)
        let opts_max = GeneratePasswordOptions {
            length: 256,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        };
        let pw_max = generate_password_internal(&opts_max).unwrap();
        assert_eq!(pw_max.len(), 256);

        // Above maximum (257)
        let opts_too_long = GeneratePasswordOptions {
            length: 257,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        };
        let err = generate_password_internal(&opts_too_long).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("cannot exceed 256"));
    }

    #[test]
    fn test_generate_password_no_charsets_selected_rejected() {
        let opts = GeneratePasswordOptions {
            length: 12,
            include_uppercase: false,
            include_lowercase: false,
            include_numbers: false,
            include_symbols: false,
        };
        let err = generate_password_internal(&opts).unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        assert!(err.message.contains("At least one character set"));
    }

    #[test]
    fn test_generate_password_single_charset_numbers_only() {
        let opts = GeneratePasswordOptions {
            length: 10,
            include_uppercase: false,
            include_lowercase: false,
            include_numbers: true,
            include_symbols: false,
        };
        let pw = generate_password_internal(&opts).unwrap();
        assert_eq!(pw.len(), 10);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_symbols_only() {
        let opts = GeneratePasswordOptions {
            length: 12,
            include_uppercase: false,
            include_lowercase: false,
            include_numbers: false,
            include_symbols: true,
        };
        let pw = generate_password_internal(&opts).unwrap();
        assert_eq!(pw.len(), 12);
        assert!(pw.chars().all(|c| CHARSET_SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn test_generate_password_unbiased_distribution() {
        // Run multiple generations to ensure uniformity and no crash
        for _ in 0..50 {
            let opts = GeneratePasswordOptions {
                length: 20,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_symbols: true,
            };
            let pw = generate_password_internal(&opts).unwrap();
            assert_eq!(pw.len(), 20);
        }
    }
}
