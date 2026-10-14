pub mod cbor;
pub mod container;

use crate::errors::{Result, VaultError};

/// Exact magic bytes for KiVault v1 container: ASCII `KIVAULT\0`.
pub const CONTAINER_MAGIC: &[u8; 8] = b"KIVAULT\0";

/// Supported v1 format major version.
pub const FORMAT_MAJOR_V1: u16 = 1;

/// Supported v1 baseline format minor version.
pub const FORMAT_MINOR_V1: u16 = 0;

/// Length of the fixed prefix in bytes.
pub const FIXED_PREFIX_LEN: usize = 24;

/// Minimum allowed header length in bytes (1 byte).
pub const MIN_HEADER_LEN: u32 = 1;

/// Maximum allowed header length in bytes (64 KiB = 65,536 bytes).
pub const MAX_HEADER_LEN: u32 = 65536;

/// Minimum allowed ciphertext length in bytes (16 bytes = auth tag only).
pub const MIN_CIPHERTEXT_LEN: u64 = 16;

/// Maximum allowed ciphertext length in bytes (512 MiB = 536,870,912 bytes).
pub const MAX_CIPHERTEXT_LEN: u64 = 536870912;

/// Fixed prefix of a `.kivault` physical container file (exactly 24 bytes).
///
/// Physical layout (§3 of `vault-format.md`):
/// - Offset 0..8: `magic` (ASCII bytes `KIVAULT\0`)
/// - Offset 8..10: `format_major` (u16 little-endian, value: 1)
/// - Offset 10..12: `format_minor` (u16 little-endian, value: 0)
/// - Offset 12..16: `header_length` (u32 little-endian, range: 1..=65536)
/// - Offset 16..24: `ciphertext_length` (u64 little-endian, range: 16..=536870912, includes 16B tag)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedPrefix {
    pub format_major: u16,
    pub format_minor: u16,
    pub header_length: u32,
    pub ciphertext_length: u64,
}

impl FixedPrefix {
    /// Create a new `FixedPrefix` with v1 version constants, validating bounds.
    pub fn new_v1(header_length: u32, ciphertext_length: u64) -> Result<Self> {
        let prefix = Self {
            format_major: FORMAT_MAJOR_V1,
            format_minor: FORMAT_MINOR_V1,
            header_length,
            ciphertext_length,
        };
        prefix.validate()?;
        Ok(prefix)
    }

    /// Validate the fields of this prefix against KiVault v1 format rules:
    /// - `format_major == 1` and `format_minor == 0`
    /// - `header_length` in `1..=65536`
    /// - `ciphertext_length` in `16..=536870912`
    /// - Checked arithmetic for expected file size does not overflow `u64`
    pub fn validate(&self) -> Result<()> {
        if self.format_major != FORMAT_MAJOR_V1 || self.format_minor != FORMAT_MINOR_V1 {
            return Err(VaultError::UnsupportedVersion {
                major: self.format_major,
                minor: self.format_minor,
            }
            .into());
        }

        if self.header_length < MIN_HEADER_LEN || self.header_length > MAX_HEADER_LEN {
            return Err(VaultError::HeaderLengthOutOfBounds(self.header_length as u64).into());
        }

        if self.ciphertext_length < MIN_CIPHERTEXT_LEN
            || self.ciphertext_length > MAX_CIPHERTEXT_LEN
        {
            return Err(VaultError::CiphertextLengthOutOfBounds(self.ciphertext_length).into());
        }

        // Validate that total expected size can be computed without overflow
        self.expected_file_size()?;

        Ok(())
    }

    /// Compute expected total physical file size:
    /// `24 + header_length + ciphertext_length`
    ///
    /// Uses checked arithmetic to prevent integer overflow.
    pub fn expected_file_size(&self) -> Result<u64> {
        (FIXED_PREFIX_LEN as u64)
            .checked_add(self.header_length as u64)
            .and_then(|sum| sum.checked_add(self.ciphertext_length))
            .ok_or_else(|| VaultError::SizeArithmeticOverflow.into())
    }

    /// Serialize this prefix to an exact 24-byte array.
    pub fn to_bytes(&self) -> [u8; FIXED_PREFIX_LEN] {
        let mut buf = [0u8; FIXED_PREFIX_LEN];
        buf[0..8].copy_from_slice(CONTAINER_MAGIC);
        buf[8..10].copy_from_slice(&self.format_major.to_le_bytes());
        buf[10..12].copy_from_slice(&self.format_minor.to_le_bytes());
        buf[12..16].copy_from_slice(&self.header_length.to_le_bytes());
        buf[16..24].copy_from_slice(&self.ciphertext_length.to_le_bytes());
        buf
    }

    /// Parse and validate a `FixedPrefix` from an exact 24-byte array.
    pub fn from_bytes(bytes: &[u8; FIXED_PREFIX_LEN]) -> Result<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if &magic != CONTAINER_MAGIC {
            return Err(VaultError::InvalidMagic(magic).into());
        }

        let format_major = u16::from_le_bytes([bytes[8], bytes[9]]);
        let format_minor = u16::from_le_bytes([bytes[10], bytes[11]]);
        let header_length = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let ciphertext_length = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);

        let prefix = Self {
            format_major,
            format_minor,
            header_length,
            ciphertext_length,
        };

        prefix.validate()?;
        Ok(prefix)
    }

    /// Parse and validate a `FixedPrefix` from a slice of untrusted input.
    ///
    /// Fails with `UnexpectedEof` if the slice contains fewer than 24 bytes.
    pub fn parse_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() < FIXED_PREFIX_LEN {
            return Err(VaultError::UnexpectedEof {
                expected: FIXED_PREFIX_LEN,
                actual: slice.len(),
            }
            .into());
        }

        let mut fixed = [0u8; FIXED_PREFIX_LEN];
        fixed.copy_from_slice(&slice[0..FIXED_PREFIX_LEN]);
        Self::from_bytes(&fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_prefix_golden_binary() {
        // Golden vector matching §3 wire representation:
        // magic: "KIVAULT\0"
        // format_major: 1 (u16 LE: 0x01, 0x00)
        // format_minor: 0 (u16 LE: 0x00, 0x00)
        // header_length: 512 (u32 LE: 0x00, 0x02, 0x00, 0x00)
        // ciphertext_length: 4096 (u64 LE: 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        const EXPECTED_PREFIX_BYTES: [u8; 24] = [
            b'K', b'I', b'V', b'A', b'U', b'L', b'T', 0x00, // 8B magic
            0x01, 0x00, // 2B format_major = 1
            0x00, 0x00, // 2B format_minor = 0
            0x00, 0x02, 0x00, 0x00, // 4B header_length = 512
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8B ciphertext_length = 4096
        ];

        let prefix = FixedPrefix::new_v1(512, 4096).expect("prefix creation should succeed");
        assert_eq!(prefix.to_bytes(), EXPECTED_PREFIX_BYTES);

        let parsed =
            FixedPrefix::from_bytes(&EXPECTED_PREFIX_BYTES).expect("golden bytes parse succeeds");
        assert_eq!(parsed, prefix);
        assert_eq!(parsed.expected_file_size().unwrap(), 24 + 512 + 4096);
    }

    #[test]
    fn test_fixed_prefix_roundtrip() {
        let prefix = FixedPrefix::new_v1(128, 1024).expect("valid prefix");
        let bytes = prefix.to_bytes();
        let parsed = FixedPrefix::from_bytes(&bytes).expect("parse roundtrip succeeds");
        assert_eq!(prefix, parsed);
    }

    #[test]
    fn test_fixed_prefix_slice_parsing() {
        let prefix = FixedPrefix::new_v1(256, 2048).unwrap();
        let mut stream = prefix.to_bytes().to_vec();
        stream.extend_from_slice(b"trailing container data that follows prefix");

        let parsed = FixedPrefix::parse_slice(&stream).expect("parse from longer slice succeeds");
        assert_eq!(parsed, prefix);
    }

    #[test]
    fn test_fixed_prefix_unexpected_eof() {
        let short_input = [0u8; 23]; // 1 byte short
        let res = FixedPrefix::parse_slice(&short_input);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::UnexpectedEof {
                expected: 24,
                actual: 23
            }))
        ));
    }

    #[test]
    fn test_fixed_prefix_invalid_magic() {
        let mut bytes = FixedPrefix::new_v1(256, 512).unwrap().to_bytes();
        bytes[0] = b'X'; // Corrupt magic

        let res = FixedPrefix::from_bytes(&bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::InvalidMagic(_)))
        ));
    }

    #[test]
    fn test_fixed_prefix_unsupported_versions() {
        let mut bytes = FixedPrefix::new_v1(256, 512).unwrap().to_bytes();

        // 1. Unsupported major (e.g. 2)
        bytes[8] = 2;
        assert!(matches!(
            FixedPrefix::from_bytes(&bytes),
            Err(crate::errors::AppError::Vault(
                VaultError::UnsupportedVersion { major: 2, minor: 0 }
            ))
        ));

        // 2. Unsupported minor (e.g. 1)
        bytes[8] = 1; // restore major = 1
        bytes[10] = 1; // minor = 1
        assert!(matches!(
            FixedPrefix::from_bytes(&bytes),
            Err(crate::errors::AppError::Vault(
                VaultError::UnsupportedVersion { major: 1, minor: 1 }
            ))
        ));
    }

    #[test]
    fn test_fixed_prefix_bounds_min_max_extremes() {
        // Minimum allowed boundary: header = 1, ciphertext = 16
        let min_prefix = FixedPrefix::new_v1(1, 16).expect("minimum allowed boundary must succeed");
        assert_eq!(min_prefix.header_length, 1);
        assert_eq!(min_prefix.ciphertext_length, 16);
        assert_eq!(min_prefix.expected_file_size().unwrap(), 24 + 1 + 16);

        // Maximum allowed boundary: header = 65536, ciphertext = 536870912
        let max_prefix =
            FixedPrefix::new_v1(65536, 536870912).expect("maximum allowed boundary must succeed");
        assert_eq!(max_prefix.header_length, 65536);
        assert_eq!(max_prefix.ciphertext_length, 536870912);
        assert_eq!(
            max_prefix.expected_file_size().unwrap(),
            24 + 65536 + 536870912
        );

        // Header out of bounds: 0
        assert!(matches!(
            FixedPrefix::new_v1(0, 16),
            Err(crate::errors::AppError::Vault(
                VaultError::HeaderLengthOutOfBounds(0)
            ))
        ));

        // Header out of bounds: 65537
        assert!(matches!(
            FixedPrefix::new_v1(65537, 16),
            Err(crate::errors::AppError::Vault(
                VaultError::HeaderLengthOutOfBounds(65537)
            ))
        ));

        // Ciphertext out of bounds: 15 (less than 16B auth tag)
        assert!(matches!(
            FixedPrefix::new_v1(100, 15),
            Err(crate::errors::AppError::Vault(
                VaultError::CiphertextLengthOutOfBounds(15)
            ))
        ));

        // Ciphertext out of bounds: 536870913 (greater than 512 MiB cap)
        assert!(matches!(
            FixedPrefix::new_v1(100, 536870913),
            Err(crate::errors::AppError::Vault(
                VaultError::CiphertextLengthOutOfBounds(536870913)
            ))
        ));
    }

    #[test]
    fn test_fixed_prefix_arithmetic_overflow_protection() {
        let overflow_prefix = FixedPrefix {
            format_major: 1,
            format_minor: 0,
            header_length: 65536,
            ciphertext_length: u64::MAX - 10,
        };

        // Even if somehow constructed directly, validate() and expected_file_size() catch overflow
        assert!(matches!(
            overflow_prefix.expected_file_size(),
            Err(crate::errors::AppError::Vault(
                VaultError::SizeArithmeticOverflow
            ))
        ));
    }
}
