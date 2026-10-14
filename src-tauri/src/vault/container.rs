use crate::errors::{Result, VaultError};
use crate::vault::cbor::VaultHeader;
use crate::vault::{FixedPrefix, FIXED_PREFIX_LEN, MAX_CIPHERTEXT_LEN, MAX_HEADER_LEN};

/// Parsed `.kivault` container components in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultContainer {
    pub prefix: FixedPrefix,
    pub header: VaultHeader,
    pub header_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Assemble a complete `.kivault` binary container.
///
/// Physical layout (§2 & §3 of `vault-format.md`):
/// ```text
/// fixed_prefix[24] || header[header_length] || encrypted_payload[ciphertext_length]
/// ```
///
/// - `header`: The validated `VaultHeader`.
/// - `ciphertext`: Encrypted SQLite bytes including the 16-byte authentication tag.
///
/// Verifies length bounds and prefix consistency before assembly.
pub fn build_container(header: &VaultHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let header_bytes = header.to_cbor();
    let header_len = header_bytes.len();
    let ciphertext_len = ciphertext.len();

    if header_len > MAX_HEADER_LEN as usize {
        return Err(VaultError::HeaderLengthOutOfBounds(header_len as u64).into());
    }

    if ciphertext_len < 16 || ciphertext_len > MAX_CIPHERTEXT_LEN as usize {
        return Err(VaultError::CiphertextLengthOutOfBounds(ciphertext_len as u64).into());
    }

    let prefix = FixedPrefix::new_v1(header_len as u32, ciphertext_len as u64)?;
    let total_size = prefix.expected_file_size()?;

    let mut container = Vec::with_capacity(total_size as usize);
    container.extend_from_slice(&prefix.to_bytes());
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(ciphertext);

    Ok(container)
}

/// Parse and validate a `.kivault` binary container from an untrusted byte slice.
///
/// Validation sequence (§4.2 of `vault-format.md`):
/// 1. Parse and validate the 24-byte fixed prefix.
/// 2. Validate prefix bounds and checked total size arithmetic.
/// 3. Verify physical buffer size matches `expected_file_size` exactly (no truncation, no trailing bytes).
/// 4. Extract and parse the canonical deterministic CBOR header.
/// 5. Verify that prefix `header_length` exactly matches `header_bytes.len()`.
/// 6. Verify that prefix `ciphertext_length` exactly matches `ciphertext.len()`.
pub fn parse_container(bytes: &[u8]) -> Result<VaultContainer> {
    // 1. Parse fixed prefix
    let prefix = FixedPrefix::parse_slice(bytes)?;

    // 2. Validate expected size
    let expected_size = prefix.expected_file_size()?;
    let actual_size = bytes.len() as u64;

    if actual_size < expected_size {
        return Err(VaultError::UnexpectedEof {
            expected: expected_size as usize,
            actual: actual_size as usize,
        }
        .into());
    }

    if actual_size > expected_size {
        return Err(
            VaultError::TrailingContainerBytes((actual_size - expected_size) as usize).into(),
        );
    }

    // 3. Extract header bytes
    let header_len = prefix.header_length as usize;
    let header_start = FIXED_PREFIX_LEN;
    let header_end = header_start + header_len;

    let header_bytes = &bytes[header_start..header_end];
    let header = VaultHeader::from_cbor(header_bytes)?;

    // Re-verify that encoded header matches declared prefix length
    let canonical_cbor = header.to_cbor();
    if canonical_cbor.len() != header_len {
        return Err(VaultError::HeaderLengthMismatch {
            prefix_len: prefix.header_length,
            actual_len: canonical_cbor.len(),
        }
        .into());
    }

    // 4. Extract ciphertext bytes
    let ciphertext_len = prefix.ciphertext_length as usize;
    let ciphertext_start = header_end;
    let ciphertext_end = ciphertext_start + ciphertext_len;

    let ciphertext = bytes[ciphertext_start..ciphertext_end].to_vec();
    if ciphertext.len() != ciphertext_len {
        return Err(VaultError::CiphertextLengthMismatch {
            prefix_len: prefix.ciphertext_length,
            actual_len: ciphertext.len(),
        }
        .into());
    }

    Ok(VaultContainer {
        prefix,
        header,
        header_bytes: header_bytes.to_vec(),
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::cbor::VaultHeaderParams;

    fn create_test_header() -> VaultHeader {
        VaultHeader::new_v1(VaultHeaderParams {
            vault_id: [0x42; 16],
            created_at: 1776123456,
            schema_version: 1,
            minimum_reader: 1,
            kdf_salt: [0x11; 32],
            wrap_nonce: [0x22; 12],
            wrapped_vdk: [0x33; 48],
            payload_kdf_salt: [0x44; 32],
            payload_nonce: [0x55; 12],
        })
        .expect("test header creation must succeed")
    }

    #[test]
    fn test_container_build_and_parse_roundtrip() {
        let header = create_test_header();
        let ciphertext = b"Sample encrypted SQLite ciphertext + 16B tag!!"; // 46 bytes >= 16

        let container_bytes =
            build_container(&header, ciphertext).expect("build container succeeds");

        let parsed = parse_container(&container_bytes).expect("parse container succeeds");

        assert_eq!(parsed.header, header);
        assert_eq!(parsed.ciphertext, ciphertext);
        assert_eq!(parsed.header_bytes, header.to_cbor());
        assert_eq!(
            parsed.prefix.header_length as usize,
            parsed.header_bytes.len()
        );
        assert_eq!(parsed.prefix.ciphertext_length as usize, ciphertext.len());
        assert_eq!(
            container_bytes.len() as u64,
            parsed.prefix.expected_file_size().unwrap()
        );
    }

    #[test]
    fn test_container_rejects_truncated_at_prefix() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let container_bytes = build_container(&header, &ciphertext).unwrap();

        // Truncate inside prefix (< 24 bytes)
        let res = parse_container(&container_bytes[..20]);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::UnexpectedEof {
                expected: 24,
                actual: 20
            }))
        ));
    }

    #[test]
    fn test_container_rejects_truncated_at_header() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let container_bytes = build_container(&header, &ciphertext).unwrap();

        // Truncate halfway through header
        let res = parse_container(&container_bytes[..50]);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::UnexpectedEof { .. }
            ))
        ));
    }

    #[test]
    fn test_container_rejects_truncated_at_ciphertext() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let container_bytes = build_container(&header, &ciphertext).unwrap();

        // Cut off 1 byte from ciphertext
        let cut_len = container_bytes.len() - 1;
        let res = parse_container(&container_bytes[..cut_len]);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::UnexpectedEof { .. }
            ))
        ));
    }

    #[test]
    fn test_container_rejects_trailing_bytes() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let mut container_bytes = build_container(&header, &ciphertext).unwrap();

        // Append 5 extra trailing bytes
        container_bytes.extend_from_slice(b"extra");

        let res = parse_container(&container_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::TrailingContainerBytes(5)
            ))
        ));
    }

    #[test]
    fn test_container_rejects_invalid_magic() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let mut container_bytes = build_container(&header, &ciphertext).unwrap();

        // Corrupt magic
        container_bytes[0] = b'X';

        let res = parse_container(&container_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::InvalidMagic(_)))
        ));
    }

    #[test]
    fn test_container_rejects_unsupported_version() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let mut container_bytes = build_container(&header, &ciphertext).unwrap();

        // Major version = 2 (byte 8)
        container_bytes[8] = 2;

        let res = parse_container(&container_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::UnsupportedVersion { major: 2, minor: 0 }
            ))
        ));
    }

    #[test]
    fn test_container_rejects_ciphertext_out_of_bounds() {
        let header = create_test_header();

        // Less than 16 bytes auth tag
        let tiny_ciphertext = vec![0xaa; 15];
        let res = build_container(&header, &tiny_ciphertext);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::CiphertextLengthOutOfBounds(15)
            ))
        ));
    }

    #[test]
    fn test_container_rejects_prefix_header_length_mismatch() {
        let header = create_test_header();
        let ciphertext = vec![0xaa; 32];
        let mut container_bytes = build_container(&header, &ciphertext).unwrap();

        // Tamper prefix header_length (increase by 1)
        let orig_header_len = u32::from_le_bytes([
            container_bytes[12],
            container_bytes[13],
            container_bytes[14],
            container_bytes[15],
        ]);
        let tampered_len = orig_header_len + 1;
        container_bytes[12..16].copy_from_slice(&tampered_len.to_le_bytes());

        // Also add 1 dummy byte at end so total size matches prefix
        container_bytes.push(0x00);

        let res = parse_container(&container_bytes);
        assert!(
            matches!(
                res,
                Err(crate::errors::AppError::Vault(
                    VaultError::HeaderLengthMismatch { .. }
                ))
            ) || matches!(
                res,
                Err(crate::errors::AppError::Vault(
                    VaultError::TrailingHeaderBytes(_)
                ))
            )
        );
    }
}
