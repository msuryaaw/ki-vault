use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::{CryptoError, Result};

/// Generate a 32-byte cryptographically secure random salt for Argon2id.
pub fn generate_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| CryptoError::RngError(format!("Failed to generate salt: {e}")))?;
    Ok(salt)
}

/// Generate a 12-byte cryptographically secure random nonce for AES-256-GCM.
pub fn generate_nonce() -> Result<[u8; 12]> {
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RngError(format!("Failed to generate nonce: {e}")))?;
    Ok(nonce)
}

/// Generate a 32-byte cryptographically secure random Vault Data Key (VDK), wrapped in Zeroizing.
pub fn generate_vdk() -> Result<Zeroizing<[u8; 32]>> {
    let mut vdk = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(vdk.as_mut())
        .map_err(|e| CryptoError::RngError(format!("Failed to generate VDK: {e}")))?;
    Ok(vdk)
}

/// Generate a 16-byte cryptographically secure raw UUIDv4 identifier for vault_id.
///
/// Sets RFC 4122 version 4 (bits 4..7 of octet 6 = 0100) and variant 1 (bits 6..7 of octet 8 = 10).
pub fn generate_vault_id() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CryptoError::RngError(format!("Failed to generate vault_id: {e}")))?;

    let uuid = uuid::Builder::from_random_bytes(bytes).into_uuid();
    Ok(*uuid.as_bytes())
}

pub const ARGON2_MEMORY_KIB: u32 = 131072; // 128 MiB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_KEY_LEN: usize = 32;

/// Derive a 32-byte Key Encryption Key (KEK) using Argon2id v1.3.
///
/// Parameters:
/// - Memory: 128 MiB (131072 KiB)
/// - Iterations: 3
/// - Parallelism (lanes): 4
/// - Output: 32 bytes (256-bit KEK) wrapped in Zeroizing
/// - Salt: 32 bytes
///
/// Neither password nor salt is trimmed, normalized, or logged.
pub fn derive_kek(password: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|e| CryptoError::Argon2Error(format!("Invalid Argon2id parameters: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, kek.as_mut())
        .map_err(|e| CryptoError::Argon2Error(format!("Argon2id KEK derivation failed: {e}")))?;

    Ok(kek)
}

pub const VDK_WRAP_CONTEXT_LABEL: &[u8; 19] = b"kivault-vdk-wrap-v1";
pub const VDK_WRAP_AAD_LEN: usize = 71;

/// Build the 71-byte Associated Authenticated Data (AAD) for VDK wrapping.
///
/// Layout (§11.1 of vault-format.md):
/// - Offset 0..19: Context label ASCII `kivault-vdk-wrap-v1` (19 bytes)
/// - Offset 19..21: `format_major` as u16 little-endian (2 bytes)
/// - Offset 21..23: `format_minor` as u16 little-endian (2 bytes)
/// - Offset 23..39: `vault_id` raw UUIDv4 bytes (16 bytes)
/// - Offset 39..71: `kdf_salt` raw bytes (32 bytes)
///
/// Total length: exactly 71 bytes.
pub fn build_vdk_wrap_aad(
    format_major: u16,
    format_minor: u16,
    vault_id: &[u8; 16],
    kdf_salt: &[u8; 32],
) -> [u8; VDK_WRAP_AAD_LEN] {
    let mut aad = [0u8; VDK_WRAP_AAD_LEN];
    aad[0..19].copy_from_slice(VDK_WRAP_CONTEXT_LABEL);
    aad[19..21].copy_from_slice(&format_major.to_le_bytes());
    aad[21..23].copy_from_slice(&format_minor.to_le_bytes());
    aad[23..39].copy_from_slice(vault_id);
    aad[39..71].copy_from_slice(kdf_salt);
    aad
}

/// Wrap (encrypt) the 32-byte Vault Data Key (VDK) using AES-256-GCM.
///
/// - Ciphertext length: 32 bytes plaintext + 16 bytes auth tag = 48 bytes.
/// - Authenticated with 71-byte AAD.
/// - Nonce: 12-byte wrap_nonce.
pub fn wrap_vdk(
    kek: &[u8; 32],
    vdk: &[u8; 32],
    wrap_nonce: &[u8; 12],
    aad: &[u8; VDK_WRAP_AAD_LEN],
) -> Result<[u8; 48]> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let key = Key::<Aes256Gcm>::from_slice(kek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(wrap_nonce);

    let payload = Payload {
        msg: vdk,
        aad: aad.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(format!("VDK wrap encryption failed: {e}")))?;

    if ciphertext.len() != 48 {
        return Err(CryptoError::EncryptionError(format!(
            "Unexpected wrapped VDK length: expected 48, got {}",
            ciphertext.len()
        ))
        .into());
    }

    let mut result = [0u8; 48];
    result.copy_from_slice(&ciphertext);
    Ok(result)
}

/// Unwrap (decrypt) the 48-byte wrapped Vault Data Key using AES-256-GCM.
///
/// - Output: 32-byte VDK wrapped in Zeroizing.
/// - Authenticated with 71-byte AAD.
/// - In case of tag mismatch or corruption, safely returns CryptoError::TagVerificationFailed.
pub fn unwrap_vdk(
    kek: &[u8; 32],
    wrapped_vdk: &[u8; 48],
    wrap_nonce: &[u8; 12],
    aad: &[u8; VDK_WRAP_AAD_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let key = Key::<Aes256Gcm>::from_slice(kek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(wrap_nonce);

    let payload = Payload {
        msg: wrapped_vdk,
        aad: aad.as_slice(),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::TagVerificationFailed)?;

    if plaintext.len() != 32 {
        return Err(CryptoError::DecryptionError(format!(
            "Unexpected unwrapped VDK length: expected 32, got {}",
            plaintext.len()
        ))
        .into());
    }

    let mut vdk = Zeroizing::new([0u8; 32]);
    vdk.copy_from_slice(&plaintext);
    Ok(vdk)
}

pub const HKDF_PAYLOAD_INFO: &[u8; 26] = b"kivault-payload-encryption";

/// Derive a 32-byte Payload Encryption Key (PEK) using HKDF-SHA256.
///
/// Parameters:
/// - PRK = HKDF-Extract(salt = payload_kdf_salt, IKM = VDK)
/// - PEK = HKDF-Expand(PRK, info = b"kivault-payload-encryption", L = 32)
///
/// Output: 32 bytes wrapped in Zeroizing.
pub fn derive_pek(vdk: &[u8; 32], payload_kdf_salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(payload_kdf_salt), vdk);
    let mut pek = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_PAYLOAD_INFO, pek.as_mut())
        .map_err(|e| CryptoError::HkdfError(format!("HKDF-SHA256 expansion failed: {e}")))?;

    Ok(pek)
}

pub const PAYLOAD_CONTEXT_LABEL: &[u8; 18] = b"kivault-payload-v1";
pub const CONTAINER_MAGIC: &[u8; 8] = b"KIVAULT\0";
pub const PAYLOAD_AAD_LEN: usize = 118;
pub const GCM_TAG_LEN: usize = 16;

/// Payload AAD metadata input structure (§11.2 of vault-format.md).
#[derive(Debug, Clone, Copy)]
pub struct PayloadAadParams<'a> {
    pub format_major: u16,
    pub format_minor: u16,
    pub header_length: u32,
    pub created_at: u64,
    pub vault_id: &'a [u8; 16],
    pub schema_version: u32,
    pub minimum_reader: u32,
    pub payload_kdf_salt: &'a [u8; 32],
    pub payload_nonce: &'a [u8; 12],
    pub ciphertext_length: u64,
}

/// Build the 118-byte Associated Authenticated Data (AAD) for payload encryption/decryption.
///
/// Layout (§11.2 of vault-format.md):
/// - Offset 0..18: Context label ASCII `kivault-payload-v1` (18 bytes)
/// - Offset 18..26: Magic bytes ASCII `KIVAULT\0` (8 bytes)
/// - Offset 26..28: `format_major` as u16 little-endian (2 bytes)
/// - Offset 28..30: `format_minor` as u16 little-endian (2 bytes)
/// - Offset 30..34: `header_length` as u32 little-endian (4 bytes)
/// - Offset 34..42: `created_at` as u64 little-endian (8 bytes, Unix epoch UTC seconds)
/// - Offset 42..58: `vault_id` raw UUID bytes (16 bytes)
/// - Offset 58..62: `schema_version` as u32 little-endian (4 bytes)
/// - Offset 62..66: `minimum_reader` as u32 little-endian (4 bytes)
/// - Offset 66..98: `payload_kdf_salt` raw bytes (32 bytes)
/// - Offset 98..110: `payload_nonce` raw bytes (12 bytes)
/// - Offset 110..118: `ciphertext_length` as u64 little-endian (8 bytes, ciphertext plus 16B tag)
///
/// Total length: exactly 118 bytes.
pub fn build_payload_aad(params: &PayloadAadParams) -> [u8; PAYLOAD_AAD_LEN] {
    let mut aad = [0u8; PAYLOAD_AAD_LEN];
    aad[0..18].copy_from_slice(PAYLOAD_CONTEXT_LABEL);
    aad[18..26].copy_from_slice(CONTAINER_MAGIC);
    aad[26..28].copy_from_slice(&params.format_major.to_le_bytes());
    aad[28..30].copy_from_slice(&params.format_minor.to_le_bytes());
    aad[30..34].copy_from_slice(&params.header_length.to_le_bytes());
    aad[34..42].copy_from_slice(&params.created_at.to_le_bytes());
    aad[42..58].copy_from_slice(params.vault_id);
    aad[58..62].copy_from_slice(&params.schema_version.to_le_bytes());
    aad[62..66].copy_from_slice(&params.minimum_reader.to_le_bytes());
    aad[66..98].copy_from_slice(params.payload_kdf_salt);
    aad[98..110].copy_from_slice(params.payload_nonce);
    aad[110..118].copy_from_slice(&params.ciphertext_length.to_le_bytes());
    aad
}

/// Encrypt the vault payload using AES-256-GCM.
///
/// - `pek`: 32-byte Payload Encryption Key.
/// - `nonce`: 12-byte payload nonce.
/// - `aad`: 118-byte authenticated associated data.
/// - `plaintext`: byte slice of the raw payload data (e.g. SQLite database).
///
/// Returns ciphertext with 16-byte authentication tag appended (`Vec<u8>`).
pub fn encrypt_payload(
    pek: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8; PAYLOAD_AAD_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let key = Key::<Aes256Gcm>::from_slice(pek);
    let cipher = Aes256Gcm::new(key);
    let gcm_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad: aad.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(gcm_nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(format!("Payload encryption failed: {e}")))?;

    Ok(ciphertext)
}

/// Decrypt the vault payload using AES-256-GCM.
///
/// - `pek`: 32-byte Payload Encryption Key.
/// - `nonce`: 12-byte payload nonce.
/// - `aad`: 118-byte authenticated associated data.
/// - `ciphertext_with_tag`: ciphertext bytes including 16-byte authentication tag.
///
/// In case of authentication or tag verification failure, returns `CryptoError::TagVerificationFailed`.
pub fn decrypt_payload(
    pek: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8; PAYLOAD_AAD_LEN],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    if ciphertext_with_tag.len() < GCM_TAG_LEN {
        return Err(CryptoError::TagVerificationFailed.into());
    }

    let key = Key::<Aes256Gcm>::from_slice(pek);
    let cipher = Aes256Gcm::new(key);
    let gcm_nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: aad.as_slice(),
    };

    let plaintext = cipher
        .decrypt(gcm_nonce, payload)
        .map_err(|_| CryptoError::TagVerificationFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_salt_length_and_non_zero() {
        let salt = generate_salt().expect("salt generation should succeed");
        assert_eq!(salt.len(), 32);
        assert_ne!(salt, [0u8; 32], "salt should not be all zeros");
    }

    #[test]
    fn test_generate_nonce_length_and_non_zero() {
        let nonce = generate_nonce().expect("nonce generation should succeed");
        assert_eq!(nonce.len(), 12);
        assert_ne!(nonce, [0u8; 12], "nonce should not be all zeros");
    }

    #[test]
    fn test_generate_vdk_length_and_non_zero() {
        let vdk = generate_vdk().expect("vdk generation should succeed");
        assert_eq!(vdk.len(), 32);
        assert_ne!(*vdk, [0u8; 32], "vdk should not be all zeros");
    }

    #[test]
    fn test_generate_vault_id_rfc4122_v4_compliance() {
        let raw_id = generate_vault_id().expect("vault_id generation should succeed");
        assert_eq!(raw_id.len(), 16);
        assert_ne!(raw_id, [0u8; 16], "vault_id should not be all zeros");

        let parsed = uuid::Uuid::from_bytes(raw_id);
        assert_eq!(parsed.get_version_num(), 4, "UUID version must be 4");
        assert_eq!(
            parsed.get_variant(),
            uuid::Variant::RFC4122,
            "UUID variant must be RFC 4122"
        );

        // Explicit bitwise verification on raw bytes:
        // Byte 6 (time_hi_and_version): bits 4..7 must be 0100 (0x40)
        assert_eq!(
            raw_id[6] & 0xf0,
            0x40,
            "octet 6 version bits must be 0100 (version 4)"
        );
        // Byte 8 (clock_seq_hi_and_reserved): bits 6..7 must be 10 (0x80)
        assert_eq!(
            raw_id[8] & 0xc0,
            0x80,
            "octet 8 variant bits must be 10 (RFC 4122 variant 1)"
        );
    }

    #[test]
    fn test_nonce_uniqueness_1000_samples() {
        let mut seen = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let nonce = generate_nonce().expect("nonce generation should succeed");
            assert!(
                seen.insert(nonce),
                "collision detected in 1000 generated nonces"
            );
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn test_derive_kek_determinism() {
        let password = b"correct-horse-battery-staple";
        let salt = [42u8; 32];

        let kek1 = derive_kek(password, &salt).expect("derivation 1 should succeed");
        let kek2 = derive_kek(password, &salt).expect("derivation 2 should succeed");

        assert_eq!(
            *kek1, *kek2,
            "same password and salt must produce identical KEK"
        );
        assert_eq!(kek1.len(), 32);
        assert_ne!(*kek1, [0u8; 32]);
    }

    #[test]
    fn test_derive_kek_different_passwords() {
        let salt = [42u8; 32];
        let kek1 = derive_kek(b"password-alpha", &salt).expect("derivation 1 should succeed");
        let kek2 = derive_kek(b"password-beta", &salt).expect("derivation 2 should succeed");

        assert_ne!(
            *kek1, *kek2,
            "different passwords must produce distinct KEKs"
        );
    }

    #[test]
    fn test_derive_kek_different_salts() {
        let password = b"same-password";
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];

        let kek1 = derive_kek(password, &salt1).expect("derivation 1 should succeed");
        let kek2 = derive_kek(password, &salt2).expect("derivation 2 should succeed");

        assert_ne!(*kek1, *kek2, "different salts must produce distinct KEKs");
    }

    #[test]
    fn test_vdk_wrap_aad_golden_vector() {
        let format_major: u16 = 1;
        let format_minor: u16 = 0;
        let vault_id: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let kdf_salt: [u8; 32] = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
            0x2d, 0x2e, 0x2f, 0x30,
        ];

        // 71-byte golden vector constructed strictly from vault-format.md §11.1
        // [0..19]   "kivault-vdk-wrap-v1"
        // [19..21]  format_major = 1 (u16 le: 0x01, 0x00)
        // [21..23]  format_minor = 0 (u16 le: 0x00, 0x00)
        // [23..39]  vault_id = 0x01..0x10
        // [39..71]  kdf_salt = 0x11..0x30
        const EXPECTED_VDK_WRAP_AAD: [u8; 71] = [
            b'k', b'i', b'v', b'a', b'u', b'l', b't', b'-', b'v', b'd', b'k', b'-', b'w', b'r',
            b'a', b'p', b'-', b'v', b'1', // 19 bytes context label
            0x01, 0x00, // format_major = 1 (u16 LE)
            0x00, 0x00, // format_minor = 0 (u16 LE)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, // 16 bytes vault_id
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
            0x2d, 0x2e, 0x2f, 0x30, // 32 bytes kdf_salt
        ];

        let aad = build_vdk_wrap_aad(format_major, format_minor, &vault_id, &kdf_salt);
        assert_eq!(aad, EXPECTED_VDK_WRAP_AAD);
    }

    #[test]
    fn test_vdk_wrap_unwrap_roundtrip() {
        let kek = [0x55u8; 32];
        let vdk = [0x77u8; 32];
        let wrap_nonce = generate_nonce().expect("nonce generation should succeed");
        let vault_id = generate_vault_id().expect("vault_id generation should succeed");
        let salt = generate_salt().expect("salt generation should succeed");
        let aad = build_vdk_wrap_aad(1, 0, &vault_id, &salt);

        let wrapped = wrap_vdk(&kek, &vdk, &wrap_nonce, &aad).expect("wrap should succeed");
        assert_eq!(wrapped.len(), 48);
        assert_ne!(
            &wrapped[..32],
            &vdk,
            "ciphertext must differ from plaintext"
        );

        let unwrapped =
            unwrap_vdk(&kek, &wrapped, &wrap_nonce, &aad).expect("unwrap should succeed");
        assert_eq!(
            *unwrapped, vdk,
            "unwrapped VDK must match original plaintext"
        );
    }

    #[test]
    fn test_vdk_unwrap_wrong_kek_fails() {
        let kek_correct = [0x11u8; 32];
        let kek_wrong = [0x22u8; 32];
        let vdk = [0x33u8; 32];
        let wrap_nonce = generate_nonce().unwrap();
        let aad = build_vdk_wrap_aad(1, 0, &[1u8; 16], &[2u8; 32]);

        let wrapped = wrap_vdk(&kek_correct, &vdk, &wrap_nonce, &aad).unwrap();
        let result = unwrap_vdk(&kek_wrong, &wrapped, &wrap_nonce, &aad);

        assert!(matches!(
            result,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_vdk_unwrap_corrupted_ciphertext_fails() {
        let kek = [0x11u8; 32];
        let vdk = [0x33u8; 32];
        let wrap_nonce = generate_nonce().unwrap();
        let aad = build_vdk_wrap_aad(1, 0, &[1u8; 16], &[2u8; 32]);

        let mut wrapped = wrap_vdk(&kek, &vdk, &wrap_nonce, &aad).unwrap();
        // Tamper with ciphertext byte
        wrapped[0] ^= 0xff;

        let result = unwrap_vdk(&kek, &wrapped, &wrap_nonce, &aad);
        assert!(matches!(
            result,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // Tamper with auth tag byte (last 16 bytes)
        wrapped[0] ^= 0xff; // restore
        wrapped[47] ^= 0xff; // tamper tag
        let result_tag = unwrap_vdk(&kek, &wrapped, &wrap_nonce, &aad);
        assert!(matches!(
            result_tag,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_vdk_unwrap_aad_or_nonce_mismatch_fails() {
        let kek = [0x11u8; 32];
        let vdk = [0x33u8; 32];
        let wrap_nonce = generate_nonce().unwrap();
        let vault_id = [1u8; 16];
        let salt = [2u8; 32];
        let aad = build_vdk_wrap_aad(1, 0, &vault_id, &salt);

        let wrapped = wrap_vdk(&kek, &vdk, &wrap_nonce, &aad).unwrap();

        // 1. Mismatch AAD
        let mut corrupted_aad = aad;
        corrupted_aad[0] = b'X';
        let res_aad = unwrap_vdk(&kek, &wrapped, &wrap_nonce, &corrupted_aad);
        assert!(matches!(
            res_aad,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // 2. Mismatch Nonce
        let mut wrong_nonce = wrap_nonce;
        wrong_nonce[0] ^= 0x01;
        let res_nonce = unwrap_vdk(&kek, &wrapped, &wrong_nonce, &aad);
        assert!(matches!(
            res_nonce,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_derive_pek_determinism() {
        let vdk = [0x42u8; 32];
        let salt = [0x99u8; 32];

        let pek1 = derive_pek(&vdk, &salt).expect("derivation 1 should succeed");
        let pek2 = derive_pek(&vdk, &salt).expect("derivation 2 should succeed");

        assert_eq!(
            *pek1, *pek2,
            "identical VDK and salt must yield identical PEK"
        );
        assert_eq!(pek1.len(), 32);
        assert_ne!(*pek1, [0u8; 32]);
    }

    #[test]
    fn test_derive_pek_different_vdk() {
        let salt = [0x99u8; 32];
        let vdk1 = [0x01u8; 32];
        let vdk2 = [0x02u8; 32];

        let pek1 = derive_pek(&vdk1, &salt).expect("derivation 1 should succeed");
        let pek2 = derive_pek(&vdk2, &salt).expect("derivation 2 should succeed");

        assert_ne!(*pek1, *pek2, "different VDKs must produce distinct PEKs");
    }

    #[test]
    fn test_derive_pek_different_salt() {
        let vdk = [0x42u8; 32];
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];

        let pek1 = derive_pek(&vdk, &salt1).expect("derivation 1 should succeed");
        let pek2 = derive_pek(&vdk, &salt2).expect("derivation 2 should succeed");

        assert_ne!(*pek1, *pek2, "different salts must produce distinct PEKs");
    }

    #[test]
    fn test_payload_aad_golden_vector() {
        let vault_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let payload_kdf_salt = [0x55u8; 32];
        let payload_nonce = [0x77u8; 12];

        let params = PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: 512,
            created_at: 1776123456, // 0x69DE3E40 in little-endian
            vault_id: &vault_id,
            schema_version: 1,
            minimum_reader: 1,
            payload_kdf_salt: &payload_kdf_salt,
            payload_nonce: &payload_nonce,
            ciphertext_length: 4096, // 0x00001000 in little-endian
        };

        // 118-byte golden vector constructed strictly from vault-format.md §11.2:
        // [0..18]    "kivault-payload-v1" (18 bytes)
        // [18..26]   "KIVAULT\0" (8 bytes)
        // [26..28]   format_major = 1 (u16 le: 0x01, 0x00)
        // [28..30]   format_minor = 0 (u16 le: 0x00, 0x00)
        // [30..34]   header_length = 512 (u32 le: 0x00, 0x02, 0x00, 0x00)
        // [34..42]   created_at = 1776123456 (u64 le: 0x40, 0x3e, 0xde, 0x69, 0x00, 0x00, 0x00, 0x00)
        // [42..58]   vault_id = 0x01..0x10 (16 bytes)
        // [58..62]   schema_version = 1 (u32 le: 0x01, 0x00, 0x00, 0x00)
        // [62..66]   minimum_reader = 1 (u32 le: 0x01, 0x00, 0x00, 0x00)
        // [66..98]   payload_kdf_salt = 32 x 0x55
        // [98..110]  payload_nonce = 12 x 0x77
        // [110..118] ciphertext_length = 4096 (u64 le: 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        const EXPECTED_PAYLOAD_AAD: [u8; 118] = [
            b'k', b'i', b'v', b'a', b'u', b'l', b't', b'-', b'p', b'a', b'y', b'l', b'o', b'a',
            b'd', b'-', b'v', b'1', // 18 bytes context label
            b'K', b'I', b'V', b'A', b'U', b'L', b'T', 0x00, // 8 bytes magic
            0x01, 0x00, // format_major = 1 (u16 LE)
            0x00, 0x00, // format_minor = 0 (u16 LE)
            0x00, 0x02, 0x00, 0x00, // header_length = 512 (u32 LE)
            0x40, 0x7e, 0xdd, 0x69, 0x00, 0x00, 0x00,
            0x00, // created_at = 1776123456 (0x69dd7e40, u64 LE)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, // 16 bytes vault_id
            0x01, 0x00, 0x00, 0x00, // schema_version = 1 (u32 LE)
            0x01, 0x00, 0x00, 0x00, // minimum_reader = 1 (u32 LE)
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, // 32 bytes payload_kdf_salt
            0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
            0x77, // 12 bytes payload_nonce
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // ciphertext_length = 4096 (u64 LE)
        ];

        let aad = build_payload_aad(&params);
        assert_eq!(aad, EXPECTED_PAYLOAD_AAD);
    }

    #[test]
    fn test_payload_encrypt_decrypt_roundtrip() {
        let pek = [0x33u8; 32];
        let nonce = generate_nonce().unwrap();
        let vault_id = generate_vault_id().unwrap();
        let salt = generate_salt().unwrap();
        let plaintext = b"SQLite format 3\0... sample database content ...";

        let ciphertext_len = (plaintext.len() + GCM_TAG_LEN) as u64;
        let aad = build_payload_aad(&PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: 256,
            created_at: 1000,
            vault_id: &vault_id,
            schema_version: 1,
            minimum_reader: 1,
            payload_kdf_salt: &salt,
            payload_nonce: &nonce,
            ciphertext_length: ciphertext_len,
        });

        let ciphertext = encrypt_payload(&pek, &nonce, &aad, plaintext).expect("encrypt succeeds");
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = decrypt_payload(&pek, &nonce, &aad, &ciphertext).expect("decrypt succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_payload_encrypt_decrypt_empty_plaintext() {
        let pek = [0x55u8; 32];
        let nonce = generate_nonce().unwrap();
        let vault_id = generate_vault_id().unwrap();
        let salt = generate_salt().unwrap();
        let plaintext = b"";

        let ciphertext_len = 16u64; // empty plaintext + 16B tag
        let aad = build_payload_aad(&PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: 256,
            created_at: 1000,
            vault_id: &vault_id,
            schema_version: 1,
            minimum_reader: 1,
            payload_kdf_salt: &salt,
            payload_nonce: &nonce,
            ciphertext_length: ciphertext_len,
        });

        let ciphertext = encrypt_payload(&pek, &nonce, &aad, plaintext).expect("encrypt succeeds");
        assert_eq!(ciphertext.len(), 16); // Only the auth tag

        let decrypted = decrypt_payload(&pek, &nonce, &aad, &ciphertext).expect("decrypt succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_payload_corrupted_ciphertext_or_tag_fails() {
        let pek = [0x33u8; 32];
        let nonce = generate_nonce().unwrap();
        let vault_id = generate_vault_id().unwrap();
        let salt = generate_salt().unwrap();
        let plaintext = b"Sensitive password vault data";

        let ciphertext_len = (plaintext.len() + 16) as u64;
        let aad = build_payload_aad(&PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: 256,
            created_at: 1000,
            vault_id: &vault_id,
            schema_version: 1,
            minimum_reader: 1,
            payload_kdf_salt: &salt,
            payload_nonce: &nonce,
            ciphertext_length: ciphertext_len,
        });

        let mut ciphertext = encrypt_payload(&pek, &nonce, &aad, plaintext).unwrap();

        // 1. Corrupt ciphertext body
        ciphertext[0] ^= 0x01;
        let res_body = decrypt_payload(&pek, &nonce, &aad, &ciphertext);
        assert!(matches!(
            res_body,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // 2. Corrupt auth tag
        ciphertext[0] ^= 0x01; // restore
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0x01; // corrupt tag
        let res_tag = decrypt_payload(&pek, &nonce, &aad, &ciphertext);
        assert!(matches!(
            res_tag,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // 3. Truncated ciphertext (< 16 bytes)
        let res_trunc = decrypt_payload(&pek, &nonce, &aad, &ciphertext[..10]);
        assert!(matches!(
            res_trunc,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }

    #[test]
    fn test_payload_nonce_or_aad_mismatch_fails() {
        let pek = [0x33u8; 32];
        let nonce = generate_nonce().unwrap();
        let vault_id = generate_vault_id().unwrap();
        let salt = generate_salt().unwrap();
        let plaintext = b"Testing AAD binding";

        let ciphertext_len = (plaintext.len() + 16) as u64;
        let aad = build_payload_aad(&PayloadAadParams {
            format_major: 1,
            format_minor: 0,
            header_length: 256,
            created_at: 1000,
            vault_id: &vault_id,
            schema_version: 1,
            minimum_reader: 1,
            payload_kdf_salt: &salt,
            payload_nonce: &nonce,
            ciphertext_length: ciphertext_len,
        });

        let ciphertext = encrypt_payload(&pek, &nonce, &aad, plaintext).unwrap();

        // 1. Mismatched AAD
        let mut tampered_aad = aad;
        tampered_aad[0] = b'X';
        let res_aad = decrypt_payload(&pek, &nonce, &tampered_aad, &ciphertext);
        assert!(matches!(
            res_aad,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));

        // 2. Mismatched Nonce
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0x01;
        let res_nonce = decrypt_payload(&pek, &wrong_nonce, &aad, &ciphertext);
        assert!(matches!(
            res_nonce,
            Err(crate::errors::AppError::Crypto(
                CryptoError::TagVerificationFailed
            ))
        ));
    }
}
