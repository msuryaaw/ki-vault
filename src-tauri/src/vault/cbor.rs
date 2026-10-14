use crate::errors::{Result, VaultError};

pub const EXPECTED_FIELD_COUNT: usize = 16;
pub const KDF_ALGORITHM_V1: &str = "Argon2id";
pub const WRAP_ALGORITHM_V1: &str = "AES-256-GCM";
pub const PAYLOAD_ALGORITHM_V1: &str = "AES-256-GCM";

pub const KDF_MEMORY_KIB_V1: u32 = 131072;
pub const KDF_ITERATIONS_V1: u32 = 3;
pub const KDF_PARALLELISM_V1: u32 = 4;
pub const KDF_OUTPUT_LENGTH_V1: u32 = 32;

/// Representation of the 16 required fields in the KiVault v1 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub vault_id: [u8; 16],
    pub created_at: u64,
    pub schema_version: u32,
    pub minimum_reader: u32,
    pub kdf_algorithm: String,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_output_length: u32,
    pub kdf_salt: [u8; 32],
    pub wrap_algorithm: String,
    pub wrap_nonce: [u8; 12],
    pub wrapped_vdk: [u8; 48],
    pub payload_kdf_salt: [u8; 32],
    pub payload_algorithm: String,
    pub payload_nonce: [u8; 12],
}

/// Parameters for constructing a new `VaultHeader` in v1 format.
#[derive(Debug, Clone)]
pub struct VaultHeaderParams {
    pub vault_id: [u8; 16],
    pub created_at: u64,
    pub schema_version: u32,
    pub minimum_reader: u32,
    pub kdf_salt: [u8; 32],
    pub wrap_nonce: [u8; 12],
    pub wrapped_vdk: [u8; 48],
    pub payload_kdf_salt: [u8; 32],
    pub payload_nonce: [u8; 12],
}

impl VaultHeader {
    /// Create a new v1 header with default algorithms and baseline Argon2id parameters.
    pub fn new_v1(params: VaultHeaderParams) -> Result<Self> {
        let header = Self {
            vault_id: params.vault_id,
            created_at: params.created_at,
            schema_version: params.schema_version,
            minimum_reader: params.minimum_reader,
            kdf_algorithm: KDF_ALGORITHM_V1.to_string(),
            kdf_memory_kib: KDF_MEMORY_KIB_V1,
            kdf_iterations: KDF_ITERATIONS_V1,
            kdf_parallelism: KDF_PARALLELISM_V1,
            kdf_output_length: KDF_OUTPUT_LENGTH_V1,
            kdf_salt: params.kdf_salt,
            wrap_algorithm: WRAP_ALGORITHM_V1.to_string(),
            wrap_nonce: params.wrap_nonce,
            wrapped_vdk: params.wrapped_vdk,
            payload_kdf_salt: params.payload_kdf_salt,
            payload_algorithm: PAYLOAD_ALGORITHM_V1.to_string(),
            payload_nonce: params.payload_nonce,
        };
        header.validate()?;
        Ok(header)
    }

    /// Validate header values against KiVault v1 format requirements.
    pub fn validate(&self) -> Result<()> {
        if self.kdf_algorithm != KDF_ALGORITHM_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "kdf_algorithm",
                reason: format!(
                    "expected '{}', got '{}'",
                    KDF_ALGORITHM_V1, self.kdf_algorithm
                ),
            }
            .into());
        }

        if self.kdf_memory_kib != KDF_MEMORY_KIB_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "kdf_memory_kib",
                reason: format!(
                    "expected {}, got {}",
                    KDF_MEMORY_KIB_V1, self.kdf_memory_kib
                ),
            }
            .into());
        }

        if self.kdf_iterations != KDF_ITERATIONS_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "kdf_iterations",
                reason: format!(
                    "expected {}, got {}",
                    KDF_ITERATIONS_V1, self.kdf_iterations
                ),
            }
            .into());
        }

        if self.kdf_parallelism != KDF_PARALLELISM_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "kdf_parallelism",
                reason: format!(
                    "expected {}, got {}",
                    KDF_PARALLELISM_V1, self.kdf_parallelism
                ),
            }
            .into());
        }

        if self.kdf_output_length != KDF_OUTPUT_LENGTH_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "kdf_output_length",
                reason: format!(
                    "expected {}, got {}",
                    KDF_OUTPUT_LENGTH_V1, self.kdf_output_length
                ),
            }
            .into());
        }

        if self.wrap_algorithm != WRAP_ALGORITHM_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "wrap_algorithm",
                reason: format!(
                    "expected '{}', got '{}'",
                    WRAP_ALGORITHM_V1, self.wrap_algorithm
                ),
            }
            .into());
        }

        if self.payload_algorithm != PAYLOAD_ALGORITHM_V1 {
            return Err(VaultError::InvalidHeaderField {
                field: "payload_algorithm",
                reason: format!(
                    "expected '{}', got '{}'",
                    PAYLOAD_ALGORITHM_V1, self.payload_algorithm
                ),
            }
            .into());
        }

        Ok(())
    }

    /// Encode this header into RFC 8949 §4.2.1 Core Deterministic CBOR bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        self.validate()
            .expect("header must be valid before encoding");

        // Exactly 16 items in map: header byte 0xa0 | 16 = 0xb0
        let mut buf = Vec::with_capacity(300);
        buf.push(0xb0);

        // 1. kdf_salt (0x68 + "kdf_salt")
        write_text_key(&mut buf, "kdf_salt");
        write_bytes(&mut buf, &self.kdf_salt);

        // 2. vault_id (0x68 + "vault_id")
        write_text_key(&mut buf, "vault_id");
        write_bytes(&mut buf, &self.vault_id);

        // 3. created_at (0x6a + "created_at")
        write_text_key(&mut buf, "created_at");
        write_uint(&mut buf, self.created_at);

        // 4. wrap_nonce (0x6a + "wrap_nonce")
        write_text_key(&mut buf, "wrap_nonce");
        write_bytes(&mut buf, &self.wrap_nonce);

        // 5. wrapped_vdk (0x6b + "wrapped_vdk")
        write_text_key(&mut buf, "wrapped_vdk");
        write_bytes(&mut buf, &self.wrapped_vdk);

        // 6. kdf_algorithm (0x6d + "kdf_algorithm")
        write_text_key(&mut buf, "kdf_algorithm");
        write_text_str(&mut buf, &self.kdf_algorithm);

        // 7. payload_nonce (0x6d + "payload_nonce")
        write_text_key(&mut buf, "payload_nonce");
        write_bytes(&mut buf, &self.payload_nonce);

        // 8. kdf_iterations (0x6e + "kdf_iterations")
        write_text_key(&mut buf, "kdf_iterations");
        write_uint(&mut buf, self.kdf_iterations as u64);

        // 9. kdf_memory_kib (0x6e + "kdf_memory_kib")
        write_text_key(&mut buf, "kdf_memory_kib");
        write_uint(&mut buf, self.kdf_memory_kib as u64);

        // 10. minimum_reader (0x6e + "minimum_reader")
        write_text_key(&mut buf, "minimum_reader");
        write_uint(&mut buf, self.minimum_reader as u64);

        // 11. schema_version (0x6e + "schema_version")
        write_text_key(&mut buf, "schema_version");
        write_uint(&mut buf, self.schema_version as u64);

        // 12. wrap_algorithm (0x6e + "wrap_algorithm")
        write_text_key(&mut buf, "wrap_algorithm");
        write_text_str(&mut buf, &self.wrap_algorithm);

        // 13. kdf_parallelism (0x6f + "kdf_parallelism")
        write_text_key(&mut buf, "kdf_parallelism");
        write_uint(&mut buf, self.kdf_parallelism as u64);

        // 14. payload_kdf_salt (0x70 + "payload_kdf_salt")
        write_text_key(&mut buf, "payload_kdf_salt");
        write_bytes(&mut buf, &self.payload_kdf_salt);

        // 15. kdf_output_length (0x71 + "kdf_output_length")
        write_text_key(&mut buf, "kdf_output_length");
        write_uint(&mut buf, self.kdf_output_length as u64);

        // 16. payload_algorithm (0x71 + "payload_algorithm")
        write_text_key(&mut buf, "payload_algorithm");
        write_text_str(&mut buf, &self.payload_algorithm);

        buf
    }

    /// Parse and validate a `VaultHeader` from RFC 8949 §4.2.1 deterministic CBOR bytes.
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        if cbor_bytes.len() > crate::vault::MAX_HEADER_LEN as usize {
            return Err(VaultError::HeaderLengthOutOfBounds(cbor_bytes.len() as u64).into());
        }

        let mut reader = CborReader::new(cbor_bytes);

        // 1. Read map header
        let map_len = reader.read_map_header()?;
        if map_len != EXPECTED_FIELD_COUNT {
            return Err(VaultError::CborDecodeError(format!(
                "expected exactly {EXPECTED_FIELD_COUNT} map entries, found {map_len}"
            ))
            .into());
        }

        let mut vault_id = None;
        let mut created_at = None;
        let mut schema_version = None;
        let mut minimum_reader = None;
        let mut kdf_algorithm = None;
        let mut kdf_memory_kib = None;
        let mut kdf_iterations = None;
        let mut kdf_parallelism = None;
        let mut kdf_output_length = None;
        let mut kdf_salt = None;
        let mut wrap_algorithm = None;
        let mut wrap_nonce = None;
        let mut wrapped_vdk = None;
        let mut payload_kdf_salt = None;
        let mut payload_algorithm = None;
        let mut payload_nonce = None;

        let mut last_key_cbor: Option<Vec<u8>> = None;
        let mut last_key_name: Option<String> = None;

        for _ in 0..map_len {
            let key_start = reader.offset();
            let key_str = reader.read_text_string()?;
            let key_cbor = reader.slice(key_start, reader.offset()).to_vec();

            // Check duplicate / sorting order (§4.2.1 bytewise-lexicographic order)
            if let Some(ref prev_cbor) = last_key_cbor {
                if prev_cbor == &key_cbor {
                    return Err(VaultError::DuplicateHeaderField(key_str).into());
                }
                if prev_cbor > &key_cbor {
                    return Err(VaultError::UnsortedHeaderKeys {
                        previous: last_key_name.unwrap_or_default(),
                        current: key_str,
                    }
                    .into());
                }
            }
            last_key_cbor = Some(key_cbor);
            last_key_name = Some(key_str.clone());

            match key_str.as_str() {
                "vault_id" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 16 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "vault_id",
                            reason: format!("expected 16 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b);
                    vault_id = Some(arr);
                }
                "created_at" => {
                    let val = reader.read_uint()?;
                    created_at = Some(val);
                }
                "schema_version" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "schema_version",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    schema_version = Some(val as u32);
                }
                "minimum_reader" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "minimum_reader",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    minimum_reader = Some(val as u32);
                }
                "kdf_algorithm" => {
                    kdf_algorithm = Some(reader.read_text_string()?);
                }
                "kdf_memory_kib" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "kdf_memory_kib",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    kdf_memory_kib = Some(val as u32);
                }
                "kdf_iterations" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "kdf_iterations",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    kdf_iterations = Some(val as u32);
                }
                "kdf_parallelism" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "kdf_parallelism",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    kdf_parallelism = Some(val as u32);
                }
                "kdf_output_length" => {
                    let val = reader.read_uint()?;
                    if val > u32::MAX as u64 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "kdf_output_length",
                            reason: "exceeds u32::MAX".to_string(),
                        }
                        .into());
                    }
                    kdf_output_length = Some(val as u32);
                }
                "kdf_salt" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 32 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "kdf_salt",
                            reason: format!("expected 32 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    kdf_salt = Some(arr);
                }
                "wrap_algorithm" => {
                    wrap_algorithm = Some(reader.read_text_string()?);
                }
                "wrap_nonce" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 12 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "wrap_nonce",
                            reason: format!("expected 12 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(b);
                    wrap_nonce = Some(arr);
                }
                "wrapped_vdk" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 48 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "wrapped_vdk",
                            reason: format!("expected 48 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 48];
                    arr.copy_from_slice(b);
                    wrapped_vdk = Some(arr);
                }
                "payload_kdf_salt" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 32 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "payload_kdf_salt",
                            reason: format!("expected 32 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    payload_kdf_salt = Some(arr);
                }
                "payload_algorithm" => {
                    payload_algorithm = Some(reader.read_text_string()?);
                }
                "payload_nonce" => {
                    let b = reader.read_byte_string()?;
                    if b.len() != 12 {
                        return Err(VaultError::InvalidHeaderField {
                            field: "payload_nonce",
                            reason: format!("expected 12 bytes, got {}", b.len()),
                        }
                        .into());
                    }
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(b);
                    payload_nonce = Some(arr);
                }
                other => {
                    return Err(VaultError::UnknownHeaderField(other.to_string()).into());
                }
            }
        }

        // Check trailing bytes
        if reader.has_remaining() {
            return Err(VaultError::TrailingHeaderBytes(reader.remaining_len()).into());
        }

        // Construct header verifying all required fields
        let header = Self {
            vault_id: vault_id.ok_or(VaultError::MissingHeaderField("vault_id"))?,
            created_at: created_at.ok_or(VaultError::MissingHeaderField("created_at"))?,
            schema_version: schema_version
                .ok_or(VaultError::MissingHeaderField("schema_version"))?,
            minimum_reader: minimum_reader
                .ok_or(VaultError::MissingHeaderField("minimum_reader"))?,
            kdf_algorithm: kdf_algorithm.ok_or(VaultError::MissingHeaderField("kdf_algorithm"))?,
            kdf_memory_kib: kdf_memory_kib
                .ok_or(VaultError::MissingHeaderField("kdf_memory_kib"))?,
            kdf_iterations: kdf_iterations
                .ok_or(VaultError::MissingHeaderField("kdf_iterations"))?,
            kdf_parallelism: kdf_parallelism
                .ok_or(VaultError::MissingHeaderField("kdf_parallelism"))?,
            kdf_output_length: kdf_output_length
                .ok_or(VaultError::MissingHeaderField("kdf_output_length"))?,
            kdf_salt: kdf_salt.ok_or(VaultError::MissingHeaderField("kdf_salt"))?,
            wrap_algorithm: wrap_algorithm
                .ok_or(VaultError::MissingHeaderField("wrap_algorithm"))?,
            wrap_nonce: wrap_nonce.ok_or(VaultError::MissingHeaderField("wrap_nonce"))?,
            wrapped_vdk: wrapped_vdk.ok_or(VaultError::MissingHeaderField("wrapped_vdk"))?,
            payload_kdf_salt: payload_kdf_salt
                .ok_or(VaultError::MissingHeaderField("payload_kdf_salt"))?,
            payload_algorithm: payload_algorithm
                .ok_or(VaultError::MissingHeaderField("payload_algorithm"))?,
            payload_nonce: payload_nonce.ok_or(VaultError::MissingHeaderField("payload_nonce"))?,
        };

        header.validate()?;
        Ok(header)
    }
}

// Low-level helper functions for writing shortest/preferred CBOR items
fn write_uint(buf: &mut Vec<u8>, val: u64) {
    if val <= 23 {
        buf.push(val as u8);
    } else if val <= 0xff {
        buf.push(0x18);
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0x19);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0x1a);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0x1b);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

fn write_text_key(buf: &mut Vec<u8>, key: &str) {
    write_text_str(buf, key);
}

fn write_text_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len() as u64;
    if len <= 23 {
        buf.push(0x60 | (len as u8));
    } else if len <= 0xff {
        buf.push(0x78);
        buf.push(len as u8);
    } else {
        panic!("header keys/text values do not exceed 255 bytes in v1");
    }
    buf.extend_from_slice(bytes);
}

fn write_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    let len = b.len() as u64;
    if len <= 23 {
        buf.push(0x40 | (len as u8));
    } else if len <= 0xff {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        panic!("header byte strings do not exceed 255 bytes in v1");
    }
    buf.extend_from_slice(b);
}

/// Strict RFC 8949 §4.2.1 Deterministic CBOR Stream Reader.
struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn offset(&self) -> usize {
        self.pos
    }

    fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        &self.data[start..end]
    }

    fn has_remaining(&self) -> bool {
        self.pos < self.data.len()
    }

    fn remaining_len(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(
                VaultError::CborDecodeError("unexpected end of CBOR stream".to_string()).into(),
            );
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(
                VaultError::CborDecodeError("unexpected end of CBOR bytes".to_string()).into(),
            );
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_header(&mut self, expected_major: u8) -> Result<u64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major != expected_major {
            return Err(VaultError::CborDecodeError(format!(
                "unexpected CBOR major type: expected {expected_major}, got {major}"
            ))
            .into());
        }

        // Check for indefinite length (0x1f = 31)
        if info == 31 {
            return Err(VaultError::CborNonDeterministic(
                "indefinite length CBOR is strictly forbidden in KiVault v1".to_string(),
            )
            .into());
        }

        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let val = self.read_byte()? as u64;
                if val <= 23 {
                    return Err(VaultError::CborNonDeterministic(format!(
                        "non-shortest integer encoding: value {val} encoded in 2 bytes"
                    ))
                    .into());
                }
                Ok(val)
            }
            25 => {
                let bytes = self.read_exact(2)?;
                let val = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
                if val <= 0xff {
                    return Err(VaultError::CborNonDeterministic(format!(
                        "non-shortest integer encoding: value {val} encoded in 3 bytes"
                    ))
                    .into());
                }
                Ok(val)
            }
            26 => {
                let bytes = self.read_exact(4)?;
                let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
                if val <= 0xffff {
                    return Err(VaultError::CborNonDeterministic(format!(
                        "non-shortest integer encoding: value {val} encoded in 5 bytes"
                    ))
                    .into());
                }
                Ok(val)
            }
            27 => {
                let bytes = self.read_exact(8)?;
                let val = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                if val <= 0xffff_ffff {
                    return Err(VaultError::CborNonDeterministic(format!(
                        "non-shortest integer encoding: value {val} encoded in 9 bytes"
                    ))
                    .into());
                }
                Ok(val)
            }
            _ => Err(VaultError::CborDecodeError(format!("unsupported CBOR info {info}")).into()),
        }
    }

    fn read_map_header(&mut self) -> Result<usize> {
        let len = self.read_header(5)?; // Major 5 = map
        if len > 64 {
            return Err(
                VaultError::CborDecodeError(format!("map length {len} exceeds bounds")).into(),
            );
        }
        Ok(len as usize)
    }

    fn read_uint(&mut self) -> Result<u64> {
        self.read_header(0) // Major 0 = uint
    }

    fn read_byte_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_header(2)? as usize; // Major 2 = byte string
        self.read_exact(len)
    }

    fn read_text_string(&mut self) -> Result<String> {
        let len = self.read_header(3)? as usize; // Major 3 = text string
        let bytes = self.read_exact(len)?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|e| {
                VaultError::CborDecodeError(format!("invalid UTF-8 text string: {e}")).into()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header() -> VaultHeader {
        VaultHeader::new_v1(VaultHeaderParams {
            vault_id: [0x01; 16],
            created_at: 1776123456,
            schema_version: 1,
            minimum_reader: 1,
            kdf_salt: [0x02; 32],
            wrap_nonce: [0x03; 12],
            wrapped_vdk: [0x04; 48],
            payload_kdf_salt: [0x05; 32],
            payload_nonce: [0x06; 12],
        })
        .expect("test header creation must succeed")
    }

    #[test]
    fn test_cbor_golden_vector_st028() {
        let header = create_test_header();
        let encoded = header.to_cbor();

        // Exact independent static golden vector for ST-028 (435 bytes)
        const EXPECTED_CBOR_HEX: &str = concat!(
            "b0",
            "686b64665f73616c7458200202020202020202020202020202020202020202020202020202020202020202",
            "687661756c745f69645001010101010101010101010101010101",
            "6a637265617465645f61741a69dd7e40",
            "6a777261705f6e6f6e63654c030303030303030303030303",
            "6b777261707065645f76646b5830040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
            "6d6b64665f616c676f726974686d684172676f6e326964",
            "6d7061796c6f61645f6e6f6e63654c060606060606060606060606",
            "6e6b64665f697465726174696f6e7303",
            "6e6b64665f6d656d6f72795f6b69621a00020000",
            "6e6d696e696d756d5f72656164657201",
            "6e736368656d615f76657273696f6e01",
            "6e777261705f616c676f726974686d6b4145532d3235362d47434d",
            "6f6b64665f706172616c6c656c69736d04",
            "707061796c6f61645f6b64665f73616c7458200505050505050505050505050505050505050505050505050505050505050505",
            "716b64665f6f75747075745f6c656e6774681820",
            "717061796c6f61645f616c676f726974686d6b4145532d3235362d47434d"
        );

        let mut expected_bytes = Vec::with_capacity(EXPECTED_CBOR_HEX.len() / 2);
        for i in (0..EXPECTED_CBOR_HEX.len()).step_by(2) {
            expected_bytes.push(u8::from_str_radix(&EXPECTED_CBOR_HEX[i..i + 2], 16).unwrap());
        }

        assert_eq!(
            encoded, expected_bytes,
            "encoded bytes must exactly match independent golden vector ST-028"
        );
        assert_eq!(encoded.len(), 435);

        let decoded =
            VaultHeader::from_cbor(&expected_bytes).expect("golden CBOR must decode cleanly");
        assert_eq!(decoded, header);
        assert_eq!(
            decoded.to_cbor(),
            expected_bytes,
            "encoding must be byte-for-byte stable"
        );
    }

    #[test]
    fn test_cbor_roundtrip_all_fields() {
        let header = create_test_header();
        let bytes = header.to_cbor();
        let decoded = VaultHeader::from_cbor(&bytes).expect("roundtrip decode succeeds");
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_cbor_rejects_unsorted_keys() {
        let header = create_test_header();
        let bytes = header.to_cbor();

        // Swap the first two key-value pairs
        // Item 1: kdf_salt (length: 1 + 8 + 2 + 32 = 43)
        // Item 2: vault_id (length: 1 + 8 + 1 + 16 = 26)
        let item1 = bytes[1..44].to_vec();
        let item2 = bytes[44..70].to_vec();

        let mut swapped = Vec::new();
        swapped.push(0xb0);
        swapped.extend_from_slice(&item2);
        swapped.extend_from_slice(&item1);
        swapped.extend_from_slice(&bytes[70..]);

        let res = VaultHeader::from_cbor(&swapped);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::UnsortedHeaderKeys { .. }
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_duplicate_keys() {
        let header = create_test_header();
        let bytes = header.to_cbor();

        // Duplicate the first item
        let item1 = bytes[1..44].to_vec();
        let mut dup = Vec::new();
        dup.push(0xb0);
        dup.extend_from_slice(&item1);
        dup.extend_from_slice(&item1);
        dup.extend_from_slice(&bytes[44..]);

        let res = VaultHeader::from_cbor(&dup);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::DuplicateHeaderField(_)
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_unknown_field() {
        // Change "kdf_salt" (68 6b 64 66 5f 73 61 6c 74) to "unknown!" (68 75 6e 6b 6e 6f 77 6e 21)
        let header = create_test_header();
        let mut bytes = header.to_cbor();
        bytes[2..10].copy_from_slice(b"unknown!");

        let res = VaultHeader::from_cbor(&bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::UnknownHeaderField(_)
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_trailing_bytes() {
        let header = create_test_header();
        let mut bytes = header.to_cbor();
        bytes.push(0x00); // 1 extra trailing byte

        let res = VaultHeader::from_cbor(&bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::TrailingHeaderBytes(1)
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_indefinite_length() {
        let header = create_test_header();
        let mut bytes = header.to_cbor();
        bytes[0] = 0xbf; // Map with indefinite length

        let res = VaultHeader::from_cbor(&bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::CborNonDeterministic(_)
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_non_shortest_integer() {
        let header = create_test_header();
        let bytes = header.to_cbor();

        // kdf_iterations is currently encoded as 0x03 (1 byte)
        // If we replace it with 0x18, 0x03 (2-byte encoding of 3), it must be rejected
        // Find index of kdf_iterations in bytes:
        let pattern = b"kdf_iterations";
        let idx = bytes
            .windows(pattern.len())
            .position(|w| w == pattern)
            .unwrap()
            + pattern.len();

        assert_eq!(bytes[idx], 0x03);
        let mut non_shortest = bytes[..idx].to_vec();
        non_shortest.push(0x18);
        non_shortest.push(0x03);
        non_shortest.extend_from_slice(&bytes[idx + 1..]);

        let res = VaultHeader::from_cbor(&non_shortest);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::CborNonDeterministic(_)
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_invalid_argon2_parameters() {
        let mut header = create_test_header();
        header.kdf_memory_kib = 65536; // non-v1 constant (should be 131072)

        // Directly construct CBOR with out-of-policy parameter:
        let mut valid_bytes = create_test_header().to_cbor();
        // Replace 131072 (0x1a, 0x00, 0x02, 0x00, 0x00) with 65536 (0x1a, 0x00, 0x01, 0x00, 0x00)
        let pat = [0x1a, 0x00, 0x02, 0x00, 0x00];
        let idx = valid_bytes
            .windows(pat.len())
            .position(|w| w == pat)
            .unwrap();
        valid_bytes[idx + 2] = 0x01; // 65536

        let res = VaultHeader::from_cbor(&valid_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::InvalidHeaderField {
                    field: "kdf_memory_kib",
                    ..
                }
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_truncated_input() {
        let valid_bytes = create_test_header().to_cbor();

        // 1. Completely truncated (header byte only)
        assert!(matches!(
            VaultHeader::from_cbor(&valid_bytes[..1]),
            Err(crate::errors::AppError::Vault(VaultError::CborDecodeError(
                _
            )))
        ));

        // 2. Truncated in the middle of a byte string
        assert!(matches!(
            VaultHeader::from_cbor(&valid_bytes[..30]),
            Err(crate::errors::AppError::Vault(VaultError::CborDecodeError(
                _
            )))
        ));
    }

    #[test]
    fn test_cbor_rejects_wrong_data_type() {
        let mut valid_bytes = create_test_header().to_cbor();

        // created_at is expected to be uint (major 0). Change it to text string (major 3).
        let pat = b"created_at";
        let idx = valid_bytes
            .windows(pat.len())
            .position(|w| w == pat)
            .unwrap()
            + pat.len();

        // Currently valid_bytes[idx] is 0x1a (uint32). Change major type to 3 (0x7a = text string):
        valid_bytes[idx] = 0x7a;

        let res = VaultHeader::from_cbor(&valid_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::CborDecodeError(
                _
            )))
        ));
    }

    #[test]
    fn test_cbor_rejects_invalid_byte_string_length() {
        let mut valid_bytes = create_test_header().to_cbor();

        // vault_id is 16 bytes (encoded with 0x50 = major 2, length 16)
        // Change 0x50 to 0x4f (15 bytes)
        let pat = b"vault_id";
        let idx = valid_bytes
            .windows(pat.len())
            .position(|w| w == pat)
            .unwrap()
            + pat.len();

        assert_eq!(valid_bytes[idx], 0x50);
        valid_bytes[idx] = 0x4f; // 15 bytes

        let res = VaultHeader::from_cbor(&valid_bytes);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::InvalidHeaderField {
                    field: "vault_id",
                    ..
                }
            ))
        ));
    }

    #[test]
    fn test_cbor_rejects_missing_required_field() {
        // Construct a CBOR map with only 15 entries (missing payload_algorithm)
        let header = create_test_header();
        let valid_bytes = header.to_cbor();

        // Locate "payload_algorithm" and slice it out
        let pat = b"payload_algorithm";
        let idx = valid_bytes
            .windows(pat.len())
            .position(|w| w == pat)
            .unwrap()
            - 1; // include text string header byte 0x71

        let mut fifteen_entries = valid_bytes[..idx].to_vec();
        fifteen_entries[0] = 0xaf; // Map of 15 entries (0xa0 | 15 = 0xaf)

        let res = VaultHeader::from_cbor(&fifteen_entries);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(VaultError::CborDecodeError(
                _
            )))
        ));
    }

    #[test]
    fn test_cbor_rejects_oversized_header_input() {
        let huge = vec![0u8; 65537]; // Exceeds MAX_HEADER_LEN (65536)
        let res = VaultHeader::from_cbor(&huge);
        assert!(matches!(
            res,
            Err(crate::errors::AppError::Vault(
                VaultError::HeaderLengthOutOfBounds(65537)
            ))
        ));
    }
}
