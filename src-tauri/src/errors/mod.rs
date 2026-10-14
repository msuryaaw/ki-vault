use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2id key derivation failed: {0}")]
    Argon2Error(String),

    #[error("AES-256-GCM encryption failed: {0}")]
    EncryptionError(String),

    #[error("AES-256-GCM decryption failed: {0}")]
    DecryptionError(String),

    #[error("Authentication tag verification failed")]
    TagVerificationFailed,

    #[error("HKDF key derivation failed: {0}")]
    HkdfError(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("Invalid AAD length: expected {expected}, got {actual}")]
    InvalidAadLength { expected: usize, actual: usize },

    #[error("Random generation failed: {0}")]
    RngError(String),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VaultError {
    #[error("Unexpected end of input: expected at least {expected} bytes, got {actual}")]
    UnexpectedEof { expected: usize, actual: usize },

    #[error("Invalid container magic bytes: expected b\"KIVAULT\\0\", got {0:?}")]
    InvalidMagic([u8; 8]),

    #[error("Unsupported vault format version: {major}.{minor} (supported: 1.0)")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("Header length out of bounds: {0} bytes (allowed: 1..=65536)")]
    HeaderLengthOutOfBounds(u64),

    #[error("Ciphertext length out of bounds: {0} bytes (allowed: 16..=536870912)")]
    CiphertextLengthOutOfBounds(u64),

    #[error("File size calculation arithmetic overflow")]
    SizeArithmeticOverflow,

    #[error("CBOR decoding error: {0}")]
    CborDecodeError(String),

    #[error("CBOR non-deterministic encoding: {0}")]
    CborNonDeterministic(String),

    #[error("Invalid header field value for '{field}': {reason}")]
    InvalidHeaderField { field: &'static str, reason: String },

    #[error("Missing required header field: '{0}'")]
    MissingHeaderField(&'static str),

    #[error("Duplicate header field: '{0}'")]
    DuplicateHeaderField(String),

    #[error("Unknown header field: '{0}'")]
    UnknownHeaderField(String),

    #[error("Unsorted header map keys: '{current}' must appear after '{previous}' in RFC 8949 §4.2.1 order")]
    UnsortedHeaderKeys { previous: String, current: String },

    #[error("Trailing bytes after CBOR header: {0} extra bytes found")]
    TrailingHeaderBytes(usize),

    #[error(
        "Container file size mismatch: expected {expected} bytes, physical size {actual} bytes"
    )]
    FileSizeMismatch { expected: u64, actual: u64 },

    #[error("Header length mismatch: prefix specifies {prefix_len} bytes, actual encoded header is {actual_len} bytes")]
    HeaderLengthMismatch { prefix_len: u32, actual_len: usize },

    #[error("Ciphertext length mismatch: prefix specifies {prefix_len} bytes, actual ciphertext is {actual_len} bytes")]
    CiphertextLengthMismatch { prefix_len: u64, actual_len: usize },

    #[error("Trailing bytes after container payload: {0} extra bytes found")]
    TrailingContainerBytes(usize),
}

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Staging file already exists: {0}")]
    StagingFileExists(String),

    #[error("Atomic replacement failed: {0}")]
    ReplacementFailed(String),

    #[error("Durability uncertain after post-replacement synchronization failure: {0}")]
    DurabilityUncertain(String),

    #[error("Container validation failed: {0}")]
    InvalidContainer(String),

    #[error("Staging candidate exists but primary vault is missing or invalid; automatic cleanup refused: {0}")]
    StaleStagingCannotBeCleaned(String),
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Database payload size exceeds maximum allowed bound: {size} bytes (allowed: up to {max} bytes)")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Corrupt or invalid SQLite database image: {0}")]
    CorruptDatabase(String),

    #[error("Unsupported or invalid database schema version: {version} (supported: {supported})")]
    UnsupportedSchemaVersion { version: u32, supported: u32 },

    #[error("Database integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("Database connection has already been closed")]
    ConnectionClosed,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Database(DatabaseError::Sqlite(err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Storage(StorageError::Io(err))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
