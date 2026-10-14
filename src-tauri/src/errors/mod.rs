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

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

pub type Result<T> = std::result::Result<T, AppError>;
