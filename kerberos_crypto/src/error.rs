use std::result;
use thiserror::Error;

/// Result that encapsulates the Error type of this library
pub type Result<T> = result::Result<T, Error>;

/// Error raised by the routines of this library
#[derive(Error, Clone, Debug, PartialEq)]
pub enum Error {
    /// Error while decrypting the data
    #[error("DecryptionError: {}", _0)]
    DecryptionError(String),

    /// Data is encrypted with an unsupported crypto algorithm
    #[error("UnsupportedAlgorithm: {}", _0)]
    UnsupportedAlgorithm(i32),

    /// Invalid key
    #[error(
        "Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]"
    )]
    InvalidKeyCharset,

    /// Invalid key
    #[error("Invalid key: Length should be {}", _0)]
    InvalidKeyLength(usize),
}
