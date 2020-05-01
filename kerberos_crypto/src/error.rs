use std::result;
use failure::Fail;

/// Result that encapsulates the Error type of this library
pub type Result<T> = result::Result<T, Error>;

/// Error raised by the routines of this library
#[derive(Fail, Clone, Debug, PartialEq)]
pub enum Error {
    /// Error while decrypting the data
    #[fail(display = "DecryptionError: {}", _0)]
    DecryptionError(String),

    /// Data is encrypted with an unsupported crypto algorithm
    #[fail(display = "UnsupportedAlgorithm: {}", _0)]
    UnsupportedAlgorithm(i32),
}
