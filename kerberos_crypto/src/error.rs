use std::result;
use std::fmt;

/// Result that encapsulates the Error type of this library
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// Error while decrypting the data
    DecryptionError(String),

    /// Data is encrypted with an unsupported crypto algorithm
    UnsupportedAlgorithm(i32),
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}
