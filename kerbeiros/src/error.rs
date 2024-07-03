//! Errors raised by this library

use crate::messages::{AsRep, KrbError};
use ascii::FromAsciiError;
use std::result;
use std::string::FromUtf8Error;
use thiserror::Error;

/// Result to wrap kerbeiros error.
pub type Result<T> = result::Result<T, Error>;

/// Type of error in kerbeiros library.
#[derive(Clone, PartialEq, Debug, Error)]
pub enum Error {
    /// Error handlening asn1 entities.
    #[error("Asn1 error: {}", _0)]
    Asn1Error(himmelblau_kerberos_asn1::Error),

    /// Error produced in the application of cryptographic algorithms.
    #[error("Cryptography error: {}", _0)]
    CryptographyError(himmelblau_kerberos_crypto::Error),

    /// Invalid ascii string.
    #[error("Invalid ascii string")]
    InvalidAscii,

    /// Invalid utf8 string.
    #[error("Invalid utf-8 string")]
    InvalidUtf8,

    /// Invalid microseconds value. Minimum = 0, Maximum = 999999.
    #[error("Invalid microseconds value {}. Max is 999999", _0)]
    InvalidMicroseconds(u32),

    /// Error in i/o operation.
    #[error("Error in i/o operation")]
    IOError,

    /// Invalid key
    #[error(
        "Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]"
    )]
    InvalidKeyCharset,

    /// Invalid key
    #[error("Invalid key: Length should be {}", _0)]
    InvalidKeyLength(usize),

    /// Received KRB-ERROR response.
    #[error("Received {:?}", _0)]
    KrbErrorResponse(KrbError),

    /// Error resolving name.
    #[error("Error resolving name: {}", _0)]
    NameResolutionError(String),

    /// Error sending/receiving data over the network.
    #[error("Network error")]
    NetworkError,

    /// No key was provided in order to decrypt the KDC response.
    #[error("No key was provided")]
    NoKeyProvided,

    /// None cipher algorithm supported was specified.
    #[error("None cipher algorithm supported was specified")]
    NoProvidedSupportedCipherAlgorithm,

    /// Some necessary data was not available in order to build the required message.
    #[error("Not available data {}", _0)]
    NotAvailableData(String),

    /// Error parsing AS-REP message.
    #[error("Error parsing AsRep: {}", _1)]
    ParseAsRepError(AsRep, Box<Error>),

    /// The type of the principal name was not specified.
    #[error("Undefined type of principal name: {}", _0)]
    PrincipalNameTypeUndefined(String),

    /// No principal name
    #[error("No principal name found")]
    NoPrincipalName,

    /// No address found
    #[error("No address found")]
    NoAddress,

    /// Error parsing binary data
    #[error("Error parsing binary data")]
    BinaryParseError,
}

impl From<himmelblau_kerberos_crypto::Error> for Error {
    fn from(kind: himmelblau_kerberos_crypto::Error) -> Error {
        return Self::CryptographyError(kind);
    }
}

impl From<FromAsciiError<&str>> for Error {
    fn from(_error: FromAsciiError<&str>) -> Self {
        return Self::InvalidAscii;
    }
}

impl From<FromAsciiError<Vec<u8>>> for Error {
    fn from(_error: FromAsciiError<Vec<u8>>) -> Self {
        return Self::InvalidAscii;
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_error: FromUtf8Error) -> Self {
        return Self::InvalidUtf8;
    }
}

impl From<himmelblau_kerberos_asn1::Error> for Error {
    fn from(error: himmelblau_kerberos_asn1::Error) -> Self {
        return Self::Asn1Error(error);
    }
}

impl<E> From<himmelblau_kerberos_ccache::Error<E>> for Error {
    fn from(_error: himmelblau_kerberos_ccache::Error<E>) -> Self {
        return Self::BinaryParseError;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kerberos_error() {
        match produce_invalid_network_error() {
            Err(kerberos_error) => match kerberos_error {
                Error::NetworkError => {}
                _ => {
                    unreachable!();
                }
            },
            _ => {
                unreachable!()
            }
        }
    }

    fn produce_invalid_network_error() -> Result<()> {
        Err(Error::NetworkError)?;
        unreachable!();
    }
}
