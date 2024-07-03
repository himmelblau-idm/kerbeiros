//! Errors raised by this library

use std::result;
use std::string::FromUtf8Error;
use thiserror::Error;

/// Result to wrap kerbeiros error.
pub type ConvertResult<T> = result::Result<T, ConvertError>;

/// Type of error in kerbeiros library.
#[derive(Clone, PartialEq, Debug, Error)]
pub enum ConvertError {
    /// Error handlening asn1 entities.
    #[error("Asn1 error: {}", _0)]
    Asn1Error(himmelblau_kerberos_asn1::Error),

    /// Invalid ascii string.
    #[error("Invalid ascii string")]
    InvalidAscii,

    /// Invalid utf8 string.
    #[error("Invalid utf8 string")]
    FromUtf8Error,

    /// No principal name
    #[error("No principal name found")]
    NoPrincipalName,

    /// No address found
    #[error("No address found")]
    NoAddress,

    /// Error parsing binary data
    #[error("Error parsing binary data")]
    BinaryParseError,

    /// The parsed struct doesn't have a required field.
    /// This could be due a Option field which is None.
    #[error("A required field is missing: {}", _0)]
    MissingField(String),

    #[error("KrbCredError: {}", _0)]
    KrbCredError(String),
}

impl From<FromUtf8Error> for ConvertError {
    fn from(_error: FromUtf8Error) -> Self {
        return Self::FromUtf8Error;
    }
}

impl From<himmelblau_kerberos_asn1::Error> for ConvertError {
    fn from(error: himmelblau_kerberos_asn1::Error) -> Self {
        return Self::Asn1Error(error);
    }
}
