//! Errors raised by this library

use std::fmt;
use std::result;
use ascii::FromAsciiError;
use failure::*;
use failure_derive::Fail;
use red_asn1;
use crate::messages::*;

/// Result to wrap kerbeiros error.
pub type Result<T> = result::Result<T, Error>;

/// Error returned by functions of the kerbeiros library.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>
}

/// Type of error in kerbeiros library.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Error handlening asn1 entities.
    #[fail (display = "Asn1 error: {}", _0)]
    Asn1Error(red_asn1::ErrorKind),

    /// Error produced in the application of cryptographic algorithms.
    #[fail (display = "Cryptography error: {}", _0)]
    CryptographyError(Box<CryptographyErrorKind>),

    /// Invalid ascii string.
    #[fail(display = "Invalid ascii string")]
    InvalidAscii,

    /// Invalid microseconds value. Minimum = 0, Maximum = 999999.
    #[fail(display = "Invalid microseconds value {}. Max is 999999", _0)]
    InvalidMicroseconds(u32),
    
    /// Error in i/o operation.
    #[fail (display = "Error in i/o operation")]
    IOError,

    /// Invalid key
    #[fail (display = "Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]")] 
    InvalidKeyCharset,

    /// Invalid key
    #[fail (display = "Invalid key: Length should be {}", _0)] 
    InvalidKeyLength(usize),

    /// Received KRB-ERROR response.
    #[fail (display = "Received {}", _0)]
    KrbErrorResponse(KrbError),

    /// Error resolving name.
    #[fail (display = "Error resolving name: {}", _0)]
    NameResolutionError(String),

    /// Error sending/receiving data over the network.
    #[fail(display = "Network error")]
    NetworkError,

    /// No key was provided in order to decrypt the KDC response.
    #[fail (display = "No key was provided")]
    NoKeyProvided,

    /// None cipher algorithm supported was specified.
    #[fail (display = "None cipher algorithm supported was specified")]
    NoProvidedSupportedCipherAlgorithm,

    /// Some necessary data was not available in order to build the required message.
    #[fail(display = "Not available data {}", _0)]
    NotAvailableData(String),

    /// Error parsing KDC-REP message.
    #[fail (display = "Error parsing KdcRep: {}", _1)]
    ParseKdcRepError(KdcRep, Box<ErrorKind>),

    /// The type of the principal name was not specified.
    #[fail(display = "Undefined type of principal name: {}", _0)]
    PrincipalNameTypeUndefined(String),
}

/// Types of errors related to data encryption/decryption
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum CryptographyErrorKind {
    /// Error while decrypting the data
    #[fail (display = "Decryption error: {}", _0)]
    DecryptionError(String),

    /// Data is encrypted with an unsupported algorithm
    #[fail (display = "Cipher algorithm with etype = {} is not supported", _0)]
    UnsupportedCipherAlgorithm(i32),
}

impl Error {

    pub fn kind(&self) -> &ErrorKind {
        return self.inner.get_context();
    }

}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        return Error {
            inner: Context::new(kind)
        };
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        return Error { inner };
    }
}

impl From<CryptographyErrorKind> for Error {
    fn from(kind: CryptographyErrorKind) -> Error {
        return Error {
            inner: Context::new(
                ErrorKind::CryptographyError(Box::new(kind))
            )
        };
    }
}


impl From<FromAsciiError<&str>> for Error {
    fn from(_error: FromAsciiError<&str>) -> Self {
        return Error {
            inner: Context::new(ErrorKind::InvalidAscii)
        };
    }
}

impl From<red_asn1::Error> for Error {
    fn from(error: red_asn1::Error) -> Self {
        return Error {
            inner: Context::new(ErrorKind::Asn1Error(error.kind().clone()))
        };
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_kerberos_error() {
        match produce_invalid_network_error() {
            Err(kerberos_error) => {
                match kerberos_error.kind() {
                    ErrorKind::NetworkError  => {
                        
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            _ => {
                unreachable!();
            }
        }
    }

    fn produce_invalid_network_error() -> Result<()> {
        Err(ErrorKind::NetworkError)?;
        unreachable!();
    }
}