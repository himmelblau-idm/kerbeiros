use std::fmt;
use std::result;
use ascii::FromAsciiError;
use failure::*;
use failure_derive::Fail;
use red_asn1;
use crate::messages::*;

/// Result to wrap library error
pub type Result<T> = result::Result<T, Error>;

/// Error returned by the library
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>
}

#[derive(Clone, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Network error")]
    NetworkError,
    #[fail(display = "Invalid ascii string")]
    InvalidAscii,
    #[fail(display = "Undefined type of principal name: {}", _0)]
    PrincipalNameTypeUndefined(String),
    #[fail(display = "Invalid microseconds value {}. Max is 999999", _0)]
    InvalidMicroseconds(u32),
    #[fail(display = "Not available data {}", _0)]
    NotAvailableData(String),
    #[fail (display = "Asn1 error: {}", _0)]
    Asn1Error(red_asn1::ErrorKind),
    #[fail (display = "Cryptography error: {}", _0)]
    CryptographyError(Box<CryptographyErrorKind>),
    #[fail (display = "Error resolving name: {}", _0)]
    NameResolutionError(String),
    #[fail (display = "Received KRB-ERROR response")]
    KrbErrorResponse(KrbError),
    #[fail (display = "Error parsing KdcRep: {}", _1)]
    ParseKdcRepError(KdcRep, Box<ErrorKind>),
    #[fail (display = "None cipher algorithm supported was specified")]
    NoProvidedSupportedCipherAlgorithm,
    #[fail (display = "Error in i/o operation")]
    IOError,
    #[fail (display = "No key was provided")]
    NoKeyProvided,
}

/// Types of errors related to data encryption/decryption
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum CryptographyErrorKind {

    /// Data is encrypted with an unsupported algorithm
    #[fail (display = "Cipher algorithm with etype = {} is not supported", _0)]
    UnsupportedCipherAlgorithm(i32),

    /// Error while decrypting the data
    #[fail (display = "Decryption error: {}", _0)]
    DecryptionError(String),
}

impl Error {

    pub fn kind(&self) -> &ErrorKind {
        return self.inner.get_context();
    }

}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
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