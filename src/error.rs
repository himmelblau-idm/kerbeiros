use std::fmt;
use std::convert;
use std::result::Result;
use ascii::FromAsciiError;
use failure::*;
use failure_derive::Fail;

pub type KerberosResult<T> = Result<T, KerberosError>;

#[derive(Debug)]
pub struct KerberosError {
    inner: Context<KerberosErrorKind>
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum KerberosErrorKind {
    #[fail(display = "Invalid KDC hostname")]
    InvalidKDC,
    #[fail(display = "Network error")]
    NetworkError,
    #[fail(display = "Invalid ascii string")]
    InvalidAscii,
    #[fail(display = "Undefined type of principal name: {}", _0)]
    PrincipalNameTypeUndefined(String),
    #[fail(display = "Invalid microseconds value {}. Max is 999999", _0)]
    InvalidMicroseconds(u32)
}

impl KerberosError {

    pub fn kind(&self) -> &KerberosErrorKind {
        return self.inner.get_context();
    }

}

impl Fail for KerberosError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for KerberosError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl convert::From<KerberosErrorKind> for KerberosError {
    fn from(kind: KerberosErrorKind) -> KerberosError {
        return KerberosError {
            inner: Context::new(kind)
        };
    }
}

impl convert::From<Context<KerberosErrorKind>> for KerberosError {
    fn from(inner: Context<KerberosErrorKind>) -> KerberosError {
        return KerberosError { inner };
    }
}



impl convert::From<FromAsciiError<&str>> for KerberosError {
    fn from(_error: FromAsciiError<&str>) -> Self {
        return KerberosError {
            inner: Context::new(KerberosErrorKind::InvalidAscii)
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
                    KerberosErrorKind::NetworkError  => {
                        
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

    fn produce_invalid_network_error() -> KerberosResult<()> {
        Err(KerberosErrorKind::NetworkError)?;
        unreachable!();
    }
}