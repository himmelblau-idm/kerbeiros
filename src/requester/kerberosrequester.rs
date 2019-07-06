
use crate::error::*;

pub const DEFAULT_KERBEROS_PORT: u16 = 88;

pub trait KerberosRequester {
    fn request_and_response(&self, raw_request: &[u8]) -> KerberosResult<Vec<u8>>;
}
