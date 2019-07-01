pub use crate::error::*;

pub trait KerberosCrypter {
    fn decrypt(&self, password: &[u8], salt: &[u8], ciphertext: &[u8]) -> KerberosResult<Vec<u8>>;
    fn encrypt(&self, password: &[u8], salt: &[u8], plaintext: &[u8]) -> KerberosResult<Vec<u8>>;
}