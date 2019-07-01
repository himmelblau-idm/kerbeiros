use super::cryptertrait::*;

pub struct RC4Crypter {
}

impl RC4Crypter {

    pub fn new() -> Self {
        return Self {};
    }

}

impl KerberosCrypter for RC4Crypter {
    fn decrypt(&self, password: &[u8], salt: &[u8], ciphertext: &[u8]) -> KerberosResult<Vec<u8>> {
        unimplemented!();
    }

    fn encrypt(&self, password: &[u8], salt: &[u8], plaintext: &[u8]) -> KerberosResult<Vec<u8>> {
        unimplemented!();
    }
}


faltan tests....