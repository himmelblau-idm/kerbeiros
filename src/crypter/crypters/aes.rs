use super::cryptertrait::*;
use super::super::aeshmacsha1::*;
pub use super::super::cryptography::AesSizes;

pub struct AESCrypter {
    aes_sizes: AesSizes
}

impl AESCrypter {

    pub fn new(aes_sizes: AesSizes) -> Self {
        return Self{
            aes_sizes
        };
    }

}

impl KerberosCrypter for AESCrypter {
    fn decrypt(&self, password: &[u8], salt: &[u8], ciphertext: &[u8]) -> KerberosResult<Vec<u8>> {
        let key = generate_aes_key(password, salt, &self.aes_sizes);
        return aes_hmac_sh1_decrypt(&key, ciphertext, &self.aes_sizes);
    }

    fn encrypt(&self, password: &[u8], salt: &[u8], plaintext: &[u8]) -> KerberosResult<Vec<u8>> {
        unimplemented!();
    }
}


faltan tests....