mod cipher_trait;
pub use cipher_trait::KerberosCipher;

mod aes;
pub use aes::AESCipher;

mod rc4;
pub use rc4::RC4Cipher;

use crate::cryptography::AesSizes;
use kerberos_constants::etypes::{
    AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMAC,
};

use crate::{Error, Result};

/// Size of RC4 key , 16 bytes
pub const RC4_KEY_SIZE: usize = 16;

/// Size of AES-128 key, 16 bytes
pub const AES128_KEY_SIZE: usize = 16;

/// Size of AES-256 key, 32 bytes
pub const AES256_KEY_SIZE: usize = 32;

/// Creates the appropiate cipher based on the encryption type specified
pub fn new_kerberos_cipher(etype: i32) -> Result<Box<dyn KerberosCipher>> {
    match etype {
        AES256_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AESCipher::new(AesSizes::Aes256)));
        }
        AES128_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AESCipher::new(AesSizes::Aes128)));
        }
        RC4_HMAC => {
            return Ok(Box::new(RC4Cipher::new()));
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm(etype))?;
        }
    }
}


