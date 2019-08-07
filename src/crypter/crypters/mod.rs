mod cryptertrait;
pub use cryptertrait::*;

mod aes;
use aes::*;

mod rc4;
use rc4::*;


use crate::constants::etypes::*;

pub const RC4_KEY_SIZE: usize = 16;
pub const AES128_KEY_SIZE: usize = 16;
pub const AES256_KEY_SIZE: usize = 32;


pub fn new_kerberos_crypter(etype: i32) -> KerberosResult<Box<KerberosCrypter>> {

    match etype {
        AES256_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AESCrypter::new(AesSizes::Aes256)));
        },
        AES128_CTS_HMAC_SHA1_96 => {
            return Ok(Box::new(AESCrypter::new(AesSizes::Aes128)));
        },
        RC4_HMAC => {
            return Ok(Box::new(RC4Crypter::new()));
        }
        _ => {
            return Err(CryptographyErrorKind::UnsupportedCipherAlgorithm(etype))?;
        }
    }

} 