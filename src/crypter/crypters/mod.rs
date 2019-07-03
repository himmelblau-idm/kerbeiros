mod cryptertrait;
pub use cryptertrait::*;

mod aes;
pub use aes::*;

mod rc4;
pub use rc4::*;


use crate::constants::etypes::*;

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
            return Err(KerberosCryptographyErrorKind::UnsupportedCipherAlgorithm(etype))?;
        }
    }

} 