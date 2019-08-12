mod cryptertrait;
pub use cryptertrait::*;

mod aes;
use aes::*;

mod rc4;
use rc4::*;


use crate::constants::etypes::*;
use crate::error::*;

pub const RC4_KEY_SIZE: usize = 16;
pub const AES128_KEY_SIZE: usize = 16;
pub const AES256_KEY_SIZE: usize = 32;


pub fn new_kerberos_crypter(etype: i32) -> Result<Box<KerberosCrypter>> {

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

pub fn is_supported_etype(etype: i32) -> bool {
    match etype {
        AES256_CTS_HMAC_SHA1_96 | AES128_CTS_HMAC_SHA1_96 | RC4_HMAC => true,
        _ => false
    }
}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn supported_etypes() {
        assert_eq!(true, is_supported_etype(AES256_CTS_HMAC_SHA1_96));
        assert_eq!(true, is_supported_etype(AES128_CTS_HMAC_SHA1_96));
        assert_eq!(true, is_supported_etype(RC4_HMAC));
        assert_eq!(false, is_supported_etype(NO_ENCRYPTION));
        assert_eq!(false, is_supported_etype(RC4_HMAC_EXP));
        assert_eq!(false, is_supported_etype(DES_CBC_MD5));
        assert_eq!(false, is_supported_etype(DES_CBC_CRC));
        assert_eq!(false, is_supported_etype(RC4_HMAC_OLD_EXP));
        assert_eq!(false, is_supported_etype(AES256_CTS_HMAC_SHA1_96 | AES128_CTS_HMAC_SHA1_96));
    }

}