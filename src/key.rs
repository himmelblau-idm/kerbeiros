use crate::crypter::*;
use crate::constants::*;

#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    Password(String),
    NTLM([u8; RC4_KEY_SIZE]),
    AES128Key([u8; AES128_KEY_SIZE]),
    AES256Key([u8; AES256_KEY_SIZE])
}


impl Key {

    pub fn get_etype(&self) -> i32 {
        match self {
            Key::Password(_) => 0,
            Key::NTLM(_) => RC4_HMAC,
            Key::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
            Key::AES256Key(_) => AES256_CTS_HMAC_SHA1_96
        }
    }

    pub fn get_value_as_bytes(&self) -> &[u8] {
        match self {
            Key::Password(ref password) => password.as_bytes(),
            Key::NTLM(ref ntlm) => ntlm,
            Key::AES128Key(ref aeskey) => aeskey,
            Key::AES256Key(ref aeskey) => aeskey
        }
    }

}