//! Exports the types of user keys available for this implementation.

use crate::crypter::*;
use crate::constants::*;

/// Encapsules the possible keys used by this Kerberos implementation.
/// Each key can be used by a different cryptographic algorithm.
#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    /// The password of the user, it is the most versatile key, since can it can be use for obtain the rest of the keys, and therefore, being used by any cryptographic algotithm.
    Password(String),

    /// NTLM hash of the user password, used by RC4-HMAC algorithm.
    NTLM([u8; RC4_KEY_SIZE]),

    /// AES key used by AES128-CTS-HMAC-SHA1-96 algorithm.
    AES128Key([u8; AES128_KEY_SIZE]),

    /// AES key used by AES256-CTS-HMAC-SHA1-96 algorithm.
    AES256Key([u8; AES256_KEY_SIZE])
}


impl Key {

    /// Return the etype associated with the type of key.
    pub fn get_etype(&self) -> i32 {
        match self {
            Key::Password(_) => 0,
            Key::NTLM(_) => RC4_HMAC,
            Key::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
            Key::AES256Key(_) => AES256_CTS_HMAC_SHA1_96
        }
    }

    /// Retrieve the key as an array of bytes.
    pub fn get_value_as_bytes(&self) -> &[u8] {
        match self {
            Key::Password(ref password) => password.as_bytes(),
            Key::NTLM(ref ntlm) => ntlm,
            Key::AES128Key(ref aeskey) => aeskey,
            Key::AES256Key(ref aeskey) => aeskey
        }
    }

}