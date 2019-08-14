//! Exports the types of user keys available for this implementation.

use crate::crypter;
use crate::constants::*;

/// Size of [`Key::NTLM`](./enum.Key.html#variant.NTLM).
pub const NTLM_SIZE: usize = crypter::RC4_KEY_SIZE;

/// Size of [`Key::AES128Key`](./enum.Key.html#variant.AES128Key).
pub const AES128_KEY_SIZE: usize = crypter::AES128_KEY_SIZE;

/// Size of [`Key::AES256Key`](./enum.Key.html#variant.AES256Key).
pub const AES256_KEY_SIZE: usize = crypter::AES256_KEY_SIZE;

/// Encapsules the possible keys used by this Kerberos implementation.
/// Each key can be used by a different cryptographic algorithm.
#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    /// The password of the user, it is the most versatile key, since can it can be use for obtain the rest of the keys, and therefore, being used by any cryptographic algotithm.
    Password(String),

    /// NTLM hash of the user password, used by RC4-HMAC algorithm.
    NTLM([u8; NTLM_SIZE]),

    /// AES key used by AES128-CTS-HMAC-SHA1-96 algorithm.
    AES128Key([u8; AES128_KEY_SIZE]),

    /// AES key used by AES256-CTS-HMAC-SHA1-96 algorithm.
    AES256Key([u8; AES256_KEY_SIZE])
}


impl Key {

    /// Return the etype associated with the type of key.
    /// 
    /// # Examples
    /// ```
    /// use kerbeiros::key;
    /// use kerbeiros::constants;
    /// 
    /// assert_eq!(0, key::Key::Password("".to_string()).etype());
    /// assert_eq!(constants::etypes::RC4_HMAC, key::Key::NTLM([0; key::NTLM_SIZE]).etype());
    /// assert_eq!(constants::etypes::AES128_CTS_HMAC_SHA1_96, key::Key::AES128Key([0; key::AES128_KEY_SIZE]).etype());
    /// assert_eq!(constants::etypes::AES256_CTS_HMAC_SHA1_96, key::Key::AES256Key([0; key::AES256_KEY_SIZE]).etype());
    /// ```
    pub fn etype(&self) -> i32 {
        match self {
            Key::Password(_) => 0,
            Key::NTLM(_) => RC4_HMAC,
            Key::AES128Key(_) => AES128_CTS_HMAC_SHA1_96,
            Key::AES256Key(_) => AES256_CTS_HMAC_SHA1_96
        }
    }

    /// Retrieve the key as an array of bytes.
    /// 
    /// # Examples
    /// ```
    /// use kerbeiros::key;
    /// 
    /// assert_eq!(&[0x73, 0x65, 0x63, 0x72, 0x65, 0x74], key::Key::Password("secret".to_string()).as_bytes());
    /// assert_eq!(&[0; key::NTLM_SIZE], key::Key::NTLM([0; key::NTLM_SIZE]).as_bytes());
    /// assert_eq!(&[0; key::AES128_KEY_SIZE], key::Key::AES128Key([0; key::AES128_KEY_SIZE]).as_bytes());
    /// assert_eq!(&[0; key::AES256_KEY_SIZE], key::Key::AES256Key([0; key::AES256_KEY_SIZE]).as_bytes());
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Key::Password(ref password) => password.as_bytes(),
            Key::NTLM(ref ntlm) => ntlm,
            Key::AES128Key(ref aeskey) => aeskey,
            Key::AES256Key(ref aeskey) => aeskey
        }
    }

}