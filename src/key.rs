//! Exports the types of user keys available for this implementation.

use crate::ciphers;
use crate::constants::*;

use crate::error::*;
use std::result;

/// Size of [`Key::RC4Key`](./enum.Key.html#variant.RC4Key).
pub const RC4_KEY_SIZE: usize = ciphers::RC4_KEY_SIZE;

/// Size of [`Key::AES128Key`](./enum.Key.html#variant.AES128Key).
pub const AES128_KEY_SIZE: usize = ciphers::AES128_KEY_SIZE;

/// Size of [`Key::AES256Key`](./enum.Key.html#variant.AES256Key).
pub const AES256_KEY_SIZE: usize = ciphers::AES256_KEY_SIZE;

/// Encapsules the possible keys used by this Kerberos implementation.
/// Each key can be used by a different cryptographic algorithm.
#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    /// The password of the user, it is the most versatile key, since can it can be use for obtain the rest of the keys, and therefore, being used by any cryptographic algotithm.
    Password(String),

    /// RC4 key used by RC4-HMAC algorithm. In Windows is the NTLM hash of the user password.
    RC4Key([u8; RC4_KEY_SIZE]),

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
    /// assert_eq!(constants::etypes::RC4_HMAC, key::Key::RC4Key([0; key::RC4_KEY_SIZE]).etype());
    /// assert_eq!(constants::etypes::AES128_CTS_HMAC_SHA1_96, key::Key::AES128Key([0; key::AES128_KEY_SIZE]).etype());
    /// assert_eq!(constants::etypes::AES256_CTS_HMAC_SHA1_96, key::Key::AES256Key([0; key::AES256_KEY_SIZE]).etype());
    /// ```
    pub fn etype(&self) -> i32 {
        match self {
            Key::Password(_) => 0,
            Key::RC4Key(_) => RC4_HMAC,
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
    /// assert_eq!(&[0; key::RC4_KEY_SIZE], key::Key::RC4Key([0; key::RC4_KEY_SIZE]).as_bytes());
    /// assert_eq!(&[0; key::AES128_KEY_SIZE], key::Key::AES128Key([0; key::AES128_KEY_SIZE]).as_bytes());
    /// assert_eq!(&[0; key::AES256_KEY_SIZE], key::Key::AES256Key([0; key::AES256_KEY_SIZE]).as_bytes());
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Key::Password(ref password) => password.as_bytes(),
            Key::RC4Key(ref rc4key) => rc4key,
            Key::AES128Key(ref aeskey) => aeskey,
            Key::AES256Key(ref aeskey) => aeskey
        }
    }

    /// Get a RC4 key from a hexdump.
    /// # Example
    /// 
    /// ```
    /// use kerbeiros::Key;
    /// assert_eq!(
    ///     Key::RC4Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), 
    ///     Key::from_rc4_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 32.
    /// 
    pub fn from_rc4_key_string(hex_str: &str) -> Result<Self> {
        let ntlm = Self::check_size_and_convert_in_byte_array(hex_str, RC4_KEY_SIZE)?;

        let mut key = [0; RC4_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..RC4_KEY_SIZE]);

        return Ok(Key::RC4Key(key));
    }

    /// Get a AES-128 key from a hexdump.
    /// # Example
    /// 
    /// ```
    /// use kerbeiros::Key;
    /// assert_eq!(
    ///     Key::AES128Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), 
    ///     Key::from_aes_128_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 32.
    /// 
    pub fn from_aes_128_key_string(hex_str: &str) -> Result<Self> {
        let ntlm = Self::check_size_and_convert_in_byte_array(hex_str, AES128_KEY_SIZE)?;

        let mut key = [0; AES128_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..AES128_KEY_SIZE]);

        return Ok(Key::AES128Key(key));
    }

    /// Get a AES-256 key from a hexdump.
    /// # Example
    /// 
    /// ```
    /// use kerbeiros::Key;
    /// assert_eq!(
    ///     Key::AES256Key([
    ///         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ///         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ///     ]), 
    ///     Key::from_aes_256_key_string("0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef").unwrap()
    /// );
    /// ```
    /// # Errors
    /// An error if raised if the argument string has any non hexadecimal character or size is different from 64.
    /// 
    pub fn from_aes_256_key_string(hex_str: &str) -> Result<Self> {
        let ntlm = Self::check_size_and_convert_in_byte_array(hex_str, AES256_KEY_SIZE)?;

        let mut key = [0; AES256_KEY_SIZE];
        key.copy_from_slice(&ntlm[0..AES256_KEY_SIZE]);

        return Ok(Key::AES256Key(key));
    }

    fn check_size_and_convert_in_byte_array(hex_str: &str, size: usize) -> Result<Vec<u8>> {
        if hex_str.len() != size * 2 {
            return Err(ErrorKind::InvalidKeyLength(size * 2))?;
        }

        return Ok(Self::convert_hex_string_into_byte_array(hex_str).map_err(|_|
            ErrorKind::InvalidKeyCharset
        )?);
    }

    fn convert_hex_string_into_byte_array(hex_str: &str) -> result::Result<Vec<u8>, std::num::ParseIntError> {
        let key_size = hex_str.len()/2;
        let mut bytes =  Vec::with_capacity(key_size);
        for i in 0..key_size {
            let str_index = i * 2;
            bytes.push(u8::from_str_radix(&hex_str[str_index..str_index+2], 16)?);
        }

        return Ok(bytes);
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hex_string_to_rc4_key() {
        assert_eq!(Key::RC4Key([0; RC4_KEY_SIZE]), Key::from_rc4_key_string("00000000000000000000000000000000").unwrap());
        assert_eq!(
            Key::RC4Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), 
            Key::from_rc4_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
        );
    }

    #[should_panic(expected="Invalid key: Length should be 32")]
    #[test]
    fn invalid_length_hex_string_to_rc4_key() {
        Key::from_rc4_key_string("0").unwrap();
    }

    #[should_panic(expected="Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]")]
    #[test]
    fn invalid_chars_hex_string_to_rc4_key() {
        Key::from_rc4_key_string("ERROR_0123456789ABCDEF0123456789").unwrap();
    }

    #[test]
    fn hex_string_to_aes_128_key() {
        assert_eq!(Key::AES128Key([0; AES128_KEY_SIZE]), Key::from_aes_128_key_string("00000000000000000000000000000000").unwrap());
        assert_eq!(
            Key::AES128Key([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), 
            Key::from_aes_128_key_string("0123456789ABCDEF0123456789abcdef").unwrap()
        );
    }

    #[should_panic(expected="Invalid key: Length should be 32")]
    #[test]
    fn invalid_length_hex_string_to_aes_128_key() {
        Key::from_aes_128_key_string("0").unwrap();
    }

    #[should_panic(expected="Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]")]
    #[test]
    fn invalid_chars_hex_string_to_aes_128_key() {
        Key::from_aes_128_key_string("ERROR_0123456789ABCDEF0123456789").unwrap();
    }


    #[test]
    fn hex_string_to_aes_256_key() {
        assert_eq!(
            Key::AES256Key([0; AES256_KEY_SIZE]), 
            Key::from_aes_256_key_string("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
        );
        assert_eq!(
            Key::AES256Key([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
            ]), 
            Key::from_aes_256_key_string("0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef").unwrap()
        );
    }

    #[should_panic(expected="Invalid key: Length should be 64")]
    #[test]
    fn invalid_length_hex_string_to_aes_256_key() {
        Key::from_aes_256_key_string("0").unwrap();
    }

    #[should_panic(expected="Invalid key: Only hexadecimal characters are allowed [1234567890abcdefABCDEF]")]
    #[test]
    fn invalid_chars_hex_string_to_aes_256_key() {
        Key::from_aes_256_key_string("ERROR_0123456789ABCDEF0123456789ERROR_0123456789ABCDEF0123456789").unwrap();
    }


}