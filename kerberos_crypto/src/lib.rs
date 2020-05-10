//! # Kerberos crypto
//! Library to implement the cryptographic algorithms involved in the kerberos protocol.
//!
//! The library provides different ciphers. The ciphers are classes which implements the diferent algorithms.
//! All of them implement the KerberosCipher trait.
//! ## Supported algorithms
//! - RC4-HMAC
//! - AES128-CTS-HMAC-SHA1-96
//! - AES256-CTS-HMAC-SHA1-96

pub mod aes_hmac_sha1;
mod cryptography;
pub use cryptography::AesSizes;

pub mod rc4_hmac_md5;

mod byteparser;

mod error;
pub use error::{Error, Result};

mod ciphers;
pub use ciphers::{
    is_supported_etype, new_kerberos_cipher, AESCipher, KerberosCipher,
    RC4Cipher, AES128_KEY_SIZE, AES256_KEY_SIZE, RC4_KEY_SIZE,
};
