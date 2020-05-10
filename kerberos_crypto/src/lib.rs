//! # Kerberos crypto
//! Library to implement the cryptographic algorithms involved in the kerberos protocol.
//!
//! The library provides different ciphers. The ciphers are classes which implements the diferent algorithms.
//! All of them implement the KerberosCipher trait.
//! ## Supported algorithms
//! - RC4-HMAC
//! - AES128-CTS-HMAC-SHA1-96
//! - AES256-CTS-HMAC-SHA1-96

mod algorithms;
pub use algorithms::aes_hmac_sha1;
pub use algorithms::rc4_hmac_md5;

mod cryptography;
pub use cryptography::{
    AesSizes, AES_128_KEY_SIZE, AES_128_SEED_SIZE, AES_256_KEY_SIZE,
    AES_256_SEED_SIZE, AES_BLOCK_SIZE, AES_MAC_SIZE, RC4_KEY_SIZE
};

mod utils;

mod error;
pub use error::{Error, Result};

mod ciphers;
pub use ciphers::{new_kerberos_cipher, AesCipher, KerberosCipher, Rc4Cipher};

mod helpers;
pub use helpers::{is_supported_etype, supported_etypes};
