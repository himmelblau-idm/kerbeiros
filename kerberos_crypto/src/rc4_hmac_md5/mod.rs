//! This module provides routines to encrypt/decrypt by using the RC4
//! algorithm with HMAC-MD5 required by RC4_HMAC
//!

mod encrypt;
pub use encrypt::{decrypt, encrypt};
