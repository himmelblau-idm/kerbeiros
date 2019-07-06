use crate::crypter::*;

pub enum AsReqCredential {
    Password(String),
    NTLM([u8; RC4_KEY_SIZE]),
    AES128Key([u8; AES128_KEY_SIZE]),
    AES256Key([u8; AES256_KEY_SIZE])
}
