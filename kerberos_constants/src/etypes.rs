//! Encryption types used by Kerberos protocol.

pub const NO_ENCRYPTION: i32 = 0;
pub const DES_CBC_CRC: i32 = 1;
pub const DES_CBC_MD5: i32 = 3;
pub const AES256_CTS_HMAC_SHA1_96: i32 = 18;
pub const AES128_CTS_HMAC_SHA1_96: i32 = 17;
pub const RC4_HMAC: i32 = 23;
pub const RC4_HMAC_EXP: i32 = 24;
pub const RC4_HMAC_OLD_EXP: i32 = -135;
