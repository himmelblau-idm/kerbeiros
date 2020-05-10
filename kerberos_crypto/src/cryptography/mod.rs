use md4::{Digest, Md4};


mod aes;
pub use aes::{decrypt_aes_ecb, encrypt_aes_cbc, pbkdf2_sha1, AesSizes};

mod hmac;
pub use hmac::{hmac_md5, hmac_sha1};

mod rc4;
pub use rc4::{rc4_decrypt, rc4_encrypt};

pub fn md4(bytes: &[u8]) -> Vec<u8> {
    return Md4::digest(&bytes).to_vec();
}

