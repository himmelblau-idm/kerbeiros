pub use super::cryptography::*;
use crate::error::*;

pub fn encrypt_rc4_hmac_md5(key: &[u8], timestamp: &[u8], preamble: &[u8]) -> Vec<u8> {
    let mut plaintext : Vec<u8> = Vec::new();
    plaintext.append(&mut preamble.to_vec());
    plaintext.append(&mut timestamp.to_vec());

    let ki = hmac_md5(key, &[1, 0, 0 ,0]);
    let mut cksum = hmac_md5(&ki, &plaintext);
    let ke = hmac_md5(&ki, &cksum);
    let mut enc = rc4_encrypt(&ke, &plaintext);

    cksum.append(&mut enc);

    return cksum;
}


pub fn decrypt_rc4_hmac_md5(key: &[u8], ciphertext: &[u8]) -> KerberosResult<Vec<u8>> {
    if ciphertext.len() < 24 {
        return Err(KerberosCryptographyErrorKind::DecryptionError("Ciphertext too short".to_string()))?;
    }

    let cksum = &ciphertext[0..16];
    let basic_ciphertext = &ciphertext[16..];
    let ki = hmac_md5(key, &[1, 0, 0 ,0]);
    let ke = hmac_md5(&ki, &cksum);
    let plaintext = rc4_decrypt(&ke, &basic_ciphertext);

    let  plaintext_cksum = hmac_md5(&ki, &plaintext);

    if cksum != &plaintext_cksum[..] {
        return Err(KerberosCryptographyErrorKind::DecryptionError("Hmac integrity failure".to_string()))?;
    }

    return Ok(plaintext[8..].to_vec());
}