pub use super::cryptography::*;

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