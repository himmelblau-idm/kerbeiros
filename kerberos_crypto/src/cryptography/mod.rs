use crate::byteparser;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use md4::{Digest, Md4};
use rand::RngCore;

mod aes;
pub use aes::{AesSizes, pbkdf2_sha1, decrypt_aes_ecb, encrypt_aes_cbc};


mod hmac;
pub use hmac::{hmac_md5, hmac_sha1};

pub fn md4(bytes: &[u8]) -> Vec<u8> {
    return Md4::digest(&bytes).to_vec();
}

pub fn string_unicode_bytes(s: &str) -> Vec<u8> {
    let s_utf16: Vec<u16> = s.encode_utf16().collect();
    return byteparser::u16_array_to_le_bytes(&s_utf16);
}

pub fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut rc4_cipher = Rc4::new(key);
    let mut result: Vec<u8> = vec![0; data.len()];
    rc4_cipher.process(data, &mut result);
    return result;
}

pub fn rc4_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    return rc4_encrypt(key, ciphertext);
}

pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut bytes);

    return bytes;
}

pub fn xorbytes(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    let mut v_xored = Vec::with_capacity(v1.len());

    for i in 0..v1.len() {
        v_xored.push(v1[i] ^ v2[i])
    }

    return v_xored;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rc4_encrypt() {
        assert_eq!(
            Vec::<u8>::new(),
            rc4_encrypt(
                &[
                    0x2d, 0xc0, 0x9b, 0x8b, 0x35, 0xaf, 0x9c, 0x03, 0x6f, 0xc3, 0xf2, 0x9c, 0xdb,
                    0xc0, 0x5f, 0xbb
                ],
                &[]
            )
        );
        assert_eq!(
            vec![0xc2, 0x54, 0xb7, 0x4f],
            rc4_encrypt(
                &[
                    0x9a, 0x06, 0x98, 0xf1, 0xb4, 0x8b, 0xc6, 0x4c, 0x95, 0xcf, 0xf7, 0x4b, 0xf4,
                    0x69, 0x16, 0x39
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0xf9, 0xa2, 0x78, 0x82, 0x74, 0x20, 0x6f, 0x81, 0x31, 0x05],
            rc4_encrypt(
                &[
                    0x59, 0x51, 0xa7, 0xa9, 0x11, 0xb8, 0x9b, 0xfb, 0x36, 0x18, 0x43, 0xbb, 0xa9,
                    0x8f, 0xfe, 0x54
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0x38, 0xe2, 0xf5, 0x06, 0xe1, 0x98, 0xe8, 0x17],
            rc4_encrypt(
                &[
                    0xaa, 0x21, 0xa8, 0xa4, 0x23, 0xd6, 0x60, 0xa6, 0x58, 0xd6, 0x1a, 0x86, 0xc8,
                    0xa9, 0x4e, 0xeb
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0x2d, 0x62, 0x3b, 0x28, 0x74, 0x09, 0xfe, 0xcc, 0x6c],
            rc4_encrypt(
                &[
                    0x22, 0x4d, 0xcb, 0x99, 0x1b, 0x06, 0x35, 0x5b, 0x82, 0x77, 0x8d, 0x74, 0x18,
                    0xad, 0xd0, 0xcf
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
        assert_eq!(
            vec![0x20, 0xbe, 0x07, 0x98],
            rc4_encrypt(
                &[
                    0x80, 0x33, 0x46, 0x1a, 0xb9, 0x1d, 0xf1, 0x61, 0xb4, 0x06, 0x62, 0x71, 0xd0,
                    0x2d, 0x3f, 0x82
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0x1a, 0xed, 0xad, 0x97, 0xc5, 0xd2, 0x3a, 0x10, 0xde, 0xee],
            rc4_encrypt(
                &[
                    0x45, 0x25, 0xbd, 0x9d, 0xcc, 0x2a, 0xaa, 0xb4, 0x86, 0x60, 0x4c, 0x46, 0x52,
                    0xf8, 0x6e, 0xc3
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0xef, 0x5f, 0x86, 0xc6, 0x09, 0x4c, 0x0d, 0x05],
            rc4_encrypt(
                &[
                    0xb4, 0xd5, 0x9f, 0xcd, 0x1e, 0xf1, 0xf1, 0x2a, 0x1a, 0xc5, 0xa4, 0x11, 0x2d,
                    0x5e, 0x1e, 0xc1
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0x9b, 0x0b, 0x32, 0x45, 0x30, 0x14, 0x69, 0x17, 0x05],
            rc4_encrypt(
                &[
                    0xaf, 0x95, 0xcb, 0x8e, 0xf6, 0x07, 0x0d, 0x12, 0x03, 0x9c, 0x68, 0xe2, 0xbe,
                    0xb5, 0xe2, 0xf2
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
        assert_eq!(
            vec![0x95, 0xb3, 0x43, 0xd1],
            rc4_encrypt(
                &[
                    0x79, 0x8a, 0xac, 0x10, 0xf4, 0xc3, 0x91, 0x86, 0x47, 0xea, 0x92, 0x36, 0x73,
                    0x8b, 0xf3, 0x25
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0x60, 0xa2, 0x6e, 0x7b, 0xe4, 0x8f, 0xd3, 0xba, 0x9a, 0xfd],
            rc4_encrypt(
                &[
                    0xbb, 0xd0, 0x9d, 0x84, 0xeb, 0x12, 0xcc, 0x2e, 0x4a, 0xa0, 0x10, 0xea, 0x16,
                    0xa8, 0xc8, 0xa9
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0x62, 0x3e, 0x6f, 0xac, 0xf6, 0xab, 0x56, 0x55],
            rc4_encrypt(
                &[
                    0x4a, 0x60, 0x81, 0x8f, 0x1a, 0x8e, 0xfa, 0x3a, 0x15, 0xbb, 0x6c, 0x28, 0xf5,
                    0x75, 0x59, 0x43
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0xa4, 0x97, 0xfa, 0xbe, 0x67, 0x95, 0x91, 0x7d, 0x0a],
            rc4_encrypt(
                &[
                    0x87, 0xa8, 0x59, 0x7a, 0x75, 0x0b, 0xc8, 0x7f, 0x58, 0x73, 0xaa, 0xd6, 0x4a,
                    0x3c, 0xa0, 0x8f
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
        assert_eq!(
            vec![0xf4, 0x3b, 0x20, 0x39],
            rc4_encrypt(
                &[
                    0xea, 0x1c, 0x52, 0x6c, 0x3d, 0x89, 0x5e, 0xeb, 0x84, 0x98, 0x29, 0x8b, 0x13,
                    0xf1, 0x08, 0x96
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0x35, 0x14, 0xa2, 0xc2, 0x5f, 0x89, 0xda, 0x66, 0xa5, 0x61],
            rc4_encrypt(
                &[
                    0x6c, 0xb9, 0x30, 0xb9, 0x66, 0x9a, 0x83, 0x2f, 0x2a, 0xce, 0x4a, 0xeb, 0x03,
                    0xba, 0xfc, 0x42
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0xa2, 0x26, 0x2a, 0xb1, 0xbb, 0xcd, 0xac, 0x74],
            rc4_encrypt(
                &[
                    0xcd, 0x2e, 0x36, 0xdc, 0x8a, 0xdd, 0x03, 0xc6, 0x97, 0xe9, 0x31, 0x8d, 0x10,
                    0x9f, 0xb0, 0x9b
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0x7f, 0x14, 0x02, 0x95, 0xb8, 0x52, 0x9d, 0xa0, 0xd6],
            rc4_encrypt(
                &[
                    0xa9, 0x65, 0x79, 0x47, 0x7e, 0x2f, 0x69, 0x3f, 0xa4, 0x3d, 0x1b, 0xc5, 0xa0,
                    0x59, 0x32, 0x62
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
        assert_eq!(
            vec![0x86, 0x5e, 0x66, 0x2f],
            rc4_encrypt(
                &[
                    0x62, 0x6a, 0x38, 0x15, 0xb0, 0x95, 0xa6, 0x8b, 0xf5, 0x7d, 0x54, 0x39, 0xf6,
                    0x0c, 0x27, 0x6c
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0xf5, 0x0e, 0x7f, 0xdd, 0xb9, 0xab, 0x43, 0x70, 0xec, 0x58],
            rc4_encrypt(
                &[
                    0x7e, 0x54, 0xa2, 0x51, 0x3d, 0x39, 0xb4, 0x9b, 0xfd, 0xc2, 0xe8, 0x67, 0x21,
                    0xe3, 0x46, 0x48
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0x52, 0xbc, 0x09, 0x0b, 0x60, 0x8e, 0xf3, 0x8d],
            rc4_encrypt(
                &[
                    0x63, 0xb8, 0x7e, 0xa3, 0x2a, 0x07, 0xf8, 0x45, 0x66, 0xca, 0xdf, 0xcb, 0x6d,
                    0xa0, 0x33, 0x9a
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0x55, 0x90, 0xed, 0xc3, 0x83, 0xf5, 0x88, 0xf6, 0xea],
            rc4_encrypt(
                &[
                    0x05, 0x35, 0x0c, 0x93, 0xe5, 0xc3, 0xdc, 0x7f, 0xa5, 0xde, 0x58, 0x54, 0x68,
                    0xa9, 0xa3, 0x50
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
        assert_eq!(
            vec![0x02, 0xfb, 0xa1, 0x85],
            rc4_encrypt(
                &[
                    0xa2, 0x75, 0x6b, 0x80, 0xaa, 0x4e, 0x84, 0xf0, 0xce, 0xe0, 0x2e, 0xf5, 0x92,
                    0xba, 0x87, 0x27
                ],
                &[0x61, 0x62, 0x63, 0x64]
            )
        );
        assert_eq!(
            vec![0x95, 0x86, 0x99, 0xc4, 0x95, 0x97, 0x7f, 0x32, 0xc3, 0x4b],
            rc4_encrypt(
                &[
                    0xf9, 0x9c, 0xd9, 0x33, 0xf7, 0x5e, 0xd5, 0x7d, 0x0c, 0xec, 0x03, 0x1d, 0x2a,
                    0x18, 0xd7, 0xbc
                ],
                &[0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70]
            )
        );
        assert_eq!(
            vec![0xb4, 0x4e, 0xbe, 0x53, 0x87, 0xc0, 0x61, 0xa3],
            rc4_encrypt(
                &[
                    0x5b, 0xd2, 0xae, 0x8f, 0xee, 0x7c, 0xf9, 0xce, 0x22, 0x58, 0x9c, 0x3f, 0xab,
                    0xc1, 0x84, 0xcf
                ],
                &[0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b]
            )
        );
        assert_eq!(
            vec![0xbc, 0xfb, 0xcd, 0x79, 0xdc, 0xea, 0x73, 0xb3, 0x3d],
            rc4_encrypt(
                &[
                    0xef, 0x6a, 0x67, 0xfc, 0xa3, 0xca, 0x20, 0x5f, 0x3c, 0x30, 0xfc, 0x1a, 0x04,
                    0x5a, 0xe5, 0x4b
                ],
                &[0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e]
            )
        );
    }

    #[test]
    fn test_rc4_decrypt() {
        assert_eq!(
            Vec::<u8>::new(),
            rc4_decrypt(
                &[
                    0x2d, 0xc0, 0x9b, 0x8b, 0x35, 0xaf, 0x9c, 0x03, 0x6f, 0xc3, 0xf2, 0x9c, 0xdb,
                    0xc0, 0x5f, 0xbb
                ],
                &[]
            )
        );
        assert_eq!(
            vec![0x61, 0x62, 0x63, 0x64],
            rc4_decrypt(
                &[
                    0x9a, 0x06, 0x98, 0xf1, 0xb4, 0x8b, 0xc6, 0x4c, 0x95, 0xcf, 0xf7, 0x4b, 0xf4,
                    0x69, 0x16, 0x39
                ],
                &[0xc2, 0x54, 0xb7, 0x4f]
            )
        );
        assert_eq!(
            vec![0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70],
            rc4_decrypt(
                &[
                    0x59, 0x51, 0xa7, 0xa9, 0x11, 0xb8, 0x9b, 0xfb, 0x36, 0x18, 0x43, 0xbb, 0xa9,
                    0x8f, 0xfe, 0x54
                ],
                &[0xf9, 0xa2, 0x78, 0x82, 0x74, 0x20, 0x6f, 0x81, 0x31, 0x05]
            )
        );
        assert_eq!(
            vec![0x61, 0x73, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b],
            rc4_decrypt(
                &[
                    0xaa, 0x21, 0xa8, 0xa4, 0x23, 0xd6, 0x60, 0xa6, 0x58, 0xd6, 0x1a, 0x86, 0xc8,
                    0xa9, 0x4e, 0xeb
                ],
                &[0x38, 0xe2, 0xf5, 0x06, 0xe1, 0x98, 0xe8, 0x17]
            )
        );
        assert_eq!(
            vec![0x7a, 0x78, 0x63, 0x76, 0x62, 0x6e, 0x6d, 0x2c, 0x2e],
            rc4_decrypt(
                &[
                    0x22, 0x4d, 0xcb, 0x99, 0x1b, 0x06, 0x35, 0x5b, 0x82, 0x77, 0x8d, 0x74, 0x18,
                    0xad, 0xd0, 0xcf
                ],
                &[0x2d, 0x62, 0x3b, 0x28, 0x74, 0x09, 0xfe, 0xcc, 0x6c]
            )
        );
        assert_eq!(
            vec![0x61, 0x62, 0x63, 0x64],
            rc4_decrypt(
                &[
                    0x80, 0x33, 0x46, 0x1a, 0xb9, 0x1d, 0xf1, 0x61, 0xb4, 0x06, 0x62, 0x71, 0xd0,
                    0x2d, 0x3f, 0x82
                ],
                &[0x20, 0xbe, 0x07, 0x98]
            )
        );
    }
}
