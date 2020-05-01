use super::cipher_trait::*;
use crate::cryptography::*;
use crate::rc4_hmac_md5::*;

use crate::Result;

pub struct RC4Cipher {
    #[cfg(test)]
    preamble: Option<Vec<u8>>,
}

#[cfg(test)]
impl RC4Cipher {
    pub fn new() -> Self {
        return Self { preamble: None };
    }

    fn set_preamble(&mut self, preamble: &[u8; 8]) {
        self.preamble = Some(preamble.to_vec());
    }

    fn preamble(&self) -> Vec<u8> {
        if let Some(self_preamble) = &self.preamble {
            return self_preamble.clone();
        } else {
            return random_bytes(8);
        }
    }
}

#[cfg(not(test))]
impl RC4Cipher {
    pub fn new() -> Self {
        return Self {};
    }

    fn preamble(&self) -> Vec<u8> {
        return random_bytes(8);
    }
}

impl KerberosCipher for RC4Cipher {
    fn generate_key(&self, key: &[u8], _salt: &[u8]) -> Vec<u8> {
        return md4(key);
    }

    fn generate_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
    ) -> Vec<u8> {
        let raw_key = string_unicode_bytes(password);
        return self.generate_key(&raw_key, salt);
    }

    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let real_key_usage;
        if key_usage == 3 {
            real_key_usage = 8; // RFC 4757 rules
        } else {
            real_key_usage = key_usage;
        }
        return decrypt_rc4_hmac_md5(key, real_key_usage, ciphertext);
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8> {
        let preamble = self.preamble();
        let real_key_usage;
        if key_usage == 3 {
            real_key_usage = 8; // RFC 4757 rules
        } else {
            real_key_usage = key_usage;
        }

        return encrypt_rc4_hmac_md5(key, real_key_usage, plaintext, &preamble);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_rc4_hmac_md5() {
        let mut rc4_cipher = RC4Cipher::new();
        rc4_cipher
            .set_preamble(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        assert_eq!(
            vec![
                0x9d, 0xc2, 0x47, 0x87, 0xcb, 0x4f, 0xea, 0x59, 0x67, 0xac,
                0x2b, 0x7f, 0x2e, 0x39, 0xb6, 0x2a, 0xea, 0x6f, 0xfe, 0xf2,
                0x08, 0xcf, 0x5d, 0x6e, 0xf4, 0x2b, 0xb9, 0x29, 0x4a, 0x6c,
                0xc2, 0xea, 0xa4, 0xf9, 0x0b, 0xc9, 0x14, 0x5a, 0x18, 0x8c,
                0x85, 0xed, 0x0b, 0xfa, 0x0f, 0x00
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "admin",
                &Vec::new(),
                1,
                &[
                    0x5a, 0x67, 0x65, 0x59, 0x30, 0x5a, 0x49, 0x65, 0x41, 0x64,
                    0x56, 0x75, 0x72, 0x54, 0x4b, 0x39, 0x62, 0x73, 0x35, 0x6b,
                    0x62, 0x47
                ]
            )
        );

        assert_eq!(
            vec![
                0x29, 0x77, 0xa8, 0x1c, 0x99, 0x6c, 0x0e, 0x74, 0xb1, 0x96,
                0x0c, 0x77, 0xf8, 0xfd, 0x59, 0x71, 0xe3, 0xa5, 0xfa, 0x2d,
                0xc0, 0xd9, 0xe0, 0xca, 0x0b, 0x07, 0x6c, 0xb8, 0x57, 0x95,
                0x12, 0x40, 0x5b, 0x87, 0x31, 0xaa, 0xf2, 0x51, 0x86, 0x9e,
                0xdb, 0xbc
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "test",
                &Vec::new(),
                2,
                &[
                    0x44, 0x4c, 0x5a, 0x4c, 0x53, 0x30, 0x35, 0x47, 0x61, 0x63,
                    0x4c, 0x4e, 0x39, 0x54, 0x6f, 0x7a, 0x42, 0x47
                ]
            )
        );

        assert_eq!(
            vec![
                0xee, 0xac, 0x19, 0xf0, 0xe0, 0x3d, 0xd4, 0x1e, 0x84, 0xaa,
                0xa8, 0x33, 0x97, 0x90, 0xd4, 0x39, 0xa6, 0x69, 0x96, 0x91,
                0xdb, 0xf6, 0x9e, 0xa7, 0x57, 0x81, 0xd8, 0x09, 0x22, 0x51,
                0x54, 0x61, 0x58, 0xfc, 0xee, 0xa8, 0x93, 0xd3, 0xb8, 0x6e,
                0xc7, 0x5a, 0xf6, 0xf0, 0xdb
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "1337",
                &Vec::new(),
                3,
                &[
                    0x4c, 0x48, 0x59, 0x62, 0x31, 0x42, 0x77, 0x6a, 0x53, 0x50,
                    0x79, 0x54, 0x59, 0x6e, 0x5a, 0x43, 0x78, 0x4f, 0x65, 0x6e,
                    0x63
                ]
            )
        );

        assert_eq!(
            vec![
                0x23, 0xb6, 0x93, 0x90, 0x3f, 0x07, 0x39, 0x30, 0xcc, 0x98,
                0x62, 0xf8, 0x0f, 0xec, 0x5e, 0x38, 0x50, 0xcf, 0x2a, 0x30,
                0x1c, 0x1f, 0x07, 0x6e, 0x98, 0x45, 0x65, 0x2c, 0xbf, 0xe7,
                0x29, 0x13, 0x2f, 0xb6, 0x65, 0x9b, 0xf2, 0x89, 0x11
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "",
                &Vec::new(),
                4,
                &[
                    0x6d, 0x55, 0x77, 0x47, 0x4f, 0x49, 0x61, 0x59, 0x69, 0x79,
                    0x31, 0x52, 0x44, 0x66, 0x75
                ]
            )
        );

        assert_eq!(
            vec![
                0xa6, 0x11, 0x9f, 0xea, 0xe1, 0x8c, 0x18, 0xbb, 0x12, 0x0f,
                0x86, 0xfd, 0x6c, 0x69, 0x56, 0xcb, 0x51, 0x3d, 0xb0, 0x80,
                0x99, 0x82, 0x05, 0x6a, 0x58, 0x6b, 0x66, 0xe9, 0xde, 0xbe,
                0xe9, 0xb5, 0xbc, 0x53, 0x72, 0xdf, 0xa3, 0x9d, 0xea, 0x8d
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "12345678",
                &Vec::new(),
                5,
                &[
                    0x74, 0x57, 0x34, 0x41, 0x68, 0x36, 0x73, 0x7a, 0x6f, 0x79,
                    0x39, 0x32, 0x68, 0x68, 0x70, 0x59
                ]
            )
        );

        assert_eq!(
            vec![
                0x4f, 0xe3, 0x5f, 0x43, 0x25, 0xe8, 0x11, 0xde, 0xdc, 0x47,
                0x3e, 0xc8, 0xba, 0x68, 0x80, 0xfa, 0x33, 0x8c, 0xe1, 0x54,
                0xc1, 0x4d, 0xed, 0x33, 0x14, 0x43, 0xa5, 0xfc, 0x09, 0x40,
                0xaa, 0x43, 0x6e, 0x59, 0x43, 0xb4, 0x33, 0x0f, 0x19, 0x45,
                0xd3, 0xfe, 0x24, 0xa4, 0x04, 0x4b, 0xc2, 0x79, 0xb9, 0x33,
                0x39, 0xe7, 0x9c, 0x14
            ],
            rc4_cipher.generate_key_from_password_and_encrypt(
                "123456789",
                &Vec::new(),
                6,
                &[
                    0x69, 0x5a, 0x7a, 0x79, 0x72, 0x76, 0x74, 0x44, 0x72, 0x36,
                    0x77, 0x6f, 0x78, 0x49, 0x68, 0x41, 0x73, 0x48, 0x4b, 0x59,
                    0x53, 0x42, 0x63, 0x46, 0x6b, 0x6e, 0x59, 0x78, 0x41, 0x53
                ]
            )
        );
    }

    #[test]
    fn test_decrypt_rc4_hmac_md5() {
        let mut rc4_cipher = RC4Cipher::new();
        rc4_cipher
            .set_preamble(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        assert_eq!(
            vec![
                0x5a, 0x67, 0x65, 0x59, 0x30, 0x5a, 0x49, 0x65, 0x41, 0x64,
                0x56, 0x75, 0x72, 0x54, 0x4b, 0x39, 0x62, 0x73, 0x35, 0x6b,
                0x62, 0x47
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "admin",
                    &Vec::new(),
                    1,
                    &[
                        0x9d, 0xc2, 0x47, 0x87, 0xcb, 0x4f, 0xea, 0x59, 0x67,
                        0xac, 0x2b, 0x7f, 0x2e, 0x39, 0xb6, 0x2a, 0xea, 0x6f,
                        0xfe, 0xf2, 0x08, 0xcf, 0x5d, 0x6e, 0xf4, 0x2b, 0xb9,
                        0x29, 0x4a, 0x6c, 0xc2, 0xea, 0xa4, 0xf9, 0x0b, 0xc9,
                        0x14, 0x5a, 0x18, 0x8c, 0x85, 0xed, 0x0b, 0xfa, 0x0f,
                        0x00
                    ]
                )
                .unwrap()
        );

        assert_eq!(
            vec![
                0x44, 0x4c, 0x5a, 0x4c, 0x53, 0x30, 0x35, 0x47, 0x61, 0x63,
                0x4c, 0x4e, 0x39, 0x54, 0x6f, 0x7a, 0x42, 0x47
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "test",
                    &Vec::new(),
                    2,
                    &[
                        0x29, 0x77, 0xa8, 0x1c, 0x99, 0x6c, 0x0e, 0x74, 0xb1,
                        0x96, 0x0c, 0x77, 0xf8, 0xfd, 0x59, 0x71, 0xe3, 0xa5,
                        0xfa, 0x2d, 0xc0, 0xd9, 0xe0, 0xca, 0x0b, 0x07, 0x6c,
                        0xb8, 0x57, 0x95, 0x12, 0x40, 0x5b, 0x87, 0x31, 0xaa,
                        0xf2, 0x51, 0x86, 0x9e, 0xdb, 0xbc
                    ]
                )
                .unwrap()
        );

        assert_eq!(
            vec![
                0x4c, 0x48, 0x59, 0x62, 0x31, 0x42, 0x77, 0x6a, 0x53, 0x50,
                0x79, 0x54, 0x59, 0x6e, 0x5a, 0x43, 0x78, 0x4f, 0x65, 0x6e,
                0x63
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "1337",
                    &Vec::new(),
                    3,
                    &[
                        0xee, 0xac, 0x19, 0xf0, 0xe0, 0x3d, 0xd4, 0x1e, 0x84,
                        0xaa, 0xa8, 0x33, 0x97, 0x90, 0xd4, 0x39, 0xa6, 0x69,
                        0x96, 0x91, 0xdb, 0xf6, 0x9e, 0xa7, 0x57, 0x81, 0xd8,
                        0x09, 0x22, 0x51, 0x54, 0x61, 0x58, 0xfc, 0xee, 0xa8,
                        0x93, 0xd3, 0xb8, 0x6e, 0xc7, 0x5a, 0xf6, 0xf0, 0xdb
                    ]
                )
                .unwrap()
        );

        assert_eq!(
            vec![
                0x6d, 0x55, 0x77, 0x47, 0x4f, 0x49, 0x61, 0x59, 0x69, 0x79,
                0x31, 0x52, 0x44, 0x66, 0x75
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "",
                    &Vec::new(),
                    4,
                    &[
                        0x23, 0xb6, 0x93, 0x90, 0x3f, 0x07, 0x39, 0x30, 0xcc,
                        0x98, 0x62, 0xf8, 0x0f, 0xec, 0x5e, 0x38, 0x50, 0xcf,
                        0x2a, 0x30, 0x1c, 0x1f, 0x07, 0x6e, 0x98, 0x45, 0x65,
                        0x2c, 0xbf, 0xe7, 0x29, 0x13, 0x2f, 0xb6, 0x65, 0x9b,
                        0xf2, 0x89, 0x11
                    ]
                )
                .unwrap()
        );

        assert_eq!(
            vec![
                0x74, 0x57, 0x34, 0x41, 0x68, 0x36, 0x73, 0x7a, 0x6f, 0x79,
                0x39, 0x32, 0x68, 0x68, 0x70, 0x59
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "12345678",
                    &Vec::new(),
                    5,
                    &[
                        0xa6, 0x11, 0x9f, 0xea, 0xe1, 0x8c, 0x18, 0xbb, 0x12,
                        0x0f, 0x86, 0xfd, 0x6c, 0x69, 0x56, 0xcb, 0x51, 0x3d,
                        0xb0, 0x80, 0x99, 0x82, 0x05, 0x6a, 0x58, 0x6b, 0x66,
                        0xe9, 0xde, 0xbe, 0xe9, 0xb5, 0xbc, 0x53, 0x72, 0xdf,
                        0xa3, 0x9d, 0xea, 0x8d
                    ]
                )
                .unwrap()
        );

        assert_eq!(
            vec![
                0x69, 0x5a, 0x7a, 0x79, 0x72, 0x76, 0x74, 0x44, 0x72, 0x36,
                0x77, 0x6f, 0x78, 0x49, 0x68, 0x41, 0x73, 0x48, 0x4b, 0x59,
                0x53, 0x42, 0x63, 0x46, 0x6b, 0x6e, 0x59, 0x78, 0x41, 0x53
            ],
            rc4_cipher
                .generate_key_from_password_and_decrypt(
                    "123456789",
                    &Vec::new(),
                    6,
                    &[
                        0x4f, 0xe3, 0x5f, 0x43, 0x25, 0xe8, 0x11, 0xde, 0xdc,
                        0x47, 0x3e, 0xc8, 0xba, 0x68, 0x80, 0xfa, 0x33, 0x8c,
                        0xe1, 0x54, 0xc1, 0x4d, 0xed, 0x33, 0x14, 0x43, 0xa5,
                        0xfc, 0x09, 0x40, 0xaa, 0x43, 0x6e, 0x59, 0x43, 0xb4,
                        0x33, 0x0f, 0x19, 0x45, 0xd3, 0xfe, 0x24, 0xa4, 0x04,
                        0x4b, 0xc2, 0x79, 0xb9, 0x33, 0x39, 0xe7, 0x9c, 0x14
                    ]
                )
                .unwrap()
        );
    }

    fn rc4_key_gen(password: &str) -> Vec<u8> {
        return RC4Cipher::new()
            .generate_key_from_password(password, &Vec::new());
    }

    #[test]
    fn generate_rc4_key() {
        assert_eq!(
            vec![
                0x20, 0x9c, 0x61, 0x74, 0xda, 0x49, 0x0c, 0xae, 0xb4, 0x22,
                0xf3, 0xfa, 0x5a, 0x7a, 0xe6, 0x34
            ],
            rc4_key_gen("admin")
        );
        assert_eq!(
            vec![
                0x0c, 0xb6, 0x94, 0x88, 0x05, 0xf7, 0x97, 0xbf, 0x2a, 0x82,
                0x80, 0x79, 0x73, 0xb8, 0x95, 0x37
            ],
            rc4_key_gen("test")
        );
        assert_eq!(
            vec![
                0x2f, 0xd6, 0xbd, 0xe7, 0xdb, 0x06, 0x81, 0x88, 0x74, 0x98,
                0x91, 0x4c, 0xb2, 0xd2, 0x01, 0xef
            ],
            rc4_key_gen("1337")
        );
        assert_eq!(
            vec![
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c,
                0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
            ],
            rc4_key_gen("")
        );
        assert_eq!(
            vec![
                0x25, 0x97, 0x45, 0xcb, 0x12, 0x3a, 0x52, 0xaa, 0x2e, 0x69,
                0x3a, 0xaa, 0xcc, 0xa2, 0xdb, 0x52
            ],
            rc4_key_gen("12345678")
        );
        assert_eq!(
            vec![
                0xc2, 0x2b, 0x31, 0x5c, 0x04, 0x0a, 0xe6, 0xe0, 0xef, 0xee,
                0x35, 0x18, 0xd8, 0x30, 0x36, 0x2b
            ],
            rc4_key_gen("123456789")
        );
    }
}
