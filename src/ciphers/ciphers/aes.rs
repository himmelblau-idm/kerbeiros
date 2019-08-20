use super::cipher_trait::*;
use super::super::aes_hmac_sha1::*;
pub use super::super::cryptography::*;

pub struct AESCipher {
    aes_sizes: AesSizes,

    #[cfg(test)]
    preamble: Option<Vec<u8>>
}

#[cfg(test)]
impl AESCipher {

    pub fn new(aes_sizes: AesSizes) -> Self {
        return Self{
            aes_sizes,
            preamble: None
        };
    }

    fn set_preamble(&mut self, preamble: &[u8;16]) {
        self.preamble = Some(preamble.to_vec());
    }

    fn preamble(&self) -> Vec<u8> {
        if let Some(self_preamble) = &self.preamble {
            return self_preamble.clone(); 
        }else {
            return random_bytes(self.aes_sizes.block_size());
        }
    }

}

#[cfg(not(test))]
impl AESCipher {

    pub fn new(aes_sizes: AesSizes) -> Self {
        return Self{
            aes_sizes
        };
    }

    fn preamble(&self) -> Vec<u8> {
        return random_bytes(self.aes_sizes.block_size());
    }

}

impl KerberosCipher for AESCipher {

    fn generate_key(&self, key: &[u8], salt: &[u8]) -> Vec<u8> {
        return generate_aes_key(key, salt, &self.aes_sizes);
    }

    fn generate_key_from_password(&self, password: &str, salt: &[u8]) -> Vec<u8> {
        return self.generate_key(password.as_bytes(), salt);
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        return aes_hmac_sh1_decrypt(key, key_usage, ciphertext, &self.aes_sizes);
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8> {
        let preamble = self.preamble();
        return aes_hmac_sha1_encrypt(key, key_usage, plaintext, &preamble, &self.aes_sizes);
    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_aes_256_hmac_sh1_encrypt() {
        let mut aes256_cipher = AESCipher::new(AesSizes::Aes256);
        aes256_cipher.set_preamble(&[0; 16]);

        assert_eq!(
            vec![0x29, 0x73, 0x7f, 0x3d, 0xb6, 0xbc, 0xdf, 0xe9, 0x99, 0x0f, 0xb2, 0x13, 0x6d, 0x3e, 0xfe, 0x6f, 0x21, 0x00, 0xe6, 0xc4, 0xac, 0x75, 0x82, 0x42, 0x99, 0xd8, 0xd3, 0x70, 0x2f, 0x5a, 0x2e, 0x31, 0xc7, 0xa3, 0x36, 0x74, 0x7d, 0xfd, 0x73, 0x4a, 0x1e, 0xa0, 0x16, 0x5e, 0xbb, 0x27, 0xc0, 0xd7, 0xce, 0x9b, 0x5a, 0xec, 0x7a], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "admin",
                "admin1234".as_bytes(),
                1,
                &[0x33, 0x61, 0x68, 0x77, 0x7a, 0x74, 0x39, 0x4d, 0x47, 0x39, 0x57, 0x56, 0x45, 0x75, 0x42, 0x56, 0x43, 0x35, 0x6a, 0x30, 0x6f, 0x69, 0x36, 0x73, 0x49]
            )
        );


        assert_eq!(
            vec![0x3d, 0x29, 0x1c, 0x68, 0x54, 0x89, 0xe7, 0xb7, 0x5d, 0xab, 0xdc, 0x6e, 0x01, 0x0a, 0xd0, 0x01, 0x9d, 0xb1, 0x64, 0x81, 0xb1, 0x2c, 0xb8, 0xbf, 0xa5, 0x13, 0x61, 0x92, 0x42, 0x76, 0x1f, 0x99, 0x0d, 0xe2, 0xc0, 0x27, 0x66, 0x1c, 0x98, 0x33, 0xbc, 0xce, 0xd3], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "test",
                "test1234".as_bytes(),
                2,
                &[0x6c, 0x4a, 0x33, 0x66, 0x74, 0x66, 0x77, 0x78, 0x6a, 0x73, 0x52, 0x35, 0x32, 0x32, 0x4f]
            )
        );


        assert_eq!(
            vec![0xb4, 0xc9, 0x95, 0x36, 0x2e, 0x8f, 0xb1, 0x7c, 0x5f, 0x8f, 0xcf, 0xc9, 0xe2, 0xe8, 0x26, 0xb9, 0xb2, 0x6f, 0xb4, 0x8c, 0xab, 0x44, 0x29, 0xdf, 0xfd, 0x93, 0x96, 0x59, 0x70, 0xfd, 0xb5, 0x59, 0xb3, 0xdf, 0x3f, 0xa1, 0xe4, 0x33, 0x5f, 0x82, 0xbd, 0xd3, 0x33, 0x1b, 0x60], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "1337",
                "13371234".as_bytes(),
                3,
                &[0x51, 0x42, 0x64, 0x33, 0x69, 0x71, 0x6b, 0x4b, 0x79, 0x5a, 0x72, 0x35, 0x59, 0x4a, 0x62, 0x6c, 0x4e]
            )
        );


        assert_eq!(
            vec![0xff, 0xb5, 0xa2, 0xaa, 0xe1, 0xaa, 0x26, 0x0b, 0xad, 0xcf, 0x5d, 0xcb, 0xe4, 0x3c, 0xdc, 0x30, 0x00, 0x2e, 0x3d, 0x97, 0x05, 0x22, 0xf1, 0x83, 0x95, 0x18, 0xbf, 0x62, 0x46, 0xbb, 0xec, 0x0d, 0x4c, 0x89, 0xb0, 0xc5, 0xb5, 0x81, 0xae], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "",
                "1234".as_bytes(),
                4,
                &[0x64, 0x4d, 0x61, 0x72, 0x7a, 0x4b, 0x43, 0x4f, 0x45, 0x54, 0x37]
            )
        );


        assert_eq!(
            vec![0x53, 0x2b, 0x02, 0xa2, 0xe0, 0xc9, 0x74, 0xb6, 0x79, 0x41, 0xca, 0xc1, 0x21, 0x72, 0x29, 0x50, 0x4f, 0x1f, 0xb2, 0x27, 0xf5, 0xe0, 0x40, 0xb3, 0xd2, 0x5c, 0xf5, 0xdd, 0x0b, 0x1a, 0x3f, 0x3d, 0x93, 0x26, 0x7c, 0xbd, 0x69, 0xa6, 0x24, 0x48, 0x09, 0x3d], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "12345678",
                "123456781234".as_bytes(),
                5,
                &[0x71, 0x75, 0x65, 0x4a, 0x6d, 0x72, 0x78, 0x76, 0x50, 0x47, 0x5a, 0x68, 0x6d, 0x78]
            )
        );


        assert_eq!(
            vec![0x4d, 0x48, 0x34, 0xe8, 0x61, 0x61, 0x8d, 0xa5, 0x8f, 0x27, 0x88, 0xff, 0xa7, 0xeb, 0xbb, 0x23, 0x6a, 0x74, 0x0f, 0x4c, 0xb9, 0x44, 0x79, 0xf7, 0xdc, 0xc3, 0xc3, 0xa3, 0xdc, 0xf2, 0xd6, 0x96, 0x36, 0x8c, 0xb7, 0xf3, 0xcc, 0xc5, 0x8a, 0x29, 0x6e, 0xf8, 0x5d, 0x09, 0xc9, 0xb8, 0x34, 0x0b, 0x93, 0xa0, 0xd8], 
            aes256_cipher.generate_key_from_password_and_encrypt(
                "123456789",
                "1234567891234".as_bytes(),
                6,
                &[0x6d, 0x4a, 0x79, 0x31, 0x42, 0x6d, 0x74, 0x54, 0x39, 0x33, 0x31, 0x56, 0x72, 0x50, 0x63, 0x6b, 0x38, 0x6c, 0x61, 0x4e, 0x77, 0x32, 0x56]
            )
        );
        
    }

    #[test]
    fn test_aes_256_hmac_sh1_decrypt() {
        let aes256_cipher = AESCipher::new(AesSizes::Aes256);

        assert_eq!(
            vec![0x33, 0x61, 0x68, 0x77, 0x7a, 0x74, 0x39, 0x4d, 0x47, 0x39, 0x57, 0x56, 0x45, 0x75, 0x42, 0x56, 0x43, 0x35, 0x6a, 0x30, 0x6f, 0x69, 0x36, 0x73, 0x49], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "admin",
                "admin1234".as_bytes(),
                1,
                &[0x29, 0x73, 0x7f, 0x3d, 0xb6, 0xbc, 0xdf, 0xe9, 0x99, 0x0f, 0xb2, 0x13, 0x6d, 0x3e, 0xfe, 0x6f, 0x21, 0x00, 0xe6, 0xc4, 0xac, 0x75, 0x82, 0x42, 0x99, 0xd8, 0xd3, 0x70, 0x2f, 0x5a, 0x2e, 0x31, 0xc7, 0xa3, 0x36, 0x74, 0x7d, 0xfd, 0x73, 0x4a, 0x1e, 0xa0, 0x16, 0x5e, 0xbb, 0x27, 0xc0, 0xd7, 0xce, 0x9b, 0x5a, 0xec, 0x7a]
            ).unwrap()
        );


        assert_eq!(
            vec![0x6c, 0x4a, 0x33, 0x66, 0x74, 0x66, 0x77, 0x78, 0x6a, 0x73, 0x52, 0x35, 0x32, 0x32, 0x4f], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "test",
                "test1234".as_bytes(),
                2,
                &[0x3d, 0x29, 0x1c, 0x68, 0x54, 0x89, 0xe7, 0xb7, 0x5d, 0xab, 0xdc, 0x6e, 0x01, 0x0a, 0xd0, 0x01, 0x9d, 0xb1, 0x64, 0x81, 0xb1, 0x2c, 0xb8, 0xbf, 0xa5, 0x13, 0x61, 0x92, 0x42, 0x76, 0x1f, 0x99, 0x0d, 0xe2, 0xc0, 0x27, 0x66, 0x1c, 0x98, 0x33, 0xbc, 0xce, 0xd3]
            ).unwrap()
        );

        assert_eq!(
            vec![0x51, 0x42, 0x64, 0x33, 0x69, 0x71, 0x6b, 0x4b, 0x79, 0x5a, 0x72, 0x35, 0x59, 0x4a, 0x62, 0x6c, 0x4e], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "1337",
                "13371234".as_bytes(),
                3,
                &[0xb4, 0xc9, 0x95, 0x36, 0x2e, 0x8f, 0xb1, 0x7c, 0x5f, 0x8f, 0xcf, 0xc9, 0xe2, 0xe8, 0x26, 0xb9, 0xb2, 0x6f, 0xb4, 0x8c, 0xab, 0x44, 0x29, 0xdf, 0xfd, 0x93, 0x96, 0x59, 0x70, 0xfd, 0xb5, 0x59, 0xb3, 0xdf, 0x3f, 0xa1, 0xe4, 0x33, 0x5f, 0x82, 0xbd, 0xd3, 0x33, 0x1b, 0x60]
            ).unwrap()
        );

        assert_eq!(
            vec![0x64, 0x4d, 0x61, 0x72, 0x7a, 0x4b, 0x43, 0x4f, 0x45, 0x54, 0x37], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "",
                "1234".as_bytes(),
                4,
                &[0xff, 0xb5, 0xa2, 0xaa, 0xe1, 0xaa, 0x26, 0x0b, 0xad, 0xcf, 0x5d, 0xcb, 0xe4, 0x3c, 0xdc, 0x30, 0x00, 0x2e, 0x3d, 0x97, 0x05, 0x22, 0xf1, 0x83, 0x95, 0x18, 0xbf, 0x62, 0x46, 0xbb, 0xec, 0x0d, 0x4c, 0x89, 0xb0, 0xc5, 0xb5, 0x81, 0xae]
            ).unwrap()
        );


        assert_eq!(
            vec![0x71, 0x75, 0x65, 0x4a, 0x6d, 0x72, 0x78, 0x76, 0x50, 0x47, 0x5a, 0x68, 0x6d, 0x78], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "12345678",
                "123456781234".as_bytes(),
                5,
                &[0x53, 0x2b, 0x02, 0xa2, 0xe0, 0xc9, 0x74, 0xb6, 0x79, 0x41, 0xca, 0xc1, 0x21, 0x72, 0x29, 0x50, 0x4f, 0x1f, 0xb2, 0x27, 0xf5, 0xe0, 0x40, 0xb3, 0xd2, 0x5c, 0xf5, 0xdd, 0x0b, 0x1a, 0x3f, 0x3d, 0x93, 0x26, 0x7c, 0xbd, 0x69, 0xa6, 0x24, 0x48, 0x09, 0x3d]
            ).unwrap()
        );


        assert_eq!(
            vec![0x6d, 0x4a, 0x79, 0x31, 0x42, 0x6d, 0x74, 0x54, 0x39, 0x33, 0x31, 0x56, 0x72, 0x50, 0x63, 0x6b, 0x38, 0x6c, 0x61, 0x4e, 0x77, 0x32, 0x56], 
            aes256_cipher.generate_key_from_password_and_decrypt(
                "123456789",
                "1234567891234".as_bytes(),
                6,
                &[0x4d, 0x48, 0x34, 0xe8, 0x61, 0x61, 0x8d, 0xa5, 0x8f, 0x27, 0x88, 0xff, 0xa7, 0xeb, 0xbb, 0x23, 0x6a, 0x74, 0x0f, 0x4c, 0xb9, 0x44, 0x79, 0xf7, 0xdc, 0xc3, 0xc3, 0xa3, 0xdc, 0xf2, 0xd6, 0x96, 0x36, 0x8c, 0xb7, 0xf3, 0xcc, 0xc5, 0x8a, 0x29, 0x6e, 0xf8, 0x5d, 0x09, 0xc9, 0xb8, 0x34, 0x0b, 0x93, 0xa0, 0xd8]
            ).unwrap()
        );
    }

    #[test]
    fn test_aes_128_hmac_sh1_encrypt() {
        let mut aes128_cipher = AESCipher::new(AesSizes::Aes128);
        aes128_cipher.set_preamble(&[0; 16]);

       assert_eq!(
            vec![0xde, 0xd4, 0xd3, 0xbf, 0xd7, 0x88, 0xa4, 0xb5, 0xec, 0x6b, 0x0d, 0x9c, 0x8f, 0x24, 0x00, 0xea, 0x04, 0x47, 0x94, 0xa5, 0xea, 0x27, 0xec, 0xd0, 0x3f, 0x8c, 0xf4, 0x2b, 0x58, 0x00, 0x8c, 0xcd, 0x27, 0xf4, 0x27, 0x78, 0x19, 0xa2, 0x6b, 0x27, 0xd9], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "admin",
                "admin1234".as_bytes(),
                1,
                &[0x6c, 0x38, 0x38, 0x70, 0x53, 0x78, 0x6b, 0x4d, 0x79, 0x78, 0x77, 0x68, 0x67]
            )
        );


        assert_eq!(
            vec![0xec, 0x67, 0xab, 0x44, 0xbc, 0x06, 0x00, 0x1a, 0x99, 0x34, 0x82, 0xd6, 0xc9, 0xa7, 0x1a, 0xd8, 0xb7, 0x8c, 0x9b, 0xd3, 0x23, 0xf8, 0x46, 0x97, 0x99, 0x01, 0x72, 0x41, 0xab, 0xed, 0x5e, 0x66, 0x24, 0xc5, 0xa5, 0x99, 0x84, 0x6a, 0x9f, 0xed, 0x46, 0xfe, 0xf5, 0xd5], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "test",
                "test1234".as_bytes(),
                2,
                &[0x37, 0x78, 0x58, 0x72, 0x46, 0x36, 0x49, 0x4b, 0x6b, 0x63, 0x54, 0x47, 0x75, 0x6f, 0x6f, 0x4e]
            )
        );


        assert_eq!(
            vec![0x3c, 0x8d, 0xb2, 0xe5, 0xe4, 0x7c, 0x7e, 0x5c, 0x7b, 0x74, 0x69, 0xa2, 0xdd, 0xb2, 0x5d, 0xbf, 0xc9, 0x40, 0x79, 0x88, 0x9d, 0x5b, 0x03, 0xe1, 0x8a, 0x9f, 0x29, 0xd8, 0x64, 0xb6, 0x6c, 0xf9, 0x16, 0xc3, 0x62, 0x61, 0xd4, 0xa3], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "1337",
                "13371234".as_bytes(),
                3,
                &[0x39, 0x4e, 0x72, 0x46, 0x64, 0x74, 0x74, 0x68, 0x4d, 0x38]
            )
        );


        assert_eq!(
            vec![0x6b, 0x17, 0x24, 0x0a, 0x56, 0xd6, 0xd1, 0xf5, 0x1b, 0x73, 0x76, 0xfa, 0x54, 0xd8, 0xb0, 0x43, 0x14, 0xe3, 0x1b, 0x1f, 0x05, 0xda, 0x5b, 0x74, 0xea, 0xc8, 0x4b, 0x42, 0x9c, 0x8d, 0x41, 0xfa, 0x46, 0x9e, 0x65, 0x76, 0xa1, 0x62, 0xe2, 0xde, 0xfb, 0x57, 0xb1, 0x01, 0xa1, 0x2f, 0xde, 0xc9, 0x56, 0x76, 0x7a, 0xe2, 0x3c, 0x56, 0x71, 0xd7, 0xf0, 0x91, 0x80], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "",
                "1234".as_bytes(),
                4,
                &[0x62, 0x4a, 0x71, 0x70, 0x5a, 0x49, 0x69, 0x43, 0x45, 0x44, 0x68, 0x6f, 0x78, 0x51, 0x76, 0x47, 0x58, 0x74, 0x30, 0x43, 0x6c, 0x62, 0x50, 0x30, 0x36, 0x66, 0x51, 0x4f, 0x56, 0x36, 0x6b]
            )
        );


        assert_eq!(
            vec![0x8a, 0xe4, 0x4b, 0xca, 0xba, 0x4d, 0x5f, 0x9a, 0xb4, 0xbc, 0x0f, 0x86, 0xc7, 0xa3, 0x05, 0x05, 0x28, 0x9b, 0xae, 0x9b, 0x9e, 0x66, 0xb5, 0xb9, 0x4e, 0xa4, 0xaa, 0x59, 0x6f, 0x55, 0x60, 0x41, 0x8d, 0x8a, 0x46, 0xad, 0x39, 0x40, 0x58, 0x9e, 0xca, 0x62, 0xef, 0x26, 0x24, 0x54, 0x95, 0xca, 0x0c, 0x01, 0xfd, 0x07, 0xf1], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "12345678",
                "123456781234".as_bytes(),
                5,
                &[0x42, 0x39, 0x70, 0x37, 0x77, 0x6d, 0x6f, 0x59, 0x55, 0x57, 0x5a, 0x76, 0x6a, 0x6e, 0x39, 0x44, 0x55, 0x61, 0x44, 0x4c, 0x51, 0x4c, 0x70, 0x5a, 0x78]
            )
        );


        assert_eq!(
            vec![0x05, 0x0d, 0x9c, 0x4c, 0x30, 0x3d, 0x26, 0x39, 0xb6, 0xff, 0x82, 0xe0, 0x37, 0x83, 0xee, 0x60, 0x2a, 0x10, 0x3c, 0xb6, 0x77, 0x6b, 0x66, 0x80, 0x3c, 0x7f, 0xe5, 0xe0, 0xe0, 0x65, 0x6e, 0x68, 0xec, 0x15, 0x49, 0x71, 0xf5, 0xba, 0x45, 0x99, 0xf2, 0x52, 0x34, 0x18, 0x58, 0x32, 0xff, 0x29, 0x2f, 0x0d, 0x26, 0x32, 0x6b, 0x2b, 0x01, 0xd2, 0xe3], 
            aes128_cipher.generate_key_from_password_and_encrypt(
                "123456789",
                "1234567891234".as_bytes(),
                6,
                &[0x70, 0x4d, 0x46, 0x5a, 0x56, 0x6e, 0x79, 0x36, 0x47, 0x42, 0x64, 0x35, 0x48, 0x35, 0x38, 0x73, 0x76, 0x37, 0x43, 0x37, 0x77, 0x51, 0x37, 0x42, 0x69, 0x30, 0x6a, 0x48, 0x70]
            )
        );

    }

    #[test]
    fn test_aes_128_hmac_sh1_decrypt() {
        let aes128_cipher = AESCipher::new(AesSizes::Aes128);

        assert_eq!(
            vec![0x6c, 0x38, 0x38, 0x70, 0x53, 0x78, 0x6b, 0x4d, 0x79, 0x78, 0x77, 0x68, 0x67],
            aes128_cipher.generate_key_from_password_and_decrypt(
                "admin",
                "admin1234".as_bytes(),
                1,
                &[0xde, 0xd4, 0xd3, 0xbf, 0xd7, 0x88, 0xa4, 0xb5, 0xec, 0x6b, 0x0d, 0x9c, 0x8f, 0x24, 0x00, 0xea, 0x04, 0x47, 0x94, 0xa5, 0xea, 0x27, 0xec, 0xd0, 0x3f, 0x8c, 0xf4, 0x2b, 0x58, 0x00, 0x8c, 0xcd, 0x27, 0xf4, 0x27, 0x78, 0x19, 0xa2, 0x6b, 0x27, 0xd9]
            ).unwrap()
        );


        assert_eq!(
            vec![0x37, 0x78, 0x58, 0x72, 0x46, 0x36, 0x49, 0x4b, 0x6b, 0x63, 0x54, 0x47, 0x75, 0x6f, 0x6f, 0x4e], 
            aes128_cipher.generate_key_from_password_and_decrypt(
                "test",
                "test1234".as_bytes(),
                2,
                &[0xec, 0x67, 0xab, 0x44, 0xbc, 0x06, 0x00, 0x1a, 0x99, 0x34, 0x82, 0xd6, 0xc9, 0xa7, 0x1a, 0xd8, 0xb7, 0x8c, 0x9b, 0xd3, 0x23, 0xf8, 0x46, 0x97, 0x99, 0x01, 0x72, 0x41, 0xab, 0xed, 0x5e, 0x66, 0x24, 0xc5, 0xa5, 0x99, 0x84, 0x6a, 0x9f, 0xed, 0x46, 0xfe, 0xf5, 0xd5]
            ).unwrap()
        );


        assert_eq!(
            vec![0x39, 0x4e, 0x72, 0x46, 0x64, 0x74, 0x74, 0x68, 0x4d, 0x38], 
            aes128_cipher.generate_key_from_password_and_decrypt(
                "1337",
                "13371234".as_bytes(),
                3,
                &[0x3c, 0x8d, 0xb2, 0xe5, 0xe4, 0x7c, 0x7e, 0x5c, 0x7b, 0x74, 0x69, 0xa2, 0xdd, 0xb2, 0x5d, 0xbf, 0xc9, 0x40, 0x79, 0x88, 0x9d, 0x5b, 0x03, 0xe1, 0x8a, 0x9f, 0x29, 0xd8, 0x64, 0xb6, 0x6c, 0xf9, 0x16, 0xc3, 0x62, 0x61, 0xd4, 0xa3]
            ).unwrap()
        );


        assert_eq!(
            vec![0x62, 0x4a, 0x71, 0x70, 0x5a, 0x49, 0x69, 0x43, 0x45, 0x44, 0x68, 0x6f, 0x78, 0x51, 0x76, 0x47, 0x58, 0x74, 0x30, 0x43, 0x6c, 0x62, 0x50, 0x30, 0x36, 0x66, 0x51, 0x4f, 0x56, 0x36, 0x6b], 
            aes128_cipher.generate_key_from_password_and_decrypt(
                "",
                "1234".as_bytes(),
                4,
                &[0x6b, 0x17, 0x24, 0x0a, 0x56, 0xd6, 0xd1, 0xf5, 0x1b, 0x73, 0x76, 0xfa, 0x54, 0xd8, 0xb0, 0x43, 0x14, 0xe3, 0x1b, 0x1f, 0x05, 0xda, 0x5b, 0x74, 0xea, 0xc8, 0x4b, 0x42, 0x9c, 0x8d, 0x41, 0xfa, 0x46, 0x9e, 0x65, 0x76, 0xa1, 0x62, 0xe2, 0xde, 0xfb, 0x57, 0xb1, 0x01, 0xa1, 0x2f, 0xde, 0xc9, 0x56, 0x76, 0x7a, 0xe2, 0x3c, 0x56, 0x71, 0xd7, 0xf0, 0x91, 0x80]
            ).unwrap()
        );


        assert_eq!(
            vec![0x42, 0x39, 0x70, 0x37, 0x77, 0x6d, 0x6f, 0x59, 0x55, 0x57, 0x5a, 0x76, 0x6a, 0x6e, 0x39, 0x44, 0x55, 0x61, 0x44, 0x4c, 0x51, 0x4c, 0x70, 0x5a, 0x78], 
            aes128_cipher.generate_key_from_password_and_decrypt(
                "12345678",
                "123456781234".as_bytes(),
                5,
                &[0x8a, 0xe4, 0x4b, 0xca, 0xba, 0x4d, 0x5f, 0x9a, 0xb4, 0xbc, 0x0f, 0x86, 0xc7, 0xa3, 0x05, 0x05, 0x28, 0x9b, 0xae, 0x9b, 0x9e, 0x66, 0xb5, 0xb9, 0x4e, 0xa4, 0xaa, 0x59, 0x6f, 0x55, 0x60, 0x41, 0x8d, 0x8a, 0x46, 0xad, 0x39, 0x40, 0x58, 0x9e, 0xca, 0x62, 0xef, 0x26, 0x24, 0x54, 0x95, 0xca, 0x0c, 0x01, 0xfd, 0x07, 0xf1]
            ).unwrap()
        );


        assert_eq!(
            vec![0x70, 0x4d, 0x46, 0x5a, 0x56, 0x6e, 0x79, 0x36, 0x47, 0x42, 0x64, 0x35, 0x48, 0x35, 0x38, 0x73, 0x76, 0x37, 0x43, 0x37, 0x77, 0x51, 0x37, 0x42, 0x69, 0x30, 0x6a, 0x48, 0x70], 
            aes128_cipher.generate_key_from_password_and_decrypt(
                "123456789",
                "1234567891234".as_bytes(),
                6,
                &[0x05, 0x0d, 0x9c, 0x4c, 0x30, 0x3d, 0x26, 0x39, 0xb6, 0xff, 0x82, 0xe0, 0x37, 0x83, 0xee, 0x60, 0x2a, 0x10, 0x3c, 0xb6, 0x77, 0x6b, 0x66, 0x80, 0x3c, 0x7f, 0xe5, 0xe0, 0xe0, 0x65, 0x6e, 0x68, 0xec, 0x15, 0x49, 0x71, 0xf5, 0xba, 0x45, 0x99, 0xf2, 0x52, 0x34, 0x18, 0x58, 0x32, 0xff, 0x29, 0x2f, 0x0d, 0x26, 0x32, 0x6b, 0x2b, 0x01, 0xd2, 0xe3]
            ).unwrap()
        );

    }

}