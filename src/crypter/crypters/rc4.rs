use super::cryptertrait::*;
use super::super::cryptography::*;
use super::super::rc4hmacmd5::*;

pub struct RC4Crypter {
    preamble: Option<Vec<u8>>
}

impl RC4Crypter {

    pub fn new() -> Self {
        return Self {
            preamble: None
        };
    }

    fn _set_preamble(&mut self, preamble: &[u8;8]) {
        self.preamble = Some(preamble.to_vec());
    }

    fn _get_preamble(&self) -> Vec<u8> {
        if let Some(self_preamble) = &self.preamble {
            return self_preamble.clone(); 
        }else {
            return random_bytes(8);
        }
    }

}

impl KerberosCrypter for RC4Crypter {

    fn generate_key(&self, key: &[u8], _salt: &[u8]) -> Vec<u8> {
        return md4(key);
    }

    fn generate_key_from_password(&self, password: &str, salt: &[u8]) -> Vec<u8> {
        let raw_key = string_unicode_bytes(password);
        return self.generate_key(&raw_key, salt);
    }

    fn decrypt(&self, key: &[u8], key_usage: i32, ciphertext: &[u8]) -> KerberosResult<Vec<u8>> {
        return decrypt_rc4_hmac_md5(key, ciphertext);
    }

    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8]) -> KerberosResult<Vec<u8>> {
        let preamble = self._get_preamble();
        return Ok(encrypt_rc4_hmac_md5(key, plaintext, &preamble));
    }
    
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::structs_asn1::PaEncTsEnc;
    use asn1::*;
    use chrono::prelude::*;
    use crate::constants::*;

    #[test]
    fn test_encrypt_timestamp_rc4_hmac_md5() {
        let timestamp = PaEncTsEnc::from_datetime(Utc.ymd(2019, 6, 4).and_hms_micro(06, 13, 52, 016747)).unwrap();
        let timestamp_raw = timestamp.asn1_type().encode().unwrap();

        let mut rc4_crypter = RC4Crypter::new();
        rc4_crypter._set_preamble(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let ciphertext = vec![
            0x8f, 0x24, 0x62, 0xd7, 0x70, 0xa7, 0xce, 0x9e, 
            0x5b, 0x5e, 0xe6, 0x35, 0xd8, 0xbc, 0x54, 0x9a,
            0x83, 0xb0, 0x93, 0xcf, 0xe2, 0x6b, 0x55, 0x25,
            0xb7, 0x83, 0x33, 0x89, 0x35, 0xd1, 0xa9, 0xf2, 
            0x8d, 0x48, 0xde, 0x78, 0xfe, 0x40, 0xf1, 0x22, 
            0xb2, 0xec, 0xe5, 0x9a, 0x6f, 0x43, 0xfb, 0x14, 
            0xaa, 0x03, 0x22
        ];

        assert_eq!(ciphertext, 
            rc4_crypter.generate_key_from_password_and_encrypt(
                "test",
                &Vec::new(),
                KEY_USAGE_PA_ENC_TIMESTAMP,
                &timestamp_raw
            ).unwrap()
        );
    }

    #[test]
    fn test_decrypt_timestamp_rc4_hmac_md5() {
        let timestamp = PaEncTsEnc::from_datetime(Utc.ymd(2019, 6, 4).and_hms_micro(06, 13, 52, 016747)).unwrap();
        let timestamp_raw = timestamp.asn1_type().encode().unwrap();

        let mut rc4_crypter = RC4Crypter::new();
        rc4_crypter._set_preamble(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let ciphertext = vec![
            0x8f, 0x24, 0x62, 0xd7, 0x70, 0xa7, 0xce, 0x9e, 
            0x5b, 0x5e, 0xe6, 0x35, 0xd8, 0xbc, 0x54, 0x9a,
            0x83, 0xb0, 0x93, 0xcf, 0xe2, 0x6b, 0x55, 0x25,
            0xb7, 0x83, 0x33, 0x89, 0x35, 0xd1, 0xa9, 0xf2, 
            0x8d, 0x48, 0xde, 0x78, 0xfe, 0x40, 0xf1, 0x22, 
            0xb2, 0xec, 0xe5, 0x9a, 0x6f, 0x43, 0xfb, 0x14, 
            0xaa, 0x03, 0x22
        ];

        assert_eq!(timestamp_raw, 
            rc4_crypter.generate_key_from_password_and_decrypt(
                "test",
                &Vec::new(),
                KEY_USAGE_PA_ENC_TIMESTAMP,
                &ciphertext
            ).unwrap()
        );
    }


    fn ntlm_hash(password: &str) -> Vec<u8> {
        return RC4Crypter::new().generate_key_from_password(password, &Vec::new());
    }

    #[test]
    fn test_ntlm_hash(){
        assert_eq!(vec![0x20, 0x9c, 0x61, 0x74, 0xda, 0x49, 0x0c, 0xae, 0xb4, 0x22, 0xf3, 0xfa, 0x5a, 0x7a, 0xe6, 0x34], 
                   ntlm_hash("admin"));
        assert_eq!(vec![0x0c, 0xb6, 0x94, 0x88, 0x05, 0xf7, 0x97, 0xbf, 0x2a, 0x82, 0x80, 0x79, 0x73, 0xb8, 0x95, 0x37], 
                   ntlm_hash("test"));
        assert_eq!(vec![0x2f, 0xd6, 0xbd, 0xe7, 0xdb, 0x06, 0x81, 0x88, 0x74, 0x98, 0x91, 0x4c, 0xb2, 0xd2, 0x01, 0xef], 
                   ntlm_hash("1337"));
        assert_eq!(vec![0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0], 
                   ntlm_hash(""));
        assert_eq!(vec![0x25, 0x97, 0x45, 0xcb, 0x12, 0x3a, 0x52, 0xaa, 0x2e, 0x69, 0x3a, 0xaa, 0xcc, 0xa2, 0xdb, 0x52], 
                   ntlm_hash("12345678"));
        assert_eq!(vec![0xc2, 0x2b, 0x31, 0x5c, 0x04, 0x0a, 0xe6, 0xe0, 0xef, 0xee, 0x35, 0x18, 0xd8, 0x30, 0x36, 0x2b], 
                   ntlm_hash("123456789"));
    
    }

}