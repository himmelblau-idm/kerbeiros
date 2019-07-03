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

}

impl KerberosCrypter for RC4Crypter {

    fn generate_key(&self, key: &[u8], salt: &[u8]) -> Vec<u8> {
        return md4(key);
    }

    fn generate_key_from_password(&self, password: &str, salt: &[u8]) -> Vec<u8> {
        let raw_key = string_unicode_bytes(password);
        return self.generate_key(&raw_key, salt);
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> KerberosResult<Vec<u8>> {
        unimplemented!();
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> KerberosResult<Vec<u8>> {
        let preamble: Vec<u8>;
        if let Some(self_preamble) = &self.preamble {
            preamble = self_preamble.clone(); 
        }else {
            preamble = random_bytes(8);
        }

        return Ok(encrypt_rc4_hmac_md5(key, plaintext, &preamble));
    }
    
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::structs_asn1::PaEncTsEnc;
    use asn1::*;
    use chrono::prelude::*;

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
                &timestamp_raw
            ).unwrap()
        );
    }


}