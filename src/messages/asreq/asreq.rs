use crate::constants::*;
use crate::structs::structs_asn1;
use crate::error::*;
use ascii::AsciiString;

use crate::key::Key;
use super::timestampcrypter::*;

pub struct AsReq {
    realm: AsciiString,
    username: AsciiString,
    user_key: Option<Key>,
    hostname: String,
    kdc_options: u32,
    etypes: Vec<i32>,
    pac: bool,
}


impl AsReq {

    pub fn new(realm: AsciiString, username: AsciiString, hostname: String) -> Self {
        let as_req = Self {
            realm,
            username,
            user_key: None,
            hostname,
            kdc_options: FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            pac: true,
            etypes: vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC]
        };

        return as_req;
    }

    pub fn set_etypes(&mut self, etypes: Vec<i32>) {
        self.etypes = etypes;
    }

    pub fn set_kdc_options(&mut self, kdc_options: u32) {
        self.kdc_options = kdc_options;
    }

    pub fn set_user_key(&mut self, user_key: Key) {
        self.user_key = Some(user_key);
    }

    pub fn include_pac(&mut self) {
        self.pac = true;
    }

    pub fn not_include_pac(&mut self) {
        self.pac = false;
    }

    pub fn build(&self) -> KerberosResult<Vec<u8>> {
        let as_req = self.create_as_req_struct()?;
        return Ok(as_req.build());
    }

    fn create_as_req_struct(&self) -> KerberosResult<structs_asn1::AsReq> {
        let mut as_req = structs_asn1::AsReq::new(self.realm.clone(), self.username.clone(), self.hostname.clone());
        as_req.set_kdc_options(self.kdc_options);

        if self.pac {
            as_req.include_pac();
        }

        if let Some(user_key) = &self.user_key {
            let (etype, encrypted_data) = self.produce_encrypted_timestamp(user_key)?;
            as_req.set_encrypted_timestamp(etype, encrypted_data);
            as_req.push_etype(etype);
        } else {
            for etype in self.etypes.iter() {
                as_req.push_etype(*etype);
            }
        }

        return Ok(as_req);
    }

    fn produce_encrypted_timestamp(&self, user_key: &Key) -> KerberosResult<(i32, Vec<u8>)>{
        return AsReqTimestampCrypter::build_encrypted_timestamp(
            &self.realm,
            &self.username,
            &user_key,
            &self.etypes
        );
    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn as_req_with_supported_rc4_and_aes_by_default() {
        let as_req = AsReq::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("Mickey").unwrap(),
            "hostname".to_string()
        );

        let as_req_struct = as_req.create_as_req_struct().unwrap();

        assert_eq!(vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC], **as_req_struct._get_etypes());
    }

    #[test]
    fn as_req_with_only_supported_rc4_when_ntlm_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let mut as_req = AsReq::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("Mickey").unwrap(),
            "hostname".to_string()
        );

        as_req.set_user_key(Key::NTLM(key));

        let as_req_struct = as_req.create_as_req_struct().unwrap();

        assert_eq!(vec![RC4_HMAC], **as_req_struct._get_etypes());
    }


    #[test]
    fn as_req_with_only_supported_aes128_when_aes128_key_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let mut as_req = AsReq::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("Mickey").unwrap(),
            "hostname".to_string()
        );

        as_req.set_user_key(Key::AES128Key(key));

        let as_req_struct = as_req.create_as_req_struct().unwrap();

        assert_eq!(vec![AES128_CTS_HMAC_SHA1_96], **as_req_struct._get_etypes());

    }


    #[test]
    fn as_req_with_only_supported_aes256_when_aes256_key_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let mut as_req = AsReq::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("Mickey").unwrap(),
            "hostname".to_string()
        );

        as_req.set_user_key(Key::AES256Key(key));

        let as_req_struct = as_req.create_as_req_struct().unwrap();

        assert_eq!(vec![AES256_CTS_HMAC_SHA1_96], **as_req_struct._get_etypes());

    }

}