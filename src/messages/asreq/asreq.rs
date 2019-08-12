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
    kdc_options: u32,
    etypes: Vec<i32>,
    pac: bool,
}


impl AsReq {

    pub fn new(realm: AsciiString, username: AsciiString) -> Self {
        let as_req = Self {
            realm,
            username,
            user_key: None,
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

    pub fn build(&self) -> Result<Vec<u8>> {
        let as_req = self.create_as_req_struct()?;
        return Ok(as_req.build());
    }

    fn create_as_req_struct(&self) -> Result<structs_asn1::AsReq> {
        let mut as_req = structs_asn1::AsReq::new(self.realm.clone(), self.username.clone());
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

    fn produce_encrypted_timestamp(&self, user_key: &Key) -> Result<(i32, Vec<u8>)>{
        return AsReqTimestampCrypter::build_encrypted_timestamp(
            &self.realm,
            &self.username,
            &user_key,
            &self.etypes
        );
    }

}


