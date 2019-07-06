use crate::constants::*;
use crate::structs_asn1;
use crate::error::*;
use ascii::AsciiString;

use super::asreqcredential::*;
use super::timestampcrypter::*;

pub struct AsReq {
    realm: AsciiString,
    username: AsciiString,
    user_key: Option<AsReqCredential>,
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
            etypes: vec![RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96]
        };

        return as_req;
    }

    pub fn set_etypes(&mut self, etypes: Vec<i32>) {
        self.etypes = etypes;
    }

    pub fn set_kdc_options(&mut self, kdc_options: u32) {
        self.kdc_options = kdc_options;
    }

    pub fn set_user_key(&mut self, user_key: AsReqCredential) {
        self.user_key = Some(user_key);
    }

    pub fn set_password(&mut self, password: String) {
        self.set_user_key(AsReqCredential::Password(password));
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

        for etype in self.etypes.iter() {
            as_req.push_etype(*etype);
        }

        if let Some(user_key) = &self.user_key {
            let (etype, encrypted_data) = self.produce_encrypted_timestamp(user_key)?;
            as_req.set_encrypted_timestamp(etype, encrypted_data);
        }

        return Ok(as_req);
    }

    fn produce_encrypted_timestamp(&self, user_key: &AsReqCredential) -> KerberosResult<(i32, Vec<u8>)>{
        return AsReqTimestampCrypter::build_encrypted_timestamp(
            &self.realm,
            &self.username,
            &user_key,
            &self.etypes
        );
    }

}


