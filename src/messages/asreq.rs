use super::super::constants::*;
use super::super::structs_asn1;
use super::super::error::*;
use chrono::Utc;
use super::super::crypter::*;
use ascii::AsciiString;

pub enum AsReqCredential {
    Password(String),
    NTLM(Vec<u8>),
}

pub enum AsReqCipher {
    Rc4HmacMD5(),
}

impl AsReqCipher {

    fn identifier(&self) -> i32 {
        match self {
            AsReqCipher::Rc4HmacMD5() => { return RC4_HMAC;}
        };
    }

}
pub struct AsReq {
    realm: AsciiString,
    username: AsciiString,
    credential: Option<AsReqCredential>,
    hostname: String,
    kdc_options: u32,
    ciphers: Vec<AsReqCipher>,
    pac: bool,
}


impl AsReq {

    pub fn new(realm: AsciiString, username: AsciiString, hostname: String) -> Self {
        let mut as_req = Self {
            realm,
            username,
            credential: None,
            hostname,
            kdc_options: 0,
            pac: true,
            ciphers: Vec::new()
        };

        as_req.add_cipher(AsReqCipher::Rc4HmacMD5());

        as_req.set_forwardable();
        as_req.set_renewable();
        as_req.set_canonicalize();
        as_req.set_renewable_ok();

        return as_req;
    }

    pub fn add_cipher(&mut self, cipher: AsReqCipher) {
        self.ciphers.push(cipher);
    }

    pub fn clear_ciphers(&mut self) {
        self.ciphers.clear();
    }

    pub fn set_credential(&mut self, credential: AsReqCredential) {
        self.credential = Some(credential);
    }

    pub fn set_password(&mut self, password: String) {
        self.set_credential(AsReqCredential::Password(password));
    }

    pub fn set_forwardable(&mut self) {
        self.kdc_options &= FORWARDABLE;
    }

    pub fn set_renewable(&mut self) {
        self.kdc_options &= RENEWABLE;
    }

    pub fn set_canonicalize(&mut self) {
        self.kdc_options &= CANONICALIZE;
    }

    pub fn set_renewable_ok(&mut self) {
        self.kdc_options &= RENEWABLE_OK;
    }

    pub fn clear_options(&mut self) {
        self.kdc_options = 0;
    }

    pub fn include_pac(&mut self) {
        self.pac = true;
    }

    pub fn not_include_pac(&mut self) {
        self.pac = false;
    }

    pub fn build(&self) -> KerberosResult<Vec<u8>> {
        let mut as_req = structs_asn1::AsReq::new(self.realm.clone(), self.username.clone(), self.hostname.clone());
        as_req.set_kdc_options(self.kdc_options);

        if self.pac {
            as_req.include_pac();
        }

        for cipher in self.ciphers.iter() {
            as_req.push_etype(cipher.identifier());
        }

        if let Some(credential) = &self.credential {
            let (etype, encrypted_data) = self.produce_encrypted_timestamp(credential);
            as_req.set_encrypted_timestamp(etype, encrypted_data);
        }
        
        return Ok(as_req.build());
    }

    fn produce_encrypted_timestamp(&self, credential: &AsReqCredential) -> (i32, Vec<u8>) {
        match credential {
            AsReqCredential::Password(password) => {
                let ntlm = ntlm_hash(password);
                return (RC4_HMAC, self.encrypt_timestamp_with_rc4(&ntlm))
            }
            AsReqCredential::NTLM(ntlm) => {
                return (RC4_HMAC, self.encrypt_timestamp_with_rc4(&ntlm));
            }
        }
    }

    fn encrypt_timestamp_with_rc4(&self, ntlm: &Vec<u8>) -> Vec<u8> {
        let timestamp = self.produce_raw_timestamp();
        return RC4Crypter::new().encrypt(ntlm, &timestamp).unwrap();
    }

    fn produce_raw_timestamp(&self) -> Vec<u8> {
        let timestamp = structs_asn1::PaEncTsEnc::from_datetime(Utc::now()).unwrap();
        return timestamp.build();
    }

}