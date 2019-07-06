use super::super::constants::*;
use super::super::structs_asn1;
use super::super::error::*;
use chrono::Utc;
use super::super::crypter::*;
use ascii::AsciiString;

pub enum AsReqCredential {
    Password(String),
    NTLM([u8; RC4_KEY_SIZE]),
    AES128Key([u8; AES128_KEY_SIZE]),
    AES256Key([u8; AES256_KEY_SIZE])
}


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
        
        return Ok(as_req.build());
    }

    fn produce_encrypted_timestamp(&self, user_key: &AsReqCredential) -> KerberosResult<(i32, Vec<u8>)> {
        let timestamp = self.produce_raw_timestamp();
        match user_key {
            AsReqCredential::Password(password) => {
                return self.encrypt_timestamp_with_best_cipher_and_password(password, &timestamp);
            }
            AsReqCredential::NTLM(ntlm) => {
                return self.encrypt_timestamp_with_cipher_and_key(RC4_HMAC, ntlm, &timestamp);
            },
            AsReqCredential::AES128Key(key_128) => {
                return self.encrypt_timestamp_with_cipher_and_key(AES128_CTS_HMAC_SHA1_96, key_128, &timestamp); 
            },
            AsReqCredential::AES256Key(key_256) => {
                return self.encrypt_timestamp_with_cipher_and_key(AES256_CTS_HMAC_SHA1_96, key_256, &timestamp);
            }
        }
    }

    

    fn encrypt_timestamp_with_best_cipher_and_password(&self, 
        password: &str, timestamp: &[u8]    
    ) -> KerberosResult<(i32, Vec<u8>)> {
        if self.etypes.contains(&AES256_CTS_HMAC_SHA1_96) {
            return self.encrypt_timestamp_with_cipher_and_password(
                AES256_CTS_HMAC_SHA1_96, 
                password,
                &self.calculate_aes_salt(), 
                timestamp
            );
        }
        else if self.etypes.contains(&AES128_CTS_HMAC_SHA1_96) {
            return self.encrypt_timestamp_with_cipher_and_password(
                AES128_CTS_HMAC_SHA1_96, 
                password,
                &self.calculate_aes_salt(),
                timestamp
            );
        }
        else if self.etypes.contains(&RC4_HMAC) {
            return self.encrypt_timestamp_with_cipher_and_password(
                RC4_HMAC, 
                password,
                "".as_bytes(),
                timestamp
            );
        }

        return Err(KerberosErrorKind::NoProvidedSupportedCipherAlgorithm)?;
    }

    fn encrypt_timestamp_with_cipher_and_key(&self, 
        etype: i32, key: &[u8], timestamp: &[u8]
    ) -> KerberosResult<(i32, Vec<u8>)> {
        let crypter = new_kerberos_crypter(etype)?;
        return Ok((etype, crypter.encrypt(key, KEY_USAGE_AS_REQ_TIMESTAMP, timestamp))); 
    }

    fn encrypt_timestamp_with_cipher_and_password(&self, 
        etype: i32, password: &str, salt: &[u8], timestamp: &[u8]
    ) -> KerberosResult<(i32, Vec<u8>)> {
        let crypter = new_kerberos_crypter(etype)?;
        return Ok((etype, crypter.generate_key_from_password_and_encrypt(
                                password,
                                salt, 
                                KEY_USAGE_AS_REQ_TIMESTAMP, 
                                timestamp)
        )); 
    }

    fn calculate_aes_salt(&self) -> Vec<u8> {
        dominio.upper() + host si el nombre de cliente acaba en $ + clientname.lower()
    }

    fn produce_raw_timestamp(&self) -> Vec<u8> {
        let timestamp = structs_asn1::PaEncTsEnc::from_datetime(Utc::now()).unwrap();
        return timestamp.build();
    }

}

hacer tests....

