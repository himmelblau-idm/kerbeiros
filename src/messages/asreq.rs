use super::super::constants::*;

pub enum AsReqCredential {
    Password(String),
    NTLM(Vec<u8>),
}

pub enum AsReqCiphers {
    Rc4HmacMD5(),
}

impl AsReqCiphers {

    fn identifier(&self) -> i32 {
        match self {
            AsReqCiphers::Rc4HmacMD5() => { return RC4_HMAC;}
        };
    }

}
pub struct AsReq {
    domain: String,
    username: String,
    credential: Option<AsReqCredential>,
    hostname: String,
    kdc_options: u32,
    ciphers: Vec<AsReqCiphers>,
    pac: bool,
}


impl AsReq {

    pub fn new(domain: String, username: String, hostname: String) -> Self {
        let mut as_req = Self {
            domain,
            username,
            credential: None,
            hostname,
            kdc_options: 0,
            pac: true,
            ciphers: Vec::new()
        };

        as_req.add_cipher(AsReqCiphers::Rc4HmacMD5());

        as_req.set_forwardable();
        as_req.set_renewable();
        as_req.set_canonicalize();
        as_req.set_renewable_ok();

        return as_req;
    }

    pub fn add_cipher(&mut self, cipher: AsReqCiphers) {
        self.ciphers.push(cipher);
    }

    pub fn clear_ciphers(&mut self) {
        self.ciphers.clear();
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

}