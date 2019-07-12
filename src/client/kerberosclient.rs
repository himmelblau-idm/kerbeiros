use std::net::IpAddr;
use dns_lookup;
pub use ascii::AsciiString;
use crate::error::*;
use crate::sysutils;
use crate::credential::*;
use super::tgtrequest::*;
use crate::key::Key;


#[derive(Debug)]
pub struct KerberosClient {
    realm: AsciiString,
    kdc_address: IpAddr,
    hostname: String
}

impl KerberosClient {
    pub fn new(realm: AsciiString) -> KerberosResult<KerberosClient> {
        let ips = dns_lookup::lookup_host(&realm.to_string()).map_err(|_|
            KerberosErrorKind::NameResolutionError(realm.to_string())
        )?;

        return Ok(Self::new_witk_kdc_address(realm, ips[0]));
    }

    pub fn new_witk_kdc_address(realm: AsciiString, kdc_address: IpAddr) -> Self {
        return Self {
            realm,
            kdc_address,
            hostname: sysutils::get_hostname()
        };
    }

    pub fn request_tgt(&self, username: AsciiString, user_key: Option<Key>) -> KerberosResult<Credential> {
        let mut tgt_request = TGTRequest::new(
            self.realm.clone(), 
            self.kdc_address.clone(), 
            self.hostname.clone(), 
            username
        );
        
        if let Some(key) = user_key {
            tgt_request.set_user_key(key);
        }

        return tgt_request.request_tgt();

    }

}
