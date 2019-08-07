use std::net::IpAddr;
pub use ascii::AsciiString;
use crate::error::*;
use crate::credential::*;
use super::tgtrequest::*;
use crate::key::Key;
use crate::transporter::*;


#[derive(Debug)]
pub struct KerberosClient {
    realm: AsciiString,
    kdc_address: IpAddr,
    transport_protocol: TransportProtocol
}

impl KerberosClient {

    pub fn new(realm: AsciiString, kdc_address: IpAddr) -> Self {
        return Self {
            realm,
            kdc_address,
            transport_protocol: TransportProtocol::TCP
        };
    }

    pub fn set_transport_protocol(&mut self, transport_protocol: TransportProtocol) {
        self.transport_protocol = transport_protocol;
    }

    pub fn request_tgt(&self, username: AsciiString, user_key: Option<Key>) -> Result<Credential> {
        let mut tgt_request = TGTRequest::new(
            self.realm.clone(), 
            self.kdc_address.clone(),
            self.transport_protocol,
            username
        );
        
        if let Some(key) = user_key {
            tgt_request.set_user_key(key);
        }

        return tgt_request.request_tgt();

    }

}
