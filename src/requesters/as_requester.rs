use std::net::IpAddr;
use ascii::AsciiString;
use crate::transporter::*;
use crate::messages::*;
use crate::error::*;
use crate::key::Key;

pub enum AsReqResponse {
    KrbError(KrbError),
    AsRep(AsRep)
}

pub struct ASRequester {
    transporter: Box<Transporter>,
    as_req: AsReq,
}

impl ASRequester {

    pub fn new(
        realm: AsciiString, username: AsciiString, 
        kdc_address: IpAddr, transport_protocol: TransportProtocol, 
        
    ) -> Self {
        return Self {
            transporter: new_transporter(kdc_address, transport_protocol),
            as_req: AsReq::new(realm, username)
        };
    }

    pub fn set_user_key(&mut self, user_key: Key) {
        self.as_req.set_user_key(user_key);
    }

    pub fn _set_transporter(&mut self, transporter: Box<Transporter>) {
        self.transporter = transporter;
    }

    pub fn request(&self) -> Result<AsReqResponse> {
        return ASRequest::request(&self.as_req, &self.transporter);
    }

}


struct ASRequest {}

impl ASRequest {

    pub fn request(as_req: &AsReq, transporter: &Box<Transporter>) -> Result<AsReqResponse> {
         let raw_as_req = as_req.build().unwrap();
         let raw_response = transporter.request_and_response(&raw_as_req)?;
         return Self::parse_as_request_response(&raw_response);
    }

    fn parse_as_request_response(raw_response: &[u8]) -> Result<AsReqResponse> {
        match KrbError::parse(raw_response) {
            Ok(krb_error) => {
                return Ok(AsReqResponse::KrbError(krb_error));
            },
            Err(_) => {
                let as_rep = AsRep::parse(raw_response)?;
                return Ok(AsReqResponse::AsRep(as_rep));
            }
        }
    }

}