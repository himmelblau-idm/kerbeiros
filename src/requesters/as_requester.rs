use std::net::IpAddr;
use ascii::AsciiString;
use crate::transporter::*;
use crate::messages::*;
use crate::error::*;
use crate::key::Key;

#[derive(Debug, PartialEq)]
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

    #[cfg(test)]
    pub fn set_transporter(&mut self, transporter: Box<Transporter>) {
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

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn receive_krb_error() {

        struct FakeTransporter{}

        impl Transporter for FakeTransporter {
            fn request_and_response(&self, _raw_request: &[u8]) -> Result<Vec<u8>> {
                return Ok(vec![
                    0x7e, 0x81, 0xdc, 0x30, 0x81, 0xd9, 
                    0xa0, 0x03, 0x02, 0x01, 0x05, 
                    0xa1, 0x03, 0x02, 0x01, 0x1e, 
                    0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30, 0x33, 0x31, 0x5a, 
                    0xa5, 0x05, 0x02, 0x03, 0x05, 0x34, 0x2f, 
                    0xa6, 0x03, 0x02, 0x01, 0x19, 
                    0xa9, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                    0xaa, 0x23, 0x30, 0x21, 
                        0xa0, 0x03, 0x02, 0x01, 0x02, 
                        0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                    0xac, 0x77, 0x04, 0x75, 0x30, 0x73, 
                        0x30, 0x50, 
                            0xa1, 0x03, 0x02, 0x01, 0x13, 
                            0xa2, 0x49, 0x04, 0x47, 
                                0x30, 0x45, 0x30, 0x1d, 
                                    0xa0, 0x03, 0x02, 0x01, 0x12, 
                                    0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                                0x30, 0x05, 
                                    0xa0, 0x03, 0x02, 0x01, 0x17, 
                                0x30, 0x1d, 
                                    0xa0, 0x03, 0x02, 0x01, 0x03, 
                                    0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00, 
                        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x10, 0xa2, 0x02, 0x04, 0x00, 
                        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2, 0x02, 0x04, 0x00
                ]);
            }
        }

        let mut as_requester = ASRequester::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("Mickey").unwrap(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            TransportProtocol::TCP
        );

        as_requester.set_transporter(Box::new(FakeTransporter{}));

        let response = as_requester.request().unwrap();

        match response {
            AsReqResponse::KrbError(_) => {

            }
            _ => {
                unreachable!();
            }
        }
    }
}
