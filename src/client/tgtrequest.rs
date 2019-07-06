use std::net::IpAddr;
use ascii::AsciiString;
pub use crate::requester::*;
use crate::messages::*;
use crate::error::*;
use crate::constants::*;
use crate::credential::*;

pub struct TGTRequest {
    requester: Box<KerberosRequester>,
    as_req: AsReq,
    password: String
}

impl TGTRequest {

    pub fn new(
        realm: AsciiString, kdc_address: IpAddr, hostname: String,
        username: AsciiString, password: String
        ) -> Self {
        return Self {
            requester: new_requester(kdc_address),
            as_req: AsReq::new(realm, username, hostname),
            password
        };
    }

    pub fn _set_requester(&mut self, requester: Box<KerberosRequester>) {
        self.requester = requester;
    }

    pub fn request_tgt(&mut self) -> KerberosResult<Credential> {
        let raw_response = self.as_request_and_response()?;

        match self.parse_as_request_response(&raw_response)? {
            AsReqResponse::KrbError(krb_error) => {
                return self.process_1st_krb_error(krb_error);
            },
            AsReqResponse::AsRep(as_rep) => {
                return self.extract_credential_from_as_rep(as_rep);
            }
        }
    }

    fn process_1st_krb_error(&mut self, krb_error: KrbError) -> KerberosResult<Credential> {
        if krb_error.get_error_code() != KDC_ERR_PREAUTH_REQUIRED {
            return Err(KerberosErrorKind::KrbErrorResponse(krb_error))?;
        }

        return self.request_2nd_as_req();
    }

    fn request_2nd_as_req(&mut self) -> KerberosResult<Credential> {
        self.as_req.set_password(self.password.clone());
        let raw_response = self.as_request_and_response()?;

        match self.parse_as_request_response(&raw_response)? {
            AsReqResponse::KrbError(krb_error) => {
                return Err(KerberosErrorKind::KrbErrorResponse(krb_error))?;
            },
            AsReqResponse::AsRep(as_rep) => {
                return self.extract_credential_from_as_rep(as_rep);
            }
        }
    }

    fn extract_credential_from_as_rep(&self, as_rep: AsRep) -> KerberosResult<Credential> {
        match CredentialTransformer::from_kdc_rep_to_credential(&self.password, &as_rep) {
            Ok(credential) => {
                return Ok(credential);
            },
            Err(error) => {
                return Err(
                    KerberosErrorKind::ParseKdcRepError(as_rep, Box::new(error.kind().clone()))
                )?;
            }
        }
    }

    fn parse_as_request_response(&self, raw_response: &[u8]) -> KerberosResult<AsReqResponse> {
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

    fn as_request_and_response(&self) -> KerberosResult<Vec<u8>> {
        let raw_as_req = self.as_req.build().unwrap();
        return self.requester.request_and_response(&raw_as_req);
    }

}

enum AsReqResponse {
    KrbError(KrbError),
    AsRep(AsRep)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    

    #[should_panic(expected="Received KRB-ERROR response")]
    #[test]
    fn request_tgt_receiving_krb_error() {

        struct FakeRequester{}

        impl KerberosRequester for FakeRequester {
            fn request_and_response(&self, _raw_request: &[u8]) -> KerberosResult<Vec<u8>> {
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

        let mut tgt_request = TGTRequest::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            "A".to_string(),
            AsciiString::from_ascii("Mickey").unwrap(),
            "Minnie1234".to_string()
        );

        tgt_request._set_requester(Box::new(FakeRequester{}));

        tgt_request.request_tgt().unwrap();

    }

}
