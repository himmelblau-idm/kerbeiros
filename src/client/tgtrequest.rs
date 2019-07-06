use std::net::IpAddr;
use ascii::AsciiString;
use crate::requester::*;
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