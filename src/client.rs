use std::net::IpAddr;
use dns_lookup;
use ascii::AsciiString;
use crate::request::*;
use crate::messages::*;
use crate::error::*;
use crate::sysutils;
use crate::constants::*;
use crate::credential::*;

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

    fn new_witk_kdc_address(realm: AsciiString, kdc_address: IpAddr) -> Self {
        return Self {
            realm,
            kdc_address,
            hostname: sysutils::get_hostname()
        };
    }

    pub fn request_tgt(&self, username: AsciiString, password: String) -> KerberosResult<Credential> {
        return KerberosTGTRequest::new(
            self.realm.clone(), 
            self.kdc_address.clone(), 
            self.hostname.clone(), 
            username,
            password
        ).request_tgt();
    }

}


struct KerberosTGTRequest {
    requester: KerberosRequester,
    as_req: AsReq,
    password: String
}

impl KerberosTGTRequest {

    fn new(
        realm: AsciiString, kdc_address: IpAddr, hostname: String,
        username: AsciiString, password: String
        ) -> Self {
        return Self {
            requester: KerberosRequester::new(kdc_address),
            as_req: AsReq::new(realm, username, hostname),
            password
        };
    }

    fn request_tgt(&self) -> KerberosResult<Credential> {
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

    fn process_1st_krb_error(&self, krb_error: KrbError) -> KerberosResult<Credential> {
        if krb_error.get_error_code() != KDC_ERR_PREAUTH_REQUIRED {
            return Err(KerberosErrorKind::KrbErrorResponse(krb_error))?;
        }

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
        as_rep.decrypt_encrypted_data_with_password(&self.password);

        obtener credenciales de aqui....
    }

    fn parse_as_request_response(&self, raw_response: &[u8]) -> KerberosResult<AsReqResponse> {
        match KrbError::parse(raw_response) {
            Ok(krb_error) => {
                return Ok(AsReqResponse::KrbError(krb_error));
            },
            Err(err) => {
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