use std::net::IpAddr;
use dns_lookup;
use ascii::AsciiString;
use crate::request::*;
use crate::messages::*;
use crate::error::*;
use crate::tickets::*;
use crate::sysutils;
use crate::constants::*;

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

    pub fn request_tgt(&self, username: AsciiString, password: String) -> KerberosResult<TGT> {

        let requester = KerberosRequester::new(self.kdc_address.clone());

        let mut as_req = AsReq::new(self.realm.clone(), username, self.hostname.clone());
        let raw_as_req = as_req.build().unwrap();
        let raw_response = requester.request_and_response(&raw_as_req)?;

        let krb_error = KrbError::parse(&raw_response)?; manexar o caso no que se devolva AS-REP

        if krb_error.get_error_code() != KDC_ERR_PREAUTH_REQUIRED {
            return Err(KerberosErrorKind::KrbErrorResponse(krb_error))?;
        }

        as_req.set_password(password);
        let raw_as_req = as_req.build().unwrap();
        let raw_response = requester.request_and_response(&raw_as_req)?;

        let as_rep = AsRep::parse(&raw_response)?; manexar o caso no que se devolva KRB-ERROR


        seguramente este ben crear que se encargue de manexar a request do TGT, KerberosRequester


        unimplemented!();

    }

}

