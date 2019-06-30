use crate::request::*;
use crate::messages::*;
use ascii::AsciiString;
use crate::error::*;
use crate::tickets::*;
use std::net::IpAddr;
use dns_lookup;

#[derive(Debug)]
pub struct KerberosClient {
    realm: AsciiString,
    kdc_address: IpAddr
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
            kdc_address
        };
    }

    pub fn request_tgt(&self, username: AsciiString, password: String) -> KerberosResult<TGT> {

        let requester = KerberosRequester::new(self.kdc_address.clone());

        let mut as_req = AsReq::new(self.realm.clone(), username, "HOLLOWBASTION".to_string());
        as_req.set_password(password);
        let raw_as_req = as_req.build().unwrap();

        //let raw_kdc_err = self._request(&raw_as_req)?;

        
        // let as_rep = AsRep::parse(&raw_as_rep).unwrap();
        
        // let kdc_err = KrbError::parse(&raw_kdc_err).unwrap();

        // println!("error_code = {}", kdc_err.get_error_code());

        unimplemented!();

        /*
        match KdcErr::parse(&raw_kdc_err) {
            Ok(kdc_err) => {

                if kdc_err.error_code == KDC_ERR_PREAUTH_REQUIRED {
                    let as_req = AsReq::new(&self.domain, username);
                    as_req.set_password(password);
                    let raw_as_req = as_req.build();

                    let raw_as_rep = self.send(&raw_as_req);

                    let as_rep = AsRep::parse(&raw_as_rep, password)?;

                    return Ok(as_rep.get_TGT());
                }else {
                    return Err("Kerberos error");
                }

            },
            Err(_) => {
                let as_rep = AsRep::parse(&raw_kdc_err, password)?;
                return Ok(as_rep.get_TGT());
            }
        }*/
    }

}

