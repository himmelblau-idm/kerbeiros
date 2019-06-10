use super::messages::*;
use super::request::*;
use super::error::*;
use super::tickets::*;


#[derive(Debug)]
pub struct KerberosClient {
    domain: String,
    requester: KerberosRequester
}

impl KerberosClient {
    pub fn new(domain: String) -> KerberosClient {
        return KerberosClient { 
            domain,
            requester: KerberosRequester::new(&"10.0.0.1".to_string()).unwrap()
        };
    }

    pub fn request_tgt(&self, username: &String, password: &String) -> KerberosResult<TGT> {
        
        let mut as_req = AsReq::new(self.domain.clone(), username.clone(), "HOLLOWBASTION".to_string());
        as_req.set_password(password.clone());
        let raw_as_req = as_req.build().unwrap();

        let raw_kdc_err = self._request(&raw_as_req)?;

        
        // let as_rep = AsRep::parse(&raw_as_rep).unwrap();
        
        let kdc_err = KrbError::parse(&raw_kdc_err).unwrap();

        println!("error_code = {}", kdc_err.get_error_code());

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

    fn _request(&self, raw_request: &Vec<u8>) -> KerberosResult<Vec<u8>> {
        return self.requester.request(raw_request);
    }

}

