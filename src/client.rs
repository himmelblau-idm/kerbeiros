use super::structs::*;
use super::request::*;
use super::error::*;


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
        
        let mut as_req = AsReq::new(&self.domain, username, &"HOLLOWBASTION".to_string()).unwrap();
        // as_req.set_password(password);
        let raw_as_req = as_req.build();

        let _raw_kdc_err = self._request(&raw_as_req)?;

        let raw_kdc_err = vec![0x7e, 0x62, 0x30, 0x60, 
                                0xa0, 0x03, 0x02, 0x01, 0x05, 
                                0xa1, 0x03, 0x02, 0x01, 0x1e, 
                                0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x32, 
                                    0x32, 0x30, 0x35, 0x32, 0x38, 0x31, 0x30, 0x5a, 
                                0xa5, 0x05, 0x02, 0x03, 0x08, 0xe6, 0xc6, 
                                0xa6, 0x03, 0x02, 0x01, 0x06, 
                                0xa9, 0x10, 0x1b, 0x0e, 0x6b, 0x69, 0x6e, 0x67, 0x64, 0x6f, 
                                    0x6d, 0x2e, 0x68, 0x65, 0x61, 0x72, 0x74, 0x73, 
                                0xaa, 0x23, 0x30, 0x21, 
                                    0xa0, 0x03, 0x02, 0x01, 0x02, 
                                    0xa1, 0x1a, 0x30, 0x18, 
                                        0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                                        0x1b, 0x0e, 0x6b, 0x69, 0x6e, 0x67, 0x64, 0x6f, 0x6d, 
                                            0x2e, 0x68, 0x65, 0x61, 0x72, 0x74, 0x73];

        let _kdc_err = KrbError::parse(&raw_kdc_err).unwrap();

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

