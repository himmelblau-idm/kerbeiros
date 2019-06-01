use std::result::Result;
use chrono::{Utc, DateTime, Duration};
use asn1::*;
use asn1_derive::*;
use super::realm::Realm;
use super::super::error::*;
use super::padata::*;
use super::kdcreqbody::{KdcReqBody, KdcReqBodyAsn1};
use super::kdcoptions::*;
use super::etype::*;
use super::kerberosstring::*;
use super::principalname::*;
use super::hostaddress::HostAddress;
use super::kerbpapacrequest::KerbPaPacRequest;


pub struct AsReq {
    pvno: i8,
    msg_type: i8,
    padata: Option<SeqOfPaData>,
    req_body: KdcReqBody
}

impl AsReq {

    pub fn new(domain: &String, username: &String, hostname: &String) -> KerberosResult<AsReq> {
        let mut as_req = AsReq{
            pvno: 5,
            msg_type: 10,
            padata: None,
            req_body: KdcReqBody::new(Realm::from(domain)?)
        };

        as_req.request_pac();
        as_req.set_username(username)?;
        as_req.set_kdc_options(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);

        as_req.set_sname(NT_SRV_INST, KerberosString::from("krbtgt").unwrap());
        as_req.push_sname(KerberosString::from(domain)?).unwrap();

        as_req.set_default_rtime();

        as_req.push_etype(ETYPE_AES256_CTS_HMAC_SHA1_96);
        as_req.push_etype(ETYPE_AES128_CTS_HMAC_SHA1_96);
        as_req.push_etype(ETYPE_ARCFOUR_HMAC_MD5);
        as_req.push_etype(ETYPE_ARCFOUR_HMAC_MD5_56);
        as_req.push_etype(ETYPE_ARCFOUR_HMAC_OLD_EXP);
        as_req.push_etype(ETYPE_DES_CBC_MD5);

        as_req.set_address(HostAddress::NetBios(hostname.clone()));

        return Ok(as_req);
    }

    fn request_pac(&mut self) {
        self.push_padata(PaData::PaPacRequest(KerbPaPacRequest::new(true)));
    }

    fn push_padata(&mut self, padata: PaData) {
        match &mut self.padata {
            Some(padatas) => {
                padatas.push(padata);
            },
            None => {
                let mut padatas = SeqOfPaData::new();
                padatas.push(padata);
                self.padata = Some(padatas);
            }
        };
    }

    fn set_username(&mut self, username: &String) -> Result<(), KerberosError> {
        return self.req_body.set_username(username);
        
    }

    fn set_kdc_options(&mut self, options: u32) {
        self.req_body.set_kdc_options(options);
    }


    fn set_sname(&mut self, name_type: i32, name_string: KerberosString){
        self.req_body.set_sname(name_type, name_string);
    }

    fn push_sname(&mut self, name_string: KerberosString) -> Result<(), KerberosError> {
        return self.req_body.push_sname(name_string);
    }

    fn set_till(&mut self, date: DateTime<Utc>) {
        self.req_body.set_till(date);
    }

    fn set_default_rtime(&mut self) {
        self.set_rtime(Utc::now().checked_add_signed(Duration::weeks(20 * 52)).unwrap())
    }

    fn set_rtime(&mut self, date: DateTime<Utc>) {
        self.req_body.set_rtime(date);
    }

    fn set_nonce(&mut self, nonce: u32) {
        self.req_body.set_nonce(nonce);
    }

    fn push_etype(&mut self, etype: i32) {
        self.req_body.push_etype(etype);
    }

    fn set_address(&mut self, address: HostAddress) {
        self.req_body.set_address(address);
    }

    pub fn build(&self) -> Vec<u8> {
        return self.asn1_type().encode().unwrap();
    }

    pub fn asn1_type(&self) -> AsReqAsn1 {
        return AsReqAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
#[seq(application_tag = 10)]
pub struct AsReqAsn1 {
    #[seq_comp(context_tag = 1)]
    pvno: SeqField<Integer>,
    #[seq_comp(context_tag = 2)]
    msg_type: SeqField<Integer>,
    #[seq_comp(context_tag = 3, optional)]
    padata: SeqField<SeqOfPaDataAsn1>,
    #[seq_comp(context_tag = 4)]
    req_body: SeqField<KdcReqBodyAsn1>
}


impl AsReqAsn1 {

    fn new(as_req: &AsReq) -> Self {
        let mut as_req_asn1 = Self::new_empty();

        as_req_asn1._set_asn1_values(as_req);
        return as_req_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            pvno: SeqField::new(),
            msg_type: SeqField::new(),
            padata: SeqField::new(),
            req_body: SeqField::new()
        };
    }

    fn _set_asn1_values(&mut self, as_req: &AsReq) {
        self.set_pvno(Integer::new(as_req.pvno as i64));
        self.set_msg_type(Integer::new(as_req.msg_type as i64));

        if let Some(seq_of_padatas) = &as_req.padata {
            self.set_padata(seq_of_padatas.asn1_type());
        }

        self.set_req_body(as_req.req_body.asn1_type());
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use chrono::*;

    #[test]
    fn test_encode_as_req() {
        let mut as_req = AsReq::new(&"KINGDOM.HEARTS".to_string(), &"mickey".to_string(), &"HOLLOWBASTION".to_string()).unwrap();
        as_req.set_till(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        as_req.set_rtime(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        as_req.set_nonce(101225910);

        assert_eq!(vec![0x6a, 0x81, 0xe3, 0x30, 0x81, 0xe0, 
                        0xa1, 0x03, 0x02, 0x01, 0x05, 
                        0xa2, 0x03, 0x02, 0x01, 0x0a, 
                        0xa3, 0x15, 0x30, 0x13, 0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff, 
                        0xa4, 0x81, 0xbc, 0x30, 0x81, 0xb9, 
                            0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10, 
                            0xa1, 0x13, 0x30, 0x11, 
                                0xa0, 0x03, 0x02, 0x01, 0x01, 
                                0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                            0xa2, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                                0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                            0xa3, 0x23, 0x30, 0x21, 
                                0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 
                                0x1a, 0x30, 0x18, 
                                    0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                                    0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                                        0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                            0xa5, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 
                                0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 
                            0xa6, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 
                                0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 
                            0xa7, 0x06, 0x02, 0x04, 0x06, 0x08, 0x95, 0xb6, 
                            0xa8, 0x15, 0x30, 0x13, 
                                0x02, 0x01, 0x12, 
                                0x02, 0x01, 0x11, 
                                0x02, 0x01, 0x17, 
                                0x02, 0x01, 0x18, 
                                0x02, 0x02, 0xff, 0x79, 
                                0x02, 0x01, 0x03, 
                            0xa9, 0x1d, 0x30, 0x1b, 0x30, 0x19, 
                                0xa0, 0x03, 0x02, 0x01, 0x14, 
                                0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 
                                    0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20],
        as_req.build());

    }

}