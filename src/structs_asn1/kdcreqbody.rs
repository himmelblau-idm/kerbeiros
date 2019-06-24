use asn1::*;
use asn1_derive::*;
use super::uint32::{UInt32, UInt32Asn1};
use super::kerberosstring::*;
use super::realm::{Realm, RealmAsn1};
use super::kdcoptions::{KdcOptions, KdcOptionsAsn1};
use super::principalname::*;
use super::super::error::*;
use super::super::constants::principalnametypes::*;
use super::kerberostime::{KerberosTime, KerberosTimeAsn1};
use super::hostaddress::{HostAddresses, HostAddressesAsn1, HostAddress};
use super::encrypteddata::{EncryptedData, EncryptedDataAsn1};
use super::ticket::*;
use super::etype::*;
use rand::Rng;

use chrono::{Duration, Utc, DateTime};

pub struct KdcReqBody {
    kdc_options: KdcOptions,
    cname: Option<PrincipalName>,
    realm: Realm,
    sname: Option<PrincipalName>,
    from: Option<KerberosTime>,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    nonce: UInt32,
    etypes: SeqOfEtype,
    addresses: Option<HostAddresses>,
    enc_authorization_data: Option<EncryptedData>,
    additional_tickets: Option<SeqOfTickets>
}

impl KdcReqBody {

    pub fn new(domain: Realm) -> KdcReqBody {
        return KdcReqBody{
            kdc_options: KdcOptions::new_empty(),
            cname: None,
            realm: domain,
            sname: None,
            from: None,
            till: Utc::now().checked_add_signed(Duration::weeks(20 * 52)).unwrap(),
            rtime: None,
            nonce: rand::thread_rng().gen::<u32>(),
            etypes: SeqOfEtype::new(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None
        };
    }

    pub fn set_kdc_options(&mut self, options: u32) {
        self.kdc_options.set_flags(options);
    }

    pub fn set_cname(&mut self, name_type: i32, name_string: KerberosString) {
        self.cname = Some(PrincipalName::new(name_type, name_string));
    }

    pub fn set_sname(&mut self, name_type: i32, name_string: KerberosString) {
        self.sname = Some(PrincipalName::new(name_type, name_string));
    }

    pub fn push_sname(&mut self, name_string: KerberosString) -> KerberosResult<()> {
        match &mut self.sname {
            Some(sname) => {
                sname.push(name_string);
                return Ok(());
            },
            None => {
                Err(KerberosErrorKind::PrincipalNameTypeUndefined("sname".to_string()))?;
            }
        };
        unreachable!()
    }

    pub fn _set_till(&mut self, date: DateTime<Utc>) {
        self.till = date;
    }

    pub fn set_rtime(&mut self, date: DateTime<Utc>) {
        self.rtime = Some(date);
    }

    pub fn _set_nonce(&mut self, nonce: u32) {
        self.nonce = nonce;
    }

    pub fn push_etype(&mut self, etype: i32) {
        self.etypes.push(etype);
    }

    pub fn set_address(&mut self, address: HostAddress) {
        self.addresses = Some(HostAddresses::new(address));
    }

    pub fn set_username(&mut self, username: AsciiString) {
        let kerberos_str = username;
        self.set_cname(NT_PRINCIPAL, kerberos_str);
    }

    pub fn asn1_type(&self) -> KdcReqBodyAsn1 {
        return KdcReqBodyAsn1::new(&self);
    }

}

#[derive(Asn1Sequence)]
pub struct KdcReqBodyAsn1 {
    #[seq_comp(context_tag = 0)]
    kdc_options: SeqField<KdcOptionsAsn1>,
    #[seq_comp(context_tag = 1, optional)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 2)]
    realm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 3, optional)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 4, optional)]
    from: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 5)]
    till: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 6, optional)]
    rtime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 7)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 8)]
    etype: SeqField<SeqOfEtypeAsn1>,
    #[seq_comp(context_tag = 9, optional)]
    addresses: SeqField<HostAddressesAsn1>,
    #[seq_comp(context_tag = 10, optional)]
    enc_authorization_data: SeqField<EncryptedDataAsn1>,
    #[seq_comp(context_tag = 11, optional)]
    additional_tickets: SeqField<SeqOfTicketsAsn1>
}

impl KdcReqBodyAsn1 {

    fn new(kdc_body: &KdcReqBody) -> KdcReqBodyAsn1 {
        let mut kdc_body_asn1 = Self::new_empty();
        kdc_body_asn1._set_asn1_values(kdc_body);
        return kdc_body_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            kdc_options: SeqField::new(),
            cname: SeqField::new(),
            realm: SeqField::new(),
            sname: SeqField::new(),
            from: SeqField::new(),
            till: SeqField::new(),
            rtime: SeqField::new(),
            nonce: SeqField::new(),
            etype: SeqField::new(),
            addresses: SeqField::new(),
            enc_authorization_data: SeqField::new(),
            additional_tickets: SeqField::new(),
        };
    }

    fn _set_asn1_values(&mut self, kdc_body: &KdcReqBody) {
        self.set_kdc_options(kdc_body.kdc_options.asn1_type());

        if let Some(cname) = &kdc_body.cname {
            self.set_cname(cname.asn1_type());
        }

        self.set_realm(RealmAsn1::new(kdc_body.realm.clone()));
        
        if let Some(sname) = &kdc_body.sname {
            self.set_sname(sname.asn1_type());
        }
        
        if let Some(from) = &kdc_body.from {
            self.set_from(KerberosTimeAsn1::new(from.clone()));
        }
        
        self.set_till(KerberosTimeAsn1::new(kdc_body.till.clone()));

        if let Some(rtime) = &kdc_body.rtime {
            self.set_rtime(KerberosTimeAsn1::new(rtime.clone()));
        }

        self.set_nonce(UInt32Asn1::new(kdc_body.nonce));
        self.set_etype(kdc_body.etypes.asn1_type());

        if let Some(addresses) = &kdc_body.addresses {
            self.set_addresses(addresses.asn1_type());
        }
        if let Some(enc_authorization_data) = &kdc_body.enc_authorization_data {
            self.set_enc_authorization_data(enc_authorization_data.asn1_type());
        }
        
        if let Some(tickets) = &kdc_body.additional_tickets {
            self.set_additional_tickets(tickets.asn1_type());
        }
    }

}


impl Asn1Tagged for KdcReqBodyAsn1{

    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }

}

impl Asn1InstanciableObject for KdcReqBodyAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::constants::*;
    use chrono::*;

    #[test]
    fn test_encode_kdc_req_body() {
        let mut kdc_req_body = KdcReqBody::new(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        kdc_req_body.set_kdc_options(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);
        kdc_req_body.set_cname(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());
        kdc_req_body.set_sname(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        kdc_req_body.push_sname(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap()).unwrap();
        kdc_req_body._set_till(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        kdc_req_body.set_rtime(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        kdc_req_body._set_nonce(101225910);
        kdc_req_body.push_etype(AES256_CTS_HMAC_SHA1_96);
        kdc_req_body.push_etype(AES128_CTS_HMAC_SHA1_96);
        kdc_req_body.push_etype(RC4_HMAC);
        kdc_req_body.push_etype(RC4_HMAC_EXP);
        kdc_req_body.push_etype(RC4_HMAC_OLD_EXP);
        kdc_req_body.push_etype(DES_CBC_MD5);
        kdc_req_body.set_address(HostAddress::NetBios("HOLLOWBASTION".to_string()));

        let kdc_req_body_asn1 = kdc_req_body.asn1_type();

        assert_eq!(vec![0x30, 0x81, 0xb9, 
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
        kdc_req_body_asn1.encode().unwrap());
    }
}