use red_asn1::*;
use super::uint32::*;
use super::kerberosstring::*;
use super::realm::{Realm, RealmAsn1};
use super::kdcoptions::*;
use super::principalname::*;
use crate::error::{ErrorKind, Result};
use crate::constants::principal_name_types::*;
use super::kerberostime::*;
use super::hostaddress::*;
use super::encrypted_data::*;
use super::ticket::*;
use super::int32::*;
use rand::Rng;

use chrono::{Duration, Utc};


/// (*KDC-REQ-BODY*) Holds the most part of data of requests.
pub struct KdcReqBody {
    kdc_options: KdcOptions,
    cname: Option<PrincipalName>,
    realm: Realm,
    sname: Option<PrincipalName>,
    from: Option<KerberosTime>,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    nonce: UInt32,
    etypes: SeqOfInt32,
    addresses: Option<HostAddresses>,
    enc_authorization_data: Option<EncryptedData>,
    additional_tickets: Option<SeqOfTickets>
}

impl KdcReqBody {

    pub fn new(realm: Realm) -> KdcReqBody {
        return KdcReqBody{
            kdc_options: KdcOptions::default(),
            cname: None,
            realm,
            sname: None,
            from: None,
            till: Utc::now().checked_add_signed(Duration::weeks(20 * 52)).unwrap(),
            rtime: None,
            nonce: rand::thread_rng().gen::<u32>(),
            etypes: SeqOfInt32::new(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None
        };
    }

    pub fn additional_tickets(&self) -> &Option<SeqOfTickets> {
        return &self.additional_tickets;
    }

    pub fn addresses(&self) -> &Option<HostAddresses> {
        return &self.addresses;
    }

    #[cfg(test)]
    pub fn set_address(&mut self, address: HostAddress) {
        self.addresses = Some(HostAddresses::new(address));
    }

    pub fn cname(&self) -> &Option<PrincipalName> {
        return &self.cname;
    }

    pub fn set_cname(&mut self, name_type: i32, name_string: KerberosString) {
        self.cname = Some(PrincipalName::new(name_type, name_string));
    }

    pub fn enc_authorization_data(&self) -> &Option<EncryptedData> {
        return &self.enc_authorization_data;
    }

    pub fn push_etype(&mut self, etype: i32) {
        self.etypes.push(etype);
    }

    pub fn etypes(&self) -> &SeqOfInt32 {
        return &self.etypes;
    }

    pub fn from(&self) -> &Option<KerberosTime> {
        return &self.from;
    }

    pub fn set_kdc_options(&mut self, options: u32) {
        self.kdc_options.set_flags(options);
    }

    pub fn kdc_options(&self) -> &KdcOptions {
        return &self.kdc_options;
    }

    pub fn nonce(&self) -> UInt32 {
        return self.nonce;
    }

    #[cfg(test)]
    pub fn set_nonce(&mut self, nonce: UInt32) {
        self.nonce = nonce;
    }

    pub fn realm(&self) -> &Realm {
        return &self.realm;
    }

    pub fn rtime(&self) -> &Option<KerberosTime> {
        return &self.rtime;
    }

    pub fn set_rtime(&mut self, rtime: KerberosTime) {
        self.rtime = Some(rtime);
    }

    pub fn sname(&self) -> &Option<PrincipalName> {
        return &self.sname;
    }

    pub fn set_sname(&mut self, name_type: i32, name_string: KerberosString) {
        self.sname = Some(PrincipalName::new(name_type, name_string));
    }

    pub fn push_sname(&mut self, name_string: KerberosString) -> Result<()> {
        match &mut self.sname {
            Some(sname) => {
                sname.push(name_string);
                return Ok(());
            },
            None => {
                Err(ErrorKind::PrincipalNameTypeUndefined("sname".to_string()))?;
            }
        };
        unreachable!()
    }

    pub fn till(&self) -> &KerberosTime {
        return &self.till;
    }

    #[cfg(test)]
    pub fn set_till(&mut self, till: KerberosTime) {
        self.till = till;
    }

    pub fn set_username(&mut self, username: KerberosString) {
        self.set_cname(NT_PRINCIPAL, username);
    }

}

#[derive(Sequence, Default, Debug, PartialEq)]
pub(crate) struct KdcReqBodyAsn1 {
    #[seq_field(context_tag = 0)]
    kdc_options: SeqField<KdcOptionsAsn1>,
    #[seq_field(context_tag = 1, optional)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_field(context_tag = 2)]
    realm: SeqField<RealmAsn1>,
    #[seq_field(context_tag = 3, optional)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_field(context_tag = 4, optional)]
    from: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 5)]
    till: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 6, optional)]
    rtime: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 7)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_field(context_tag = 8)]
    etype: SeqField<SeqOfInt32Asn1>,
    #[seq_field(context_tag = 9, optional)]
    addresses: SeqField<HostAddressesAsn1>,
    #[seq_field(context_tag = 10, optional)]
    enc_authorization_data: SeqField<EncryptedDataAsn1>,
    #[seq_field(context_tag = 11, optional)]
    additional_tickets: SeqField<SeqOfTicketsAsn1>
}

impl KdcReqBodyAsn1 {

    fn set_asn1_values(&mut self, kdc_body: &KdcReqBody) {
        self.set_kdc_options(kdc_body.kdc_options().into());

        if let Some(cname) = kdc_body.cname() {
            self.set_cname(cname.into());
        }

        self.set_realm(kdc_body.realm().into());
        
        if let Some(sname) = kdc_body.sname() {
            self.set_sname(sname.into());
        }
        
        if let Some(from) = kdc_body.from() {
            self.set_from(from.into());
        }
        
        self.set_till(kdc_body.till().into());

        if let Some(rtime) = kdc_body.rtime() {
            self.set_rtime(rtime.into());
        }

        self.set_nonce(kdc_body.nonce().into());
        self.set_etype(kdc_body.etypes().into());

        if let Some(addresses) = kdc_body.addresses() {
            self.set_addresses(addresses.into());
        }
        if let Some(enc_authorization_data) = kdc_body.enc_authorization_data() {
            self.set_enc_authorization_data(enc_authorization_data.into());
        }
        
        if let Some(tickets) = kdc_body.additional_tickets() {
            self.set_additional_tickets(tickets.into());
        }
    }

}

impl From<&KdcReqBody> for KdcReqBodyAsn1 {
    fn from(kdc_body: &KdcReqBody) -> Self {
        let mut kdc_body_asn1 = Self::default();
        kdc_body_asn1.set_asn1_values(kdc_body);
        return kdc_body_asn1;
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;
    use chrono::prelude::*;

    #[test]
    fn create_default_kdc_req_body_asn1() {
        assert_eq!(
            KdcReqBodyAsn1 {
                kdc_options: SeqField::default(),
                cname: SeqField::default(),
                realm: SeqField::default(),
                sname: SeqField::default(),
                from: SeqField::default(),
                till: SeqField::default(),
                rtime: SeqField::default(),
                nonce: SeqField::default(),
                etype: SeqField::default(),
                addresses: SeqField::default(),
                enc_authorization_data: SeqField::default(),
                additional_tickets: SeqField::default(),
            },
            KdcReqBodyAsn1::default()
        )
    }

    #[test]
    fn test_encode_kdc_req_body() {
        let mut kdc_req_body = KdcReqBody::new(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        kdc_req_body.set_kdc_options(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);
        kdc_req_body.set_cname(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());
        kdc_req_body.set_sname(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        kdc_req_body.push_sname(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap()).unwrap();
        kdc_req_body.set_till(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        kdc_req_body.set_rtime(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        kdc_req_body.set_nonce(101225910);
        kdc_req_body.push_etype(AES256_CTS_HMAC_SHA1_96);
        kdc_req_body.push_etype(AES128_CTS_HMAC_SHA1_96);
        kdc_req_body.push_etype(RC4_HMAC);
        kdc_req_body.push_etype(RC4_HMAC_EXP);
        kdc_req_body.push_etype(RC4_HMAC_OLD_EXP);
        kdc_req_body.push_etype(DES_CBC_MD5);
        kdc_req_body.set_address(HostAddress::NetBios("HOLLOWBASTION".to_string()));

        let kdc_req_body_asn1 = KdcReqBodyAsn1::from(&kdc_req_body);

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