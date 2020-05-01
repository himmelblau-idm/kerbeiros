use super::super::basics::*;
use super::super::ticket::*;
use super::kdc_options::*;
use crate::constants::principal_name_types::*;
use crate::{Error, Result};
use rand::Rng;
use red_asn1::*;

use chrono::{Duration, Utc};

/// (*KDC-REQ-BODY*) Holds the most part of data of requests.
#[derive(Debug, PartialEq, Clone)]
pub struct KdcReqBody {
    pub kdc_options: KdcOptions,
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: Option<PrincipalName>,
    pub from: Option<KerberosTime>,
    pub till: KerberosTime,
    pub rtime: Option<KerberosTime>,
    pub nonce: UInt32,
    pub etypes: SeqOfInt32,
    pub addresses: Option<HostAddresses>,
    pub enc_authorization_data: Option<EncryptedData>,
    pub additional_tickets: Option<SeqOfTickets>,
}

impl KdcReqBody {
    pub fn new(realm: Realm) -> KdcReqBody {
        return KdcReqBody {
            kdc_options: KdcOptions::default(),
            cname: None,
            realm,
            sname: None,
            from: None,
            till: Utc::now()
                .checked_add_signed(Duration::weeks(20 * 52))
                .unwrap(),
            rtime: None,
            nonce: rand::thread_rng().gen::<u32>(),
            etypes: SeqOfInt32::new(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
    }

    #[cfg(test)]
    pub fn set_address(&mut self, address: HostAddress) {
        self.addresses = Some(HostAddresses::new(address));
    }

    pub fn push_sname(&mut self, name_string: KerberosString) -> Result<()> {
        match &mut self.sname {
            Some(sname) => {
                sname.push(name_string);
                return Ok(());
            }
            None => {
                Err(Error::PrincipalNameTypeUndefined(
                    "sname".to_string(),
                ))?;
            }
        };
        unreachable!()
    }

    pub fn set_username(&mut self, username: KerberosString) {
        self.cname = Some(PrincipalName::new(NT_PRINCIPAL, username));
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
    additional_tickets: SeqField<SeqOfTicketsAsn1>,
}

impl KdcReqBodyAsn1 {
    fn set_asn1_values(&mut self, kdc_body: KdcReqBody) {
        self.set_kdc_options((&kdc_body.kdc_options).into());

        if let Some(cname) = kdc_body.cname {
            self.set_cname(cname.into());
        }

        self.set_realm(kdc_body.realm.into());

        if let Some(sname) = kdc_body.sname {
            self.set_sname(sname.into());
        }

        if let Some(from) = kdc_body.from {
            self.set_from(from.into());
        }

        self.set_till(kdc_body.till.into());

        if let Some(rtime) = kdc_body.rtime {
            self.set_rtime(rtime.into());
        }

        self.set_nonce(kdc_body.nonce.into());
        self.set_etype((&kdc_body.etypes).into());

        if let Some(addresses) = kdc_body.addresses {
            self.set_addresses((&addresses).into());
        }
        if let Some(enc_authorization_data) = kdc_body.enc_authorization_data
        {
            self.set_enc_authorization_data(
                enc_authorization_data.clone().into(),
            );
        }

        if let Some(tickets) = kdc_body.additional_tickets {
            self.set_additional_tickets(tickets.into());
        }
    }
}

impl From<KdcReqBody> for KdcReqBodyAsn1 {
    fn from(kdc_body: KdcReqBody) -> Self {
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
        let mut kdc_req_body = KdcReqBody::new(
            KerberosString::from_ascii("KINGDOM.HEARTS").unwrap(),
        );
        kdc_req_body
            .kdc_options
            .set_flags(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);
        kdc_req_body.cname = Some(PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from_ascii("mickey").unwrap(),
        ));

        kdc_req_body.sname = Some(PrincipalName::new(
            NT_SRV_INST,
            KerberosString::from_ascii("krbtgt").unwrap(),
        ));
        kdc_req_body
            .push_sname(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap())
            .unwrap();
        kdc_req_body.till = Utc.ymd(2037, 9, 13).and_hms(02, 48, 5);
        kdc_req_body.rtime = Some(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5));
        kdc_req_body.nonce = 101225910;
        kdc_req_body.etypes.push(AES256_CTS_HMAC_SHA1_96);
        kdc_req_body.etypes.push(AES128_CTS_HMAC_SHA1_96);
        kdc_req_body.etypes.push(RC4_HMAC);
        kdc_req_body.etypes.push(RC4_HMAC_EXP);
        kdc_req_body.etypes.push(RC4_HMAC_OLD_EXP);
        kdc_req_body.etypes.push(DES_CBC_MD5);
        kdc_req_body
            .set_address(HostAddress::NetBios("HOLLOWBASTION".to_string()));

        let kdc_req_body_asn1 = KdcReqBodyAsn1::from(kdc_req_body);

        assert_eq!(
            vec![
                0x30, 0x81, 0xb9, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81,
                0x00, 0x10, 0xa1, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01,
                0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d, 0x69, 0x63,
                0x6b, 0x65, 0x79, 0xa2, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e,
                0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54,
                0x53, 0xa3, 0x23, 0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02,
                0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74,
                0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
                0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa5, 0x11,
                0x18, 0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33,
                0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa6, 0x11, 0x18,
                0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30,
                0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa7, 0x06, 0x02, 0x04,
                0x06, 0x08, 0x95, 0xb6, 0xa8, 0x15, 0x30, 0x13, 0x02, 0x01,
                0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18,
                0x02, 0x02, 0xff, 0x79, 0x02, 0x01, 0x03, 0xa9, 0x1d, 0x30,
                0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12,
                0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42, 0x41,
                0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
            ],
            kdc_req_body_asn1.encode().unwrap()
        );
    }
}
