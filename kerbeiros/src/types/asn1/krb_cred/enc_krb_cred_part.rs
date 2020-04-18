use super::super::basics::*;
use super::krb_cred_info::*;
use red_asn1::*;

#[cfg(test)]
use crate::error::{ErrorKind, Result};

/// (*EncKrbCredPart*) Holds the data for user in [KrbCred](./struct.KrbCred.html)
#[derive(Debug, Clone, PartialEq)]
pub struct EncKrbCredPart {
    ticket_info: SeqOfKrbCredInfo,
    nonce: Option<UInt32>,
    timestamp: Option<KerberosTime>,
    usec: Option<Microseconds>,
    s_address: Option<HostAddress>,
    r_address: Option<HostAddress>,
}

impl EncKrbCredPart {
    pub fn new(ticket_info: SeqOfKrbCredInfo) -> Self {
        return Self {
            ticket_info,
            nonce: None,
            timestamp: None,
            usec: None,
            s_address: None,
            r_address: None,
        };
    }

    pub fn nonce(&self) -> Option<UInt32> {
        return self.nonce;
    }

    #[cfg(test)]
    fn set_nonce(&mut self, nonce: UInt32) {
        self.nonce = Some(nonce);
    }

    pub fn r_address(&self) -> &Option<HostAddress> {
        return &self.r_address;
    }

    #[cfg(test)]
    fn set_r_address(&mut self, r_address: HostAddress) {
        self.r_address = Some(r_address);
    }

    pub fn s_address(&self) -> &Option<HostAddress> {
        return &self.s_address;
    }

    #[cfg(test)]
    fn set_s_address(&mut self, s_address: HostAddress) {
        self.s_address = Some(s_address);
    }

    pub fn ticket_info(&self) -> &SeqOfKrbCredInfo {
        return &self.ticket_info;
    }

    pub fn timestamp(&self) -> &Option<KerberosTime> {
        return &self.timestamp;
    }

    #[cfg(test)]
    fn set_timestamp(&mut self, timestamp: KerberosTime) {
        self.timestamp = Some(timestamp);
    }

    pub fn usec(&self) -> &Option<Microseconds> {
        return &self.usec;
    }

    #[cfg(test)]
    fn set_usec(&mut self, usec: Microseconds) {
        self.usec = Some(usec);
    }

    pub fn build(&self) -> Vec<u8> {
        return EncKrbCredPartAsn1::from(self).encode().unwrap();
    }
}

#[derive(Sequence, Default, Debug, PartialEq)]
#[seq(application_tag = 29)]
pub(crate) struct EncKrbCredPartAsn1 {
    #[seq_field(context_tag = 0)]
    ticket_info: SeqField<SeqOfKrbCredInfoAsn1>,
    #[seq_field(context_tag = 1, optional)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_field(context_tag = 2, optional)]
    timestamp: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 3, optional)]
    usec: SeqField<MicrosecondsAsn1>,
    #[seq_field(context_tag = 4, optional)]
    s_address: SeqField<HostAddressAsn1>,
    #[seq_field(context_tag = 5, optional)]
    r_address: SeqField<HostAddressAsn1>,
}

impl EncKrbCredPartAsn1 {
    #[cfg(test)]
    pub fn no_asn1_type(&self) -> Result<EncKrbCredPart> {
        let ticket_info = self.get_ticket_info().ok_or_else(|| {
            ErrorKind::NotAvailableData("EncKrbCredPart::ticket_info".to_string())
        })?;

        let mut enc_krb_cred_part = EncKrbCredPart::new(ticket_info.no_asn1_type()?);

        if let Some(nonce) = self.get_nonce() {
            enc_krb_cred_part.set_nonce(nonce.no_asn1_type()?);
        }

        if let Some(timestamp) = self.get_timestamp() {
            enc_krb_cred_part.set_timestamp(timestamp.no_asn1_type()?);
        }

        if let Some(usec) = self.get_usec() {
            enc_krb_cred_part.set_usec(usec.no_asn1_type()?);
        }

        if let Some(s_address) = self.get_s_address() {
            enc_krb_cred_part.set_s_address(s_address.no_asn1_type()?);
        }

        if let Some(r_address) = self.get_r_address() {
            enc_krb_cred_part.set_r_address(r_address.no_asn1_type()?);
        }

        return Ok(enc_krb_cred_part);
    }
}

impl From<&EncKrbCredPart> for EncKrbCredPartAsn1 {
    fn from(enc_krb_cred_part: &EncKrbCredPart) -> Self {
        let mut enc_krb_cred_part_asn1 = Self::default();

        enc_krb_cred_part_asn1.set_ticket_info(enc_krb_cred_part.ticket_info().into());

        if let Some(nonce) = enc_krb_cred_part.nonce() {
            enc_krb_cred_part_asn1.set_nonce(nonce.into());
        }
        if let Some(timestamp) = enc_krb_cred_part.timestamp() {
            enc_krb_cred_part_asn1.set_timestamp(timestamp.clone().into());
        }
        if let Some(usec) = enc_krb_cred_part.usec() {
            enc_krb_cred_part_asn1.set_usec(usec.into());
        }
        if let Some(s_address) = enc_krb_cred_part.s_address() {
            enc_krb_cred_part_asn1.set_s_address(s_address.into());
        }
        if let Some(r_address) = enc_krb_cred_part.r_address() {
            enc_krb_cred_part_asn1.set_r_address(r_address.into());
        }

        return enc_krb_cred_part_asn1;
    }
}

#[cfg(test)]
mod test {
    use super::super::super::*;
    use super::*;
    use crate::constants::*;
    use chrono::prelude::*;

    #[test]
    fn create_default_enc_krb_cred_part_asn1() {
        assert_eq!(
            EncKrbCredPartAsn1 {
                ticket_info: SeqField::default(),
                nonce: SeqField::default(),
                timestamp: SeqField::default(),
                usec: SeqField::default(),
                s_address: SeqField::default(),
                r_address: SeqField::default()
            },
            EncKrbCredPartAsn1::default()
        );
    }

    #[test]
    fn decode_enc_krb_cred_part() {
        let raw: Vec<u8> = vec![
            0x7d, 0x81, 0xd9, 0x30, 0x81, 0xd6, 0xa0, 0x81, 0xd3, 0x30, 0x81, 0xd0, 0x30, 0x81,
            0xcd, 0xa0, 0x2b, 0x30, 0x29, 0xa0, 0x3, 0x2, 0x1, 0x12, 0xa1, 0x22, 0x4, 0x20, 0x89,
            0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51,
            0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f, 0x70, 0xc2,
            0x78, 0x47, 0x86, 0xa1, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
            0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x13, 0x30, 0x11, 0xa0, 0x3, 0x2, 0x1,
            0x1, 0xa1, 0xa, 0x30, 0x8, 0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 0xa3, 0x7,
            0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 0xa5, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa6, 0x11, 0x18,
            0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31, 0x32, 0x38, 0x35,
            0x33, 0x5a, 0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x37, 0x30, 0x32,
            0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa8, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e,
            0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa9, 0x23, 0x30,
            0x21, 0xa0, 0x3, 0x2, 0x1, 0x2, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x6, 0x6b, 0x72, 0x62,
            0x74, 0x67, 0x74, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53,
        ];

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef,
                0x51, 0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f, 0x70,
                0xc2, 0x78, 0x47, 0x86,
            ],
        );

        let pname = PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());

        let mut sname =
            PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut krb_cred_info = KrbCredInfo::new(encryption_key);

        krb_cred_info.set_prealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_pname(pname);
        krb_cred_info.set_flags(TicketFlags::new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT,
        ));

        krb_cred_info.set_starttime(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.set_endtime(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.set_renew_till(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.set_srealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_sname(sname);

        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::default();
        seq_of_krb_cred_info.push(krb_cred_info);

        let enc_krb_cred_part = EncKrbCredPart::new(seq_of_krb_cred_info);

        assert_eq!(
            raw,
            EncKrbCredPartAsn1::from(&enc_krb_cred_part)
                .encode()
                .unwrap()
        );
    }

    #[test]
    fn encode_enc_krb_cred_part() {
        let raw: Vec<u8> = vec![
            0x7d, 0x81, 0xd9, 0x30, 0x81, 0xd6, 0xa0, 0x81, 0xd3, 0x30, 0x81, 0xd0, 0x30, 0x81,
            0xcd, 0xa0, 0x2b, 0x30, 0x29, 0xa0, 0x3, 0x2, 0x1, 0x12, 0xa1, 0x22, 0x4, 0x20, 0x89,
            0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51,
            0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f, 0x70, 0xc2,
            0x78, 0x47, 0x86, 0xa1, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
            0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x13, 0x30, 0x11, 0xa0, 0x3, 0x2, 0x1,
            0x1, 0xa1, 0xa, 0x30, 0x8, 0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 0xa3, 0x7,
            0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 0xa5, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa6, 0x11, 0x18,
            0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31, 0x32, 0x38, 0x35,
            0x33, 0x5a, 0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x37, 0x30, 0x32,
            0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa8, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e,
            0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa9, 0x23, 0x30,
            0x21, 0xa0, 0x3, 0x2, 0x1, 0x2, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x6, 0x6b, 0x72, 0x62,
            0x74, 0x67, 0x74, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53,
        ];

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef,
                0x51, 0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f, 0x70,
                0xc2, 0x78, 0x47, 0x86,
            ],
        );

        let pname = PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());

        let mut sname =
            PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut krb_cred_info = KrbCredInfo::new(encryption_key);

        krb_cred_info.set_prealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_pname(pname);
        krb_cred_info.set_flags(TicketFlags::new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT,
        ));

        krb_cred_info.set_starttime(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.set_endtime(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.set_renew_till(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.set_srealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_sname(sname);

        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::default();
        seq_of_krb_cred_info.push(krb_cred_info);

        let enc_krb_cred_part = EncKrbCredPart::new(seq_of_krb_cred_info);

        let mut enc_krb_cred_part_asn1 = EncKrbCredPartAsn1::default();
        enc_krb_cred_part_asn1.decode(&raw).unwrap();

        assert_eq!(
            enc_krb_cred_part,
            enc_krb_cred_part_asn1.no_asn1_type().unwrap()
        );
    }
}
