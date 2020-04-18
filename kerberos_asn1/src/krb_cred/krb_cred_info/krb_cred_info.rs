use super::super::super::basics::*;
use super::super::super::ticket::ticket_flags::*;
use red_asn1::*;

#[cfg(test)]
use crate::error::{ErrorKind, Result};

/// (*KrbCredInfo*) Gives information about user and client for a [EncKrbCredPart](./struct.EncKrbCredPart.html).
#[derive(Debug, PartialEq, Clone)]
pub struct KrbCredInfo {
    pub key: EncryptionKey,
    pub prealm: Option<Realm>,
    pub pname: Option<PrincipalName>,
    pub flags: Option<TicketFlags>,
    pub authtime: Option<KerberosTime>,
    pub starttime: Option<KerberosTime>,
    pub endtime: Option<KerberosTime>,
    pub renew_till: Option<KerberosTime>,
    pub srealm: Option<Realm>,
    pub sname: Option<PrincipalName>,
    pub caddr: Option<HostAddresses>,
}

impl KrbCredInfo {
    pub fn new(key: EncryptionKey) -> Self {
        return Self {
            key,
            prealm: None,
            pname: None,
            flags: None,
            authtime: None,
            starttime: None,
            endtime: None,
            renew_till: None,
            srealm: None,
            sname: None,
            caddr: None,
        };
    }

}

#[derive(Sequence, Default, Debug, PartialEq)]
pub(crate) struct KrbCredInfoAsn1 {
    #[seq_field(context_tag = 0)]
    key: SeqField<EncryptionKeyAsn1>,

    #[seq_field(context_tag = 1, optional)]
    prealm: SeqField<RealmAsn1>,

    #[seq_field(context_tag = 2, optional)]
    pname: SeqField<PrincipalNameAsn1>,

    #[seq_field(context_tag = 3, optional)]
    flags: SeqField<TicketFlagsAsn1>,

    #[seq_field(context_tag = 4, optional)]
    authtime: SeqField<KerberosTimeAsn1>,

    #[seq_field(context_tag = 5, optional)]
    starttime: SeqField<KerberosTimeAsn1>,

    #[seq_field(context_tag = 6, optional)]
    endtime: SeqField<KerberosTimeAsn1>,

    #[seq_field(context_tag = 7, optional)]
    renew_till: SeqField<KerberosTimeAsn1>,

    #[seq_field(context_tag = 8, optional)]
    srealm: SeqField<RealmAsn1>,

    #[seq_field(context_tag = 9, optional)]
    sname: SeqField<PrincipalNameAsn1>,

    #[seq_field(context_tag = 10, optional)]
    caddr: SeqField<HostAddressesAsn1>,
}

impl KrbCredInfoAsn1 {
    #[cfg(test)]
    pub fn no_asn1_type(&self) -> Result<KrbCredInfo> {
        let key = self
            .get_key()
            .ok_or_else(|| ErrorKind::NotAvailableData("KrbCredInfo::key".to_string()))?;

        let mut krb_cred_info = KrbCredInfo::new(key.no_asn1_type()?);

        if let Some(prealm) = self.get_prealm() {
            krb_cred_info.prealm = Some(prealm.no_asn1_type()?);
        }

        if let Some(pname) = self.get_pname() {
            krb_cred_info.pname = Some(pname.no_asn1_type()?);
        }

        if let Some(flags) = self.get_flags() {
            krb_cred_info.flags = Some(flags.no_asn1_type()?);
        }

        if let Some(authtime) = self.get_authtime() {
            krb_cred_info.authtime = Some(authtime.no_asn1_type()?);
        }

        if let Some(starttime) = self.get_starttime() {
            krb_cred_info.starttime = Some(starttime.no_asn1_type()?);
        }

        if let Some(endtime) = self.get_endtime() {
            krb_cred_info.endtime = Some(endtime.no_asn1_type()?);
        }

        if let Some(renew_till) = self.get_renew_till() {
            krb_cred_info.renew_till = Some(renew_till.no_asn1_type()?);
        }

        if let Some(srealm) = self.get_srealm() {
            krb_cred_info.srealm = Some(srealm.no_asn1_type()?);
        }

        if let Some(sname) = self.get_sname() {
            krb_cred_info.sname = Some(sname.no_asn1_type()?);
        }

        if let Some(caddr) = self.get_caddr() {
            krb_cred_info.caddr = Some(caddr.no_asn1_type()?);
        }

        return Ok(krb_cred_info);
    }
}

impl From<KrbCredInfo> for KrbCredInfoAsn1 {
    fn from(krb_cred_info: KrbCredInfo) -> Self {
        let mut krb_cred_info_asn1 = Self::default();

        krb_cred_info_asn1.set_key(krb_cred_info.key.into());

        if let Some(prealm) = krb_cred_info.prealm {
            krb_cred_info_asn1.set_prealm(prealm.into());
        }

        if let Some(pname) = krb_cred_info.pname {
            krb_cred_info_asn1.set_pname(pname.into());
        }

        if let Some(flags) = krb_cred_info.flags {
            krb_cred_info_asn1.set_flags((&flags).into());
        }

        if let Some(authtime) = krb_cred_info.authtime {
            krb_cred_info_asn1.set_authtime(authtime.into());
        }

        if let Some(starttime) = krb_cred_info.starttime {
            krb_cred_info_asn1.set_starttime(starttime.into());
        }

        if let Some(endtime) = krb_cred_info.endtime {
            krb_cred_info_asn1.set_endtime(endtime.into());
        }

        if let Some(renew_till) = krb_cred_info.renew_till {
            krb_cred_info_asn1.set_renew_till(renew_till.into());
        }

        if let Some(srealm) = krb_cred_info.srealm {
            krb_cred_info_asn1.set_srealm(srealm.into());
        }
        if let Some(sname) = krb_cred_info.sname {
            krb_cred_info_asn1.set_sname(sname.into());
        }
        if let Some(caddr) = krb_cred_info.caddr {
            krb_cred_info_asn1.set_caddr((&caddr).into());
        }

        return krb_cred_info_asn1;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;
    use chrono::prelude::*;

    #[test]
    fn create_default_kdc_cred_info_asn1() {
        assert_eq!(
            KrbCredInfoAsn1 {
                key: SeqField::default(),
                prealm: SeqField::default(),
                pname: SeqField::default(),
                flags: SeqField::default(),
                authtime: SeqField::default(),
                starttime: SeqField::default(),
                endtime: SeqField::default(),
                renew_till: SeqField::default(),
                srealm: SeqField::default(),
                sname: SeqField::default(),
                caddr: SeqField::default(),
            },
            KrbCredInfoAsn1::default()
        )
    }

    #[test]
    fn test_krb_cred_info_decode() {
        let raw: Vec<u8> = vec![
            0x30, 0x81, 0xcd, 0xa0, 0x2b, 0x30, 0x29, 0xa0, 0x3, 0x2, 0x1, 0x12, 0xa1, 0x22, 0x4,
            0x20, 0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f,
            0xef, 0x51, 0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f,
            0x70, 0xc2, 0x78, 0x47, 0x86, 0xa1, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44,
            0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x13, 0x30, 0x11, 0xa0,
            0x3, 0x2, 0x1, 0x1, 0xa1, 0xa, 0x30, 0x8, 0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65,
            0x79, 0xa3, 0x7, 0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 0xa5, 0x11, 0x18, 0xf, 0x32,
            0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a,
            0xa6, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31,
            0x32, 0x38, 0x35, 0x33, 0x5a, 0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30,
            0x37, 0x30, 0x32, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa8, 0x10, 0x1b, 0xe,
            0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            0xa9, 0x23, 0x30, 0x21, 0xa0, 0x3, 0x2, 0x1, 0x2, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x6,
            0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
            0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
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

        krb_cred_info.prealm = Some(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.pname = Some(pname);
        krb_cred_info.flags = Some(TicketFlags::new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT,
        ));

        krb_cred_info.starttime = Some(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.endtime = Some(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.renew_till = Some(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.srealm = Some(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.sname = Some(sname);

        assert_eq!(raw, KrbCredInfoAsn1::from(krb_cred_info).encode().unwrap());
    }

    #[test]
    fn test_krb_cred_info_encode() {
        let raw: Vec<u8> = vec![
            0x30, 0x81, 0xcd, 0xa0, 0x2b, 0x30, 0x29, 0xa0, 0x3, 0x2, 0x1, 0x12, 0xa1, 0x22, 0x4,
            0x20, 0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 0x4e, 0x51, 0x1e, 0xe1, 0x8f,
            0xef, 0x51, 0xc4, 0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 0x85, 0x72, 0x5f,
            0x70, 0xc2, 0x78, 0x47, 0x86, 0xa1, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44,
            0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x13, 0x30, 0x11, 0xa0,
            0x3, 0x2, 0x1, 0x1, 0xa1, 0xa, 0x30, 0x8, 0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65,
            0x79, 0xa3, 0x7, 0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 0xa5, 0x11, 0x18, 0xf, 0x32,
            0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a,
            0xa6, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31,
            0x32, 0x38, 0x35, 0x33, 0x5a, 0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30,
            0x37, 0x30, 0x32, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 0xa8, 0x10, 0x1b, 0xe,
            0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            0xa9, 0x23, 0x30, 0x21, 0xa0, 0x3, 0x2, 0x1, 0x2, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x6,
            0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
            0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
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

        krb_cred_info.prealm = Some(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.pname = Some(pname);
        krb_cred_info.flags = Some(TicketFlags::new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT,
        ));

        krb_cred_info.starttime = Some(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.endtime = Some(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.renew_till = Some(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.srealm  = Some(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.sname = Some(sname);

        let mut krb_cred_info_asn1 = KrbCredInfoAsn1::default();
        krb_cred_info_asn1.decode(&raw).unwrap();

        assert_eq!(krb_cred_info, krb_cred_info_asn1.no_asn1_type().unwrap());
    }
}
