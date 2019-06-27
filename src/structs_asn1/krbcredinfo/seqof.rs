use asn1::*;
use std::ops::{Deref, DerefMut};
use super::krbcredinfo::*;
use crate::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct SeqOfKrbCredInfo {
    entries: Vec<KrbCredInfo>
}

impl Deref for SeqOfKrbCredInfo {
    type Target = Vec<KrbCredInfo>;
    fn deref(&self) -> &Vec<KrbCredInfo> {
        &self.entries
    }
}

impl DerefMut for SeqOfKrbCredInfo {
    fn deref_mut(&mut self) -> &mut Vec<KrbCredInfo> {
        &mut self.entries
    }
}

impl SeqOfKrbCredInfo {

    pub fn new() -> Self {
        return Self::new_empty();
    }

    fn new_empty() -> Self {
        return Self{ entries: Vec::new() };
    }

    pub fn asn1_type(&self) -> SeqOfKrbCredInfoAsn1 {
        return SeqOfKrbCredInfoAsn1::new(self);
    }

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<Self> {
        let mut seq_of_krb_cred_info_asn1 = SeqOfKrbCredInfoAsn1::new_empty();
        seq_of_krb_cred_info_asn1.decode(raw)?;
        return Ok(seq_of_krb_cred_info_asn1.no_asn1_type().unwrap());
    }

}


pub struct SeqOfKrbCredInfoAsn1 {
    subtype: SequenceOf<KrbCredInfoAsn1>
}

impl SeqOfKrbCredInfoAsn1 {

    fn new(seq_of_krb_cred_info: &SeqOfKrbCredInfo) -> Self {
        let mut seq_of_krb_cred_info_asn1 = Self::new_empty();
        seq_of_krb_cred_info_asn1._set_asn1_values(seq_of_krb_cred_info);
        return seq_of_krb_cred_info_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_krb_cred_info: &SeqOfKrbCredInfo) {
        for krb_cred_info in seq_of_krb_cred_info.iter() {
            self.subtype.push(krb_cred_info.asn1_type());
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<SeqOfKrbCredInfo> {
        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::new_empty();
        for seq_of_krb_cred_info_asn1 in self.subtype.iter() {
            seq_of_krb_cred_info.push(seq_of_krb_cred_info_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_krb_cred_info);
    }
}

impl Asn1Object for SeqOfKrbCredInfoAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>, Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}


impl Asn1Tagged for SeqOfKrbCredInfoAsn1 {
    fn type_tag() -> Tag {
        return SequenceOf::<KrbCredInfoAsn1>::type_tag();
    }
}

impl Asn1InstanciableObject for SeqOfKrbCredInfoAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_encode_seq_of_krb_cred_info() {
        let raw: Vec<u8> = vec![
            0x30, 0x81, 0xd0,
            0x30, 0x81, 0xcd, 
                0xa0, 0x2b, 0x30, 0x29, 
                    0xa0, 0x3, 0x2, 0x1, 0x12, 
                    0xa1, 0x22, 0x4, 0x20, 
                        0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 
                        0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 
                        0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 
                        0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78, 0x47, 0x86, 
                0xa1, 0x10, 0x1b, 0xe, 
                    0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                    0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                0xa2, 0x13, 0x30, 0x11, 
                    0xa0, 0x3, 0x2, 0x1, 0x1, 
                    0xa1, 0xa, 0x30, 0x8, 
                        0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79,
                0xa3, 0x7, 0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 
                0xa5, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa6, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x37, 0x30, 0x32, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa8, 0x10, 0x1b, 0xe, 
                    0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                    0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                0xa9, 0x23, 0x30, 0x21, 
                    0xa0, 0x3, 0x2, 0x1, 0x2, 
                    0xa1, 0x1a, 0x30, 0x18, 
                        0x1b, 0x6, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                        0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
        ];


        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 
                0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 
                0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 
                0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78, 0x47, 0x86
            ]
        );

        let pname = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("mickey").unwrap()
        );

        let mut sname = PrincipalName::new(
            NT_SRV_INST, 
            KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        

        let mut krb_cred_info = KrbCredInfo::new(encryption_key);

        krb_cred_info.set_prealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_pname(pname);
        krb_cred_info.set_flags(TicketFlags::_new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT
        ));

        krb_cred_info.set_starttime(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.set_endtime(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.set_renew_till(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.set_srealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_sname(sname);


        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::new_empty();
        seq_of_krb_cred_info.push(krb_cred_info);

        assert_eq!(raw, seq_of_krb_cred_info.asn1_type().encode().unwrap());
    }


    #[test]
    fn test_decode_seq_of_entries(){
        let raw: Vec<u8> = vec![
            0x30, 0x81, 0xd0,
            0x30, 0x81, 0xcd, 
                0xa0, 0x2b, 0x30, 0x29, 
                    0xa0, 0x3, 0x2, 0x1, 0x12, 
                    0xa1, 0x22, 0x4, 0x20, 
                        0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 
                        0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 
                        0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 
                        0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78, 0x47, 0x86, 
                0xa1, 0x10, 0x1b, 0xe, 
                    0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                    0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                0xa2, 0x13, 0x30, 0x11, 
                    0xa0, 0x3, 0x2, 0x1, 0x1, 
                    0xa1, 0xa, 0x30, 0x8, 
                        0x1b, 0x6, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79,
                0xa3, 0x7, 0x3, 0x5, 0x0, 0x40, 0xe0, 0x0, 0x0, 
                0xa5, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x35, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa6, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 0x32, 0x36, 0x30, 0x31, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa7, 0x11, 0x18, 0xf, 0x32, 0x30, 0x31, 0x39, 0x30, 0x37, 0x30, 0x32, 0x31, 0x35, 0x32, 0x38, 0x35, 0x33, 0x5a, 
                0xa8, 0x10, 0x1b, 0xe, 
                    0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 
                    0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                0xa9, 0x23, 0x30, 0x21, 
                    0xa0, 0x3, 0x2, 0x1, 0x2, 
                    0xa1, 0x1a, 0x30, 0x18, 
                        0x1b, 0x6, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                        0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
        ];


        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 
                0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 
                0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 
                0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78, 0x47, 0x86
            ]
        );

        let pname = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("mickey").unwrap()
        );

        let mut sname = PrincipalName::new(
            NT_SRV_INST, 
            KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        

        let mut krb_cred_info = KrbCredInfo::new(encryption_key);

        krb_cred_info.set_prealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_pname(pname);
        krb_cred_info.set_flags(TicketFlags::_new(
            FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT
        ));

        krb_cred_info.set_starttime(Utc.ymd(2019, 6, 25).and_hms(15, 28, 53));
        krb_cred_info.set_endtime(Utc.ymd(2019, 6, 26).and_hms(1, 28, 53));
        krb_cred_info.set_renew_till(Utc.ymd(2019, 7, 2).and_hms(15, 28, 53));
        krb_cred_info.set_srealm(Realm::from_ascii("KINGDOM.HEARTS").unwrap());
        krb_cred_info.set_sname(sname);


        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::new_empty();
        seq_of_krb_cred_info.push(krb_cred_info);

        let mut seq_of_krb_cred_info_asn1 = SeqOfKrbCredInfoAsn1::new_empty();
        seq_of_krb_cred_info_asn1.decode(&raw).unwrap();


        assert_eq!(seq_of_krb_cred_info, seq_of_krb_cred_info_asn1.no_asn1_type().unwrap());
    }

}