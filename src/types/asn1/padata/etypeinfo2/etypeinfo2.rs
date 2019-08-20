use red_asn1::*;
use std::ops::{Deref, DerefMut};
use crate::error::Result;
use super::entry::*;

/// (*ETYPE-INFO2*) Array of [EtypeInfo2Entry](./struct.EtypeInfo2Entry.html) that indicates the available encryption algorithms.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EtypeInfo2 {
    entries: Vec<EtypeInfo2Entry>
}

impl Deref for EtypeInfo2 {
    type Target = Vec<EtypeInfo2Entry>;
    fn deref(&self) -> &Vec<EtypeInfo2Entry> {
        &self.entries
    }
}

impl DerefMut for EtypeInfo2 {
    fn deref_mut(&mut self) -> &mut Vec<EtypeInfo2Entry> {
        &mut self.entries
    }
}

impl EtypeInfo2 {

    pub fn parse(raw: &Vec<u8>) -> Result<Self> {
        let mut seq_of_padata_asn1 = EtypeInfo2Asn1::default();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}


pub(crate) struct EtypeInfo2Asn1 {
    subtype: SequenceOf<EtypeInfo2EntryAsn1>
}

impl EtypeInfo2Asn1 {

    fn default() -> Self {
        return Self{
            subtype: SequenceOf::default()
        };
    }

    fn set_asn1_values(&mut self, seq_of_padatas: &EtypeInfo2) {
        for padata in seq_of_padatas.iter() {
            self.subtype.push(padata.into());
        }
    }

    fn no_asn1_type(&self) -> Result<EtypeInfo2> {
        let mut seq_of_padata = EtypeInfo2::default();
        for padata_asn1 in self.subtype.iter() {
            seq_of_padata.entries.push(padata_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_padata);
    }
}

impl From<&EtypeInfo2> for EtypeInfo2Asn1 {
    fn from(seq_of_padatas: &EtypeInfo2) -> Self {
        let mut seq_padatas_asn1 = Self::default();

        seq_padatas_asn1.set_asn1_values(seq_of_padatas);
        return seq_padatas_asn1;
    }
}

impl Asn1Object for EtypeInfo2Asn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::super::basics::kerberos_string::*;
    use crate::constants::etypes::*;

    #[test]
    fn test_create_default_etypeinfo2() {
        assert_eq!(
            EtypeInfo2 { entries: Vec::new() },
            EtypeInfo2::default()
        )
    }

    #[test]
    fn decode_etypeinfo2() {
        let mut info2_asn1 = EtypeInfo2Asn1::default();

        info2_asn1.decode(&[0x30, 0x45, 0x30, 0x1d, 
                    0xa0, 0x03, 0x02, 0x01, 0x12, 
                    0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 
                        0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 
                        0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                0x30, 0x05, 
                    0xa0, 0x03, 0x02, 0x01, 0x17, 
                0x30, 0x1d, 
                    0xa0, 0x03, 0x02, 0x01, 0x03, 
                    0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 
                        0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 
                        0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79]).unwrap();

        let mut entry1 = EtypeInfo2Entry::new(AES256_CTS_HMAC_SHA1_96);
        entry1.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let entry2 = EtypeInfo2Entry::new(RC4_HMAC);

        let mut entry3 = EtypeInfo2Entry::new(DES_CBC_MD5);
        entry3.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::default();

        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);
        
        assert_eq!(info2, info2_asn1.no_asn1_type().unwrap());

    }

}