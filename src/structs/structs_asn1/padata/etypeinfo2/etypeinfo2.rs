use red_asn1::*;
use std::ops::{Deref, DerefMut};
use crate::error::*;
use super::entry::*;


#[derive(Debug, Clone, PartialEq)]
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

    pub fn _new() -> Self {
        return Self::new_empty();
    }

    fn new_empty() -> Self {
        return Self{ entries: Vec::new() };
    }

    pub fn asn1_type(&self) -> EtypeInfo2Asn1 {
        return EtypeInfo2Asn1::new(self);
    }

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<Self> {
        let mut seq_of_padata_asn1 = EtypeInfo2Asn1::new_empty();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}


pub struct EtypeInfo2Asn1 {
    subtype: SequenceOf<EtypeInfo2EntryAsn1>
}

impl EtypeInfo2Asn1 {

    fn new(seq_of_padatas: &EtypeInfo2) -> Self {
        let mut seq_padatas_asn1 = Self::new_empty();

        seq_padatas_asn1._set_asn1_values(seq_of_padatas);
        return seq_padatas_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_padatas: &EtypeInfo2) {
        for padata in seq_of_padatas.iter() {
            self.subtype.push(padata.asn1_type());
        }
    }

    fn no_asn1_type(&self) -> KerberosResult<EtypeInfo2> {
        let mut seq_of_padata = EtypeInfo2::new_empty();
        for padata_asn1 in self.subtype.iter() {
            seq_of_padata.entries.push(padata_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_padata);
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

impl Asn1InstanciableObject for EtypeInfo2Asn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::super::kerberosstring::*;
    use crate::constants::etypes::*;

    #[test]
    fn decode_etypeinfo2() {
        let mut info2_asn1 = EtypeInfo2Asn1::new_empty();

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

        let mut entry1 = EtypeInfo2Entry::_new(AES256_CTS_HMAC_SHA1_96);
        entry1._set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let entry2 = EtypeInfo2Entry::_new(RC4_HMAC);

        let mut entry3 = EtypeInfo2Entry::_new(DES_CBC_MD5);
        entry3._set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::new_empty();

        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);
        
        assert_eq!(info2, info2_asn1.no_asn1_type().unwrap());

    }

}