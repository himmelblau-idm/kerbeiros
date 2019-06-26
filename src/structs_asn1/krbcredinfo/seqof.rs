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
        let mut seq_of_padata_asn1 = SeqOfKrbCredInfoAsn1::new_empty();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}


pub struct SeqOfKrbCredInfoAsn1 {
    subtype: SequenceOf<KrbCredInfoAsn1>
}

impl SeqOfKrbCredInfoAsn1 {

    fn new(seq_of_entries: &SeqOfKrbCredInfo) -> Self {
        let mut seq_entries_asn1 = Self::new_empty();

        seq_entries_asn1._set_asn1_values(seq_of_entries);
        return seq_entries_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_entries: &SeqOfKrbCredInfo) {
        for padata in seq_of_entries.iter() {
            self.subtype.push(padata.asn1_type());
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<SeqOfKrbCredInfo> {
        let mut seq_of_padata = SeqOfKrbCredInfo::new_empty();
        for padata_asn1 in self.subtype.iter() {
            seq_of_padata.push(padata_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_padata);
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
    use super::super::pacrequest::PacRequest;

    #[test]
    fn test_encode_seq_of_entries(){
        let mut seq_of_entries = SeqOfKrbCredInfo::new();
        seq_of_entries.push(KrbCredInfo::PacRequest(PacRequest::new(true)));

        assert_eq!(vec![0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                        seq_of_entries.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_encode_empty_seq_of_entries(){
        let seq_of_entries = SeqOfKrbCredInfo::new();

        assert_eq!(vec![0x30, 0x0],
                        seq_of_entries.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_seq_of_entries(){

        let mut seq_of_entries_asn1 = SeqOfKrbCredInfoAsn1::new_empty();

        seq_of_entries_asn1.decode(&[0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]).unwrap();

        let mut seq_of_entries = SeqOfKrbCredInfo::new();
        seq_of_entries.push(KrbCredInfo::PacRequest(PacRequest::new(true)));

        assert_eq!(seq_of_entries, seq_of_entries_asn1.no_asn1_type().unwrap());
    }

}