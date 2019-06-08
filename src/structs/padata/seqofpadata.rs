use asn1::*;
use std::ops::{Deref, DerefMut};
use super::padata::*;
use super::super::super::error::*;

pub type MethodData = SeqOfPaData;

#[derive(Debug, Clone, PartialEq)]
pub struct SeqOfPaData {
    padatas: Vec<PaData>
}

impl Deref for SeqOfPaData {
    type Target = Vec<PaData>;
    fn deref(&self) -> &Vec<PaData> {
        &self.padatas
    }
}

impl DerefMut for SeqOfPaData {
    fn deref_mut(&mut self) -> &mut Vec<PaData> {
        &mut self.padatas
    }
}

impl SeqOfPaData {

    pub fn new() -> Self {
        return Self::new_empty();
    }

    fn new_empty() -> Self {
        return Self{ padatas: Vec::new() };
    }

    pub fn asn1_type(&self) -> SeqOfPaDataAsn1 {
        return SeqOfPaDataAsn1::new(self);
    }

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<Self> {
        let mut seq_of_padata_asn1 = SeqOfPaDataAsn1::new_empty();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}


pub struct SeqOfPaDataAsn1 {
    subtype: SequenceOf<PaDataAsn1>
}

impl SeqOfPaDataAsn1 {

    fn new(seq_of_padatas: &SeqOfPaData) -> Self {
        let mut seq_padatas_asn1 = Self::new_empty();

        seq_padatas_asn1._set_asn1_values(seq_of_padatas);
        return seq_padatas_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_padatas: &SeqOfPaData) {
        for padata in seq_of_padatas.iter() {
            self.subtype.push(padata.asn1_type());
        }
    }

    fn no_asn1_type(&self) -> KerberosResult<SeqOfPaData> {
        let mut seq_of_padata = SeqOfPaData::new_empty();
        for padata_asn1 in self.subtype.iter() {
            seq_of_padata.padatas.push(padata_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_padata);
    }
}

impl Asn1Object for SeqOfPaDataAsn1 {

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


impl Asn1Tagged for SeqOfPaDataAsn1 {
    fn type_tag() -> Tag {
        return SequenceOf::<PaDataAsn1>::type_tag();
    }
}

impl Asn1InstanciableObject for SeqOfPaDataAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use super::super::pacrequest::PacRequest;

    #[test]
    fn test_encode_seq_of_padatas(){
        let mut seq_of_padatas = SeqOfPaData::new();
        seq_of_padatas.push(PaData::PacRequest(PacRequest::new(true)));

        assert_eq!(vec![0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                        seq_of_padatas.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_encode_empty_seq_of_padatas(){
        let seq_of_padatas = SeqOfPaData::new();

        assert_eq!(vec![0x30, 0x0],
                        seq_of_padatas.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_seq_of_padatas(){

        let mut seq_of_padatas_asn1 = SeqOfPaDataAsn1::new_empty();

        seq_of_padatas_asn1.decode(&[0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]).unwrap();

        let mut seq_of_padatas = SeqOfPaData::new();
        seq_of_padatas.push(PaData::PacRequest(PacRequest::new(true)));

        assert_eq!(seq_of_padatas, seq_of_padatas_asn1.no_asn1_type().unwrap());
    }

}