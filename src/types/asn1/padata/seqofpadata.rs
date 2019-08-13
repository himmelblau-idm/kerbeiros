use red_asn1::*;
use std::ops::{Deref, DerefMut};
use super::padata::*;
use crate::error::Result;

pub type MethodData = SeqOfPaData;
pub type MethodDataAsn1 = SeqOfPaDataAsn1;

#[derive(Debug, Clone, PartialEq, Default)]
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

    pub(crate) fn asn1_type(&self) -> SeqOfPaDataAsn1 {
        return SeqOfPaDataAsn1::new(self);
    }

    pub fn parse(raw: &Vec<u8>) -> Result<Self> {
        let mut seq_of_padata_asn1 = SeqOfPaDataAsn1::default();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}

#[derive(Default, Debug, PartialEq)]
pub struct SeqOfPaDataAsn1 {
    subtype: SequenceOf<PaDataAsn1>
}

impl SeqOfPaDataAsn1 {

    fn new(seq_of_padatas: &SeqOfPaData) -> Self {
        let mut seq_padatas_asn1 = Self::default();

        seq_padatas_asn1.set_asn1_values(seq_of_padatas);
        return seq_padatas_asn1;
    }

    fn set_asn1_values(&mut self, seq_of_padatas: &SeqOfPaData) {
        for padata in seq_of_padatas.iter() {
            self.subtype.push(padata.asn1_type());
        }
    }

    pub fn no_asn1_type(&self) -> Result<SeqOfPaData> {
        let mut seq_of_padata = SeqOfPaData::default();
        for padata_asn1 in self.subtype.iter() {
            seq_of_padata.push(padata_asn1.no_asn1_type()?);
        }

        return Ok(seq_of_padata);
    }
}

impl Asn1Object for SeqOfPaDataAsn1 {

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
    use super::super::pacrequest::PacRequest;

    #[test]
    fn create_default_seq_of_padatas_asn1() {
        assert_eq!(
            SeqOfPaDataAsn1{
                subtype: SequenceOf::default()
            },
            SeqOfPaDataAsn1::default()
        )
    }

    #[test]
    fn create_default_seq_of_padatas() {
        let seq_of_padatas = SeqOfPaData::default();
        assert_eq!(Vec::<PaData>::new(), seq_of_padatas.padatas);
    }

    #[test]
    fn test_encode_seq_of_padatas(){
        let mut seq_of_padatas = SeqOfPaData::default();
        seq_of_padatas.push(PaData::PacRequest(PacRequest::new(true)));

        assert_eq!(vec![0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                        seq_of_padatas.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_encode_empty_seq_of_padatas(){
        let seq_of_padatas = SeqOfPaData::default();

        assert_eq!(vec![0x30, 0x0],
                        seq_of_padatas.asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_seq_of_padatas(){

        let mut seq_of_padatas_asn1 = SeqOfPaDataAsn1::default();

        seq_of_padatas_asn1.decode(&[0x30, 0x13, 0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]).unwrap();

        let mut seq_of_padatas = SeqOfPaData::default();
        seq_of_padatas.push(PaData::PacRequest(PacRequest::new(true)));

        assert_eq!(seq_of_padatas, seq_of_padatas_asn1.no_asn1_type().unwrap());
    }

}