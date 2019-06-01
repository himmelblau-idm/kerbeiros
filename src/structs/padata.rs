use asn1::*;
use asn1_derive::*;
use super::int32::{Int32, Int32Asn1};
use super::kerbpapacrequest::KerbPaPacRequest;
use std::ops::{Deref, DerefMut};

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

    pub fn new() -> SeqOfPaData {
        return SeqOfPaData{
            padatas: Vec::new()
        };
    }

    pub fn asn1_type(&self) -> SeqOfPaDataAsn1 {
        return SeqOfPaDataAsn1::new(self);
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


pub enum PaData {
    PaPacRequest(KerbPaPacRequest)
}

impl PaData {

    fn into_int32(&self) -> Int32 {
        match self {
            PaData::PaPacRequest(_) => Int32::new(128)
        }
    } 

    fn bytes_value(&self) -> Vec<u8> {
        match self {
            PaData::PaPacRequest(pac_request) => pac_request.asn1().encode().unwrap()
        }
    }

    fn asn1_type(&self) -> PaDataAsn1 {
        return PaDataAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
pub struct PaDataAsn1 {
    #[seq_comp(context_tag = 1)]
    padata_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 2)]
    padata_value: SeqField<OctetString>
}

impl PaDataAsn1 {

    fn new(pa_data: &PaData) -> PaDataAsn1 {
        let mut pa_data_asn1 = Self::new_empty();
        pa_data_asn1._set_asn1_values(pa_data);
        return pa_data_asn1;
    }

    fn new_empty() -> PaDataAsn1 {
        let pa_data_asn1 = PaDataAsn1 {
            padata_type: SeqField::new(),
            padata_value: SeqField::new(),
        };
        return pa_data_asn1;
    }

    fn _set_asn1_values(&mut self, pa_data: &PaData) {
        self.set_padata_type(pa_data.into_int32().asn1_type());
        self.set_padata_value(OctetString::new(pa_data.bytes_value()));
    }

}

impl Asn1InstanciableObject for PaDataAsn1 {

    fn new_default() -> PaDataAsn1 {
        return PaDataAsn1::new_empty();
    }
}

impl<'a> Asn1Tagged for PaDataAsn1 {
    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_padata_pac_request(){
        assert_eq!(vec![0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                        PaData::PaPacRequest(KerbPaPacRequest::new(true)).asn1_type().encode().unwrap()
        );
        assert_eq!(vec![0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00],
                        PaData::PaPacRequest(KerbPaPacRequest::new(false)).asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_encode_seq_of_padatas(){
        let mut seq_of_padatas = SeqOfPaData::new();
        seq_of_padatas.push(PaData::PaPacRequest(KerbPaPacRequest::new(true)));

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

}