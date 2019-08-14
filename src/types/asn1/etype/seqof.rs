use red_asn1::*;
use std::ops::{Deref, DerefMut};
use super::etype::*;

#[derive(Debug, PartialEq, Clone)]
pub struct SeqOfEtype {
    etypes: Vec<Etype>
}

impl Deref for SeqOfEtype {
    type Target = Vec<Etype>;
    fn deref(&self) -> &Vec<Etype> {
        &self.etypes
    }
}

impl DerefMut for SeqOfEtype {
    fn deref_mut(&mut self) -> &mut Vec<Etype> {
        &mut self.etypes
    }
}

impl SeqOfEtype {

    pub fn new() -> SeqOfEtype {
        return SeqOfEtype{
            etypes: Vec::new()
        };
    }

}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct SeqOfEtypeAsn1 {
    subtype: SequenceOf<EtypeAsn1>
}

impl SeqOfEtypeAsn1 {

    fn set_asn1_values(&mut self, seq_of_etype: &SeqOfEtype) {
        for etype in seq_of_etype.iter() {
            self.subtype.push((*etype).into());
        }
    }
}

impl From<&SeqOfEtype> for SeqOfEtypeAsn1 {
    fn from(seq_of_etype: &SeqOfEtype) -> SeqOfEtypeAsn1 {
        let mut seq_etype_asn1 = Self::default();

        seq_etype_asn1.set_asn1_values(seq_of_etype);
        return seq_etype_asn1;
    }
}

impl Asn1Object for SeqOfEtypeAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }
    
    fn decode_value(&mut self, raw: &[u8]) -> Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        self.subtype.unset_value();
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::etypes::*;

    #[test]
    fn create_default_sequence_of_etypes_asn1() {
        assert_eq!(
            SeqOfEtypeAsn1 {
                subtype: SequenceOf::default()
            },
            SeqOfEtypeAsn1::default()
        )
    }

    #[test]
    fn test_encode_sequence_of_etypes() {
        let mut seq_etypes = SeqOfEtype::new();

        seq_etypes.push(AES256_CTS_HMAC_SHA1_96);
        seq_etypes.push(AES128_CTS_HMAC_SHA1_96);
        seq_etypes.push(RC4_HMAC);
        seq_etypes.push(RC4_HMAC_EXP);
        seq_etypes.push(DES_CBC_MD5);
        seq_etypes.push(DES_CBC_CRC);
        seq_etypes.push(RC4_HMAC_OLD_EXP);

        assert_eq!(vec![0x30, 0x16, 
                        0x02, 0x01, 0x12, 
                        0x02, 0x01, 0x11, 
                        0x02, 0x01, 0x17, 
                        0x02, 0x01, 0x18,
                        0x02, 0x01, 0x03,
                        0x02, 0x01, 0x01,
                        0x02, 0x02, 0xff, 0x79,],
                        SeqOfEtypeAsn1::from(&seq_etypes).encode().unwrap());
    }
} 
