use asn1::*;
use std::ops::{Deref, DerefMut};
use super::etype::*;

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

    pub fn asn1_type(&self) -> SeqOfEtypeAsn1 {
        return SeqOfEtypeAsn1::new(self);
    }

}


pub struct SeqOfEtypeAsn1 {
    subtype: SequenceOf<EtypeAsn1>
}

impl SeqOfEtypeAsn1 {

    fn new(seq_of_etype: &SeqOfEtype) -> SeqOfEtypeAsn1 {
        let mut seq_etype_asn1 = Self::new_empty();

        seq_etype_asn1._set_asn1_values(seq_of_etype);
        return seq_etype_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_etype: &SeqOfEtype) {
        for etype in seq_of_etype.iter() {
            self.subtype.push(EtypeAsn1::new(*etype));
        }
    }
}

impl Asn1Object for SeqOfEtypeAsn1 {

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
        self.subtype.unset_value();
    }

}

impl Asn1Tagged for SeqOfEtypeAsn1 {
    fn type_tag() -> Tag {
        return SequenceOf::<EtypeAsn1>::type_tag();
    }
}

impl Asn1InstanciableObject for SeqOfEtypeAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::super::constants::etypes::*;

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
                        seq_etypes.asn1_type().encode().unwrap());
    }
} 
