use super::super::int32::*;
use red_asn1::*;
use std::ops::{Deref, DerefMut};

/// (*SEQUENCE OF Int32*)Array of [Int32](./type.Int32.html).
#[derive(Debug, PartialEq, Clone)]
pub struct SeqOfInt32 {
    etypes: Vec<Int32>,
}

impl Deref for SeqOfInt32 {
    type Target = Vec<Int32>;
    fn deref(&self) -> &Vec<Int32> {
        &self.etypes
    }
}

impl DerefMut for SeqOfInt32 {
    fn deref_mut(&mut self) -> &mut Vec<Int32> {
        &mut self.etypes
    }
}

impl SeqOfInt32 {
    pub fn new() -> SeqOfInt32 {
        return SeqOfInt32 { etypes: Vec::new() };
    }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct SeqOfInt32Asn1 {
    subtype: SequenceOf<Int32Asn1>,
}

impl SeqOfInt32Asn1 {
    fn set_asn1_values(&mut self, seq_of_etype: &SeqOfInt32) {
        for etype in seq_of_etype.iter() {
            self.subtype.push((*etype).into());
        }
    }
}

impl From<&SeqOfInt32> for SeqOfInt32Asn1 {
    fn from(seq_of_etype: &SeqOfInt32) -> SeqOfInt32Asn1 {
        let mut seq_etype_asn1 = Self::default();

        seq_etype_asn1.set_asn1_values(seq_of_etype);
        return seq_etype_asn1;
    }
}

impl Asn1Object for SeqOfInt32Asn1 {
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
    use kerberos_constants::etypes::*;

    #[test]
    fn create_default_sequence_of_int32_asn1() {
        assert_eq!(
            SeqOfInt32Asn1 {
                subtype: SequenceOf::default()
            },
            SeqOfInt32Asn1::default()
        )
    }

    #[test]
    fn test_encode_sequence_of_int32() {
        let mut seq_etypes = SeqOfInt32::new();

        seq_etypes.push(AES256_CTS_HMAC_SHA1_96);
        seq_etypes.push(AES128_CTS_HMAC_SHA1_96);
        seq_etypes.push(RC4_HMAC);
        seq_etypes.push(RC4_HMAC_EXP);
        seq_etypes.push(DES_CBC_MD5);
        seq_etypes.push(DES_CBC_CRC);
        seq_etypes.push(RC4_HMAC_OLD_EXP);

        assert_eq!(
            vec![
                0x30, 0x16, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18,
                0x02, 0x01, 0x03, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0x79,
            ],
            SeqOfInt32Asn1::from(&seq_etypes).encode().unwrap()
        );
    }
}
