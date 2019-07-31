use red_asn1::*;
use super::lastreqentry::*;
use crate::error::*;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LastReq {
    entries: Vec<LastReqEntry>
}

impl Deref for LastReq {
    type Target = Vec<LastReqEntry>;
    fn deref(&self) -> &Vec<LastReqEntry> {
        &self.entries
    }
}

impl DerefMut for LastReq {
    fn deref_mut(&mut self) -> &mut Vec<LastReqEntry> {
        &mut self.entries
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct LastReqAsn1 {
    subtype: SequenceOf<LastReqEntryAsn1>
}

impl LastReqAsn1 {

    pub fn no_asn1_type(&self) -> KerberosResult<LastReq> {
        let mut last_req = LastReq::default();
        for last_req_asn1 in self.subtype.iter() {
            last_req.push(last_req_asn1.no_asn1_type()?);
        }

        return Ok(last_req);
    }

}

impl Asn1Object for LastReqAsn1 {

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

    #[test]
    fn create_default_last_req() {
        let last_req = LastReq::default();
        assert_eq!(Vec::<LastReqEntry>::new(), last_req.entries);
    }

    #[test]
    fn test_decode_last_req() {
        let raw: Vec<u8> = vec![
            0x30, 0x1a,
            0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x00,
            0xa1, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30,
            0x33, 0x31, 0x5a
        ];

        let mut last_req_asn1 = LastReqAsn1::default();
        last_req_asn1.decode(&raw).unwrap();

        let mut last_req = LastReq::default();

        last_req.push(LastReqEntry::new(
            0,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)
        ));

        assert_eq!(last_req, last_req_asn1.no_asn1_type().unwrap());

    }

}