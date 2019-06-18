use asn1::*;
use asn1_derive::*;
use super::int32::*;
use super::kerberostime::*;
use super::super::error::*;
use std::ops::{Deref, DerefMut};


#[derive(Debug, Clone, PartialEq)]
struct LastReq {
    entries: Vec<LastReqEntry>
}

impl LastReq {

    fn new_empty() -> Self {
        return Self{ entries: Vec::new() };
    }
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

struct LastReqAsn1 {
    subtype: SequenceOf<LastReqEntryAsn1>
}

impl LastReqAsn1 {

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<LastReq> {
        let mut last_req = LastReq::new_empty();
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


#[derive(Debug, PartialEq, Clone)]
struct LastReqEntry {
    lr_type: Int32,
    lr_value: KerberosTime
}

impl LastReqEntry {

    fn new(lr_type: Int32, lr_value: KerberosTime) -> Self {
        return Self {
            lr_type,
            lr_value
        };
    }

}


#[derive(Asn1Sequence)]
struct LastReqEntryAsn1 {
    #[seq_comp(context_tag = 0)]
    lr_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1)]
    lr_value: SeqField<KerberosTimeAsn1>,
}

impl LastReqEntryAsn1 {

    fn new_empty() -> Self {
        return Self {
            lr_type: SeqField::new(),
            lr_value: SeqField::new()
        }
    }

    fn no_asn1_type(&self) -> KerberosResult<LastReqEntry> {
        let lr_type = self.get_lr_type().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let lr_value = self.get_lr_value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;

        let last_req_entry = LastReqEntry::new(
            lr_type.no_asn1_type()?, 
            lr_value.no_asn1_type()?
        );

        return Ok(last_req_entry);
    }

}

impl Asn1InstanciableObject for LastReqEntryAsn1 {

    fn new_default() -> Self {
        return Self::new_empty();
    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decode_last_req_entry() {
        let raw: Vec<u8> = vec![
            0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x00,
            0xa1, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30,
            0x33, 0x31, 0x5a
        ];

        let mut last_req_entry_asn1 = LastReqEntryAsn1::new_empty();
        last_req_entry_asn1.decode(&raw).unwrap();


        let last_req_entry = LastReqEntry::new(
            Int32::new(0),
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        );

        assert_eq!(last_req_entry, last_req_entry_asn1.no_asn1_type().unwrap());
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

        let mut last_req_asn1 = LastReqAsn1::new_empty();
        last_req_asn1.decode(&raw).unwrap();

        let mut last_req = LastReq::new_empty();

        last_req.push(LastReqEntry::new(
            Int32::new(0),
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        ));

        assert_eq!(last_req, last_req_asn1.no_asn1_type().unwrap());

    }

}