use std::convert::From;
use crate::structs_asn1;
use chrono::prelude::*;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq)]
pub struct LastReq {
    entries: Vec<LastReqEntry>
}

impl LastReq {

    fn new_empty() -> Self {
        return Self {
            entries: Vec::new()
        };
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


impl From<&structs_asn1::LastReq> for LastReq {
    fn from(last_req_asn1: &structs_asn1::LastReq) -> Self {
        let mut last_req = Self::new_empty();
        
        for entry in last_req_asn1.iter() {
            last_req.push(
                LastReqEntry::from(entry)
            );
        }

        return last_req;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LastReqEntry {
    lr_type: i32,
    lr_value: DateTime<Utc>
}

impl LastReqEntry {

    fn new(lr_type: i32, lr_value: DateTime<Utc>) -> Self {
        return Self {
            lr_type,
            lr_value
        };
    }

}

impl From<&structs_asn1::LastReqEntry> for LastReqEntry {
    fn from(last_req_entry_asn1: &structs_asn1::LastReqEntry) -> Self {
        return Self::new(
            last_req_entry_asn1.get_lr_type_i32(),
            last_req_entry_asn1.get_lr_value_datetime()
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_convert_from_last_req_entry() {
        let last_req_entry_asn1 = structs_asn1::LastReqEntry::new(
            0,
            structs_asn1::KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        );

        let last_req_entry = LastReqEntry::new(
            0,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)
        );

        assert_eq!(last_req_entry, LastReqEntry::from(&last_req_entry_asn1));
    }


    #[test]
    fn test_convert_from_last_req() {
        let mut last_req_asn1 = structs_asn1::LastReq::new_empty();

        last_req_asn1.push(structs_asn1::LastReqEntry::new(
            0,
            structs_asn1::KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        ));

        let mut last_req = LastReq::new_empty();
        last_req.push(LastReqEntry::new(
            0,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)
        ));

        assert_eq!(last_req, LastReq::from(&last_req_asn1));
    }

}