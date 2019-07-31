use red_asn1::*;
pub use super::super::int32::*;
pub use super::super::kerberostime::*;
use crate::error::*;

#[derive(Debug, PartialEq, Clone)]
pub struct LastReqEntry {
    lr_type: Int32,
    lr_value: KerberosTime
}

impl LastReqEntry {

    pub fn new(lr_type: Int32, lr_value: KerberosTime) -> Self {
        return Self {
            lr_type,
            lr_value
        };
    }

}


#[derive(Sequence, Default, Debug, PartialEq)]
pub struct LastReqEntryAsn1 {
    #[seq_field(context_tag = 0)]
    lr_type: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 1)]
    lr_value: SeqField<KerberosTimeAsn1>,
}

impl LastReqEntryAsn1 {

    pub fn no_asn1_type(&self) -> KerberosResult<LastReqEntry> {
        let lr_type = self.get_lr_type().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("LastReqEntry::lr_type".to_string())
        )?;
        let lr_value = self.get_lr_value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("LastReqEntry::lr_value".to_string())
        )?;

        let last_req_entry = LastReqEntry::new(
            lr_type.no_asn1_type()?, 
            lr_value.no_asn1_type()?
        );

        return Ok(last_req_entry);
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

        let mut last_req_entry_asn1 = LastReqEntryAsn1::default();
        last_req_entry_asn1.decode(&raw).unwrap();


        let last_req_entry = LastReqEntry::new(
            0,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)
        );

        assert_eq!(last_req_entry, last_req_entry_asn1.no_asn1_type().unwrap());
    }

}