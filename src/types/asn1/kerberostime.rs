use chrono::prelude::*;
use red_asn1::*;
use crate::error::{ErrorKind, Result};


pub type KerberosTime = DateTime<Utc>;

#[derive(Default, Debug, PartialEq)]
pub(crate) struct KerberosTimeAsn1 {
    subtype: GeneralizedTime
}

impl KerberosTimeAsn1 {

    pub fn no_asn1_type(&self) -> Result<KerberosTime> {
        let time = self.subtype.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("KerberosTime".to_string())
        )?;
        return Ok(time.clone());
    }

}

impl From<KerberosTime> for KerberosTimeAsn1 {
    fn from(date: KerberosTime) -> Self {
        let mut generalized_time = GeneralizedTime::from(date);
        generalized_time.set_format(TimeFormat::YYYYmmddHHMMSSZ);

        return Self{
            subtype: generalized_time
        }
    }
}


impl Asn1Object for KerberosTimeAsn1 {

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
mod tests {
    use super::*;

    #[test]
    fn test_encode_kerberos_time() {
        assert_eq!(vec![0x18 ,0x0f ,0x32 ,0x30 ,0x33 ,0x37 ,0x30 ,0x39 ,0x31 ,0x33 ,0x30 ,0x32 ,0x34 ,0x38 ,0x30 ,0x35 ,0x5a],
        KerberosTimeAsn1::from(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5)).encode().unwrap());
    }

    #[test]
    fn test_decode_kerberos_time() {
        let mut kerberos_time_asn1 = KerberosTimeAsn1::default();

        kerberos_time_asn1.decode(
            &[0x18 ,0x0f ,0x32 ,0x30 ,0x33 ,0x37 ,0x30 ,0x39 ,0x31 ,0x33 ,0x30 ,0x32 ,0x34 ,0x38 ,0x30 ,0x35 ,0x5a]
        ).unwrap();

        assert_eq!(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5),
        kerberos_time_asn1.no_asn1_type().unwrap());
    }
}

