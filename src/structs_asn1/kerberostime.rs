pub use chrono::prelude::*;
use asn1::*;
use super::super::error::*;


pub type KerberosTime = DateTime<Utc>;

pub struct KerberosTimeAsn1 {
    subtype: GeneralizedTime
}

impl KerberosTimeAsn1 {

    pub fn new(date: KerberosTime) -> KerberosTimeAsn1 {
        let mut generalized_time = GeneralizedTime::new(date);
        generalized_time.set_format(TimeFormat::YYYYmmddHHMMSSZ);

        return KerberosTimeAsn1{
            subtype: generalized_time
        }
    }

    fn new_empty() -> Self {
        let mut generalized_time = GeneralizedTime::new_empty();
        generalized_time.set_format(TimeFormat::YYYYmmddHHMMSSZ);
        return Self {
            subtype: generalized_time
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<KerberosTime> {
        let time = self.subtype.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("KerberosTime".to_string())
        )?;
        return Ok(time.clone());
    }

}


impl Asn1Object for KerberosTimeAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>,Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}

impl Asn1Tagged for KerberosTimeAsn1 {

    fn type_tag() -> Tag {
        return GeneralizedTime::type_tag();
    }
}

impl Asn1InstanciableObject for KerberosTimeAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_kerberos_time() {
        assert_eq!(vec![0x18 ,0x0f ,0x32 ,0x30 ,0x33 ,0x37 ,0x30 ,0x39 ,0x31 ,0x33 ,0x30 ,0x32 ,0x34 ,0x38 ,0x30 ,0x35 ,0x5a],
        KerberosTimeAsn1::new(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5)).encode().unwrap());
    }

    #[test]
    fn test_decode_kerberos_time() {
        let mut kerberos_time_asn1 = KerberosTimeAsn1::new_empty();

        kerberos_time_asn1.decode(
            &[0x18 ,0x0f ,0x32 ,0x30 ,0x33 ,0x37 ,0x30 ,0x39 ,0x31 ,0x33 ,0x30 ,0x32 ,0x34 ,0x38 ,0x30 ,0x35 ,0x5a]
        ).unwrap();

        assert_eq!(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5),
        kerberos_time_asn1.no_asn1_type().unwrap());
    }
}

