use chrono::prelude::*;
use asn1::*;
use std::ops::Deref;

#[derive(Debug, Clone)]
pub struct KerberosTime(DateTime<Utc>);

impl Deref for KerberosTime {
    type Target = DateTime<Utc>;
    fn deref(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl KerberosTime {

    pub fn new(x: DateTime<Utc>) -> KerberosTime {
        return KerberosTime(x);
    }

    pub fn asn1_type(&self) -> KerberosTimeAsn1 {
        return KerberosTimeAsn1::new(self);
    }
}

pub struct KerberosTimeAsn1 {
    subtype: GeneralizedTime
}

impl KerberosTimeAsn1 {

    pub fn new(date: &KerberosTime) -> KerberosTimeAsn1 {
        let mut generalized_time = GeneralizedTime::new(*date.deref());
        generalized_time.set_format(TimeFormat::YYYYmmddHHMMSSZ);

        return KerberosTimeAsn1{
            subtype: generalized_time
        }
    }

    fn new_empty() -> Self {
        return Self {
            subtype: GeneralizedTime::new_empty()
        };
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
        KerberosTime::new(Utc.ymd(2037, 9, 13).and_hms(02, 48, 5)).asn1_type().encode().unwrap());
    }
}

