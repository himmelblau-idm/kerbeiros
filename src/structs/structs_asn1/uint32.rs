use asn1::*;
use crate::error::*;

pub type UInt32 = u32;



pub struct UInt32Asn1 {
    subtype: Integer
}

impl UInt32Asn1 {
    pub fn new(value: UInt32) -> UInt32Asn1 {
        return UInt32Asn1{
            subtype: Integer::new(value as i64)
        };
    }

    pub fn new_empty() -> UInt32Asn1 {
        return UInt32Asn1{
            subtype: Integer::new_empty()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<UInt32> {
        let value = self.subtype.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("UInt32Asn1".to_string())
        )?;
        return Ok(*value as u32);
    }
}

impl Asn1Tagged for UInt32Asn1 {

    fn type_tag() -> Tag {
        return Integer::type_tag();
    }

}

impl Asn1Object for UInt32Asn1 {
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


impl Asn1InstanciableObject for UInt32Asn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}



#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_uint32() {
        assert_eq!(vec![0x02, 0x04, 0x06, 0x08, 0x95, 0xb6],
            UInt32Asn1::new(101225910).encode().unwrap()
        );
    }

}