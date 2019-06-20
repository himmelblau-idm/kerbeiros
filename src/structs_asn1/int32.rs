use asn1::*;
use std::ops::Deref;
use super::super::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Int32(i32);

impl Deref for Int32 {
    type Target = i32;
    fn deref(&self) -> &i32 {
        &self.0
    }
}

impl Int32 {

    pub fn new(x: i32) -> Int32 {
        return Int32(x);
    }

    pub fn asn1_type(&self) -> Int32Asn1 {
        return Int32Asn1::new(self.clone());
    }
}



pub struct Int32Asn1 {
    subtype: Integer
}

impl Int32Asn1 {
    pub fn new(value: Int32) -> Int32Asn1 {
        return Int32Asn1{
            subtype: Integer::new(*value.deref() as i64)
        };
    }

    fn new_empty() -> Int32Asn1 {
        return Int32Asn1{
            subtype: Integer::new_default(),
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<Int32> {
        let value = self.subtype.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("Int32".to_string())
        )?;
        return Ok(Int32::new(*value as i32));
    }

}

impl Asn1Tagged for Int32Asn1 {

    fn type_tag() -> Tag {
        return Integer::type_tag();
    }

}

impl Asn1Object for Int32Asn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>,Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        let previous_value = self.subtype.value().cloned();
        self.subtype.decode_value(raw)?;
        let new_value = self.subtype.value().unwrap().clone();

        if new_value > 2147483647 || new_value < -2147483648 {
            match previous_value {
                Some(val) => {
                    self.subtype.set_value(val);
                },
                None => {
                    self.subtype.unset_value();
                }
            };

            return Err(Asn1ErrorKind::InvalidValue(
                        format!("{} is not valid, must be between -2147483648 and 2147483647", new_value)
                        ))?; 
        }

        return Ok(());
    }

    fn unset_value(&mut self) {
        self.subtype.unset_value();
    }

}

impl Asn1InstanciableObject for Int32Asn1 {
    
    fn new_default() -> Int32Asn1 {
        return Int32Asn1::new_empty();
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_int32() {
        assert_eq!(vec![0x02, 0x02, 0xff, 0x79],
            Int32(-135).asn1_type().encode().unwrap()
        );

        assert_eq!(vec![0x02, 0x01, 0x03],
            Int32(3).asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_int32() {
        let mut int32_asn1 = Int32Asn1::new_empty();

        int32_asn1.decode(&[0x02, 0x02, 0xff, 0x79]).unwrap();

        assert_eq!(Int32(-135), int32_asn1.no_asn1_type().unwrap());

        int32_asn1.decode(&[0x02, 0x01, 0x03]).unwrap();
        assert_eq!(Int32(3), int32_asn1.no_asn1_type().unwrap());
    }

    #[should_panic (expected = "Invalid value")]
    #[test]
    fn test_decode_higher_value_than_int32() {
        let mut int32_asn1 = Int32Asn1::new_empty();
        int32_asn1.decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]).unwrap();
    }

    #[should_panic (expected = "Invalid value")]
    #[test]
    fn test_decode_lower_value_than_int32() {
        let mut int32_asn1 = Int32Asn1::new_empty();
        int32_asn1.decode(&[0x02, 0x05, 0xf1, 0x00, 0x00, 0x00, 0x00]).unwrap();
    }

    #[test]
    fn test_decode_not_change_value_after_decode_failure() {
        let mut int32_asn1 = Int32Asn1::new_empty();
        int32_asn1.decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]).err();
        assert_eq!(None, int32_asn1.subtype.value());

        int32_asn1.subtype.set_value(1);
        int32_asn1.decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]).err();
        assert_eq!(&1, int32_asn1.subtype.value().unwrap());
    }

}