use asn1::*;
use std::ops::Deref;

#[derive(Debug, Clone)]
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
        return self.subtype.decode_value(raw);
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

}