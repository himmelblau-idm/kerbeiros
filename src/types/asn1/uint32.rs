use red_asn1::*;
use crate::error::{ErrorKind, Result};

pub type UInt32 = u32;


#[derive(Default, Debug, PartialEq)]
pub(crate) struct UInt32Asn1 {
    subtype: Integer
}

impl UInt32Asn1 {
    pub fn new(value: UInt32) -> UInt32Asn1 {
        return UInt32Asn1{
            // convert first to i32 to transform values > i32_max into negatives, avoiding overflow when convert to asn1
            subtype: Integer::from((value as i32) as i64)
        };
    }

    pub fn no_asn1_type(&self) -> Result<UInt32> {
        let value = self.subtype.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("UInt32Asn1".to_string())
        )?;
        return Ok(value as u32);
    }
}

impl Asn1Object for UInt32Asn1 {
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
    fn test_encode_uint32() {
        assert_eq!(
            vec![0x02, 0x04, 0x06, 0x08, 0x95, 0xb6],
            UInt32Asn1::new(101225910).encode().unwrap()
        );

        assert_eq!(
            vec![0x02, 0x04, 0xc1, 0x75, 0xc7, 0xce],
            UInt32Asn1::new(3245721550).encode().unwrap()
        );
    }


    #[test]
    fn test_decode_uint32() {
        let mut uint32 = UInt32Asn1::default();

        uint32.decode(&[0x02, 0x04, 0x06, 0x08, 0x95, 0xb6]).unwrap();
        assert_eq!(101225910, uint32.no_asn1_type().unwrap());

        uint32.decode(&[0x02, 0x04, 0xc1, 0x75, 0xc7, 0xce]).unwrap();
        assert_eq!(3245721550, uint32.no_asn1_type().unwrap());
    }

}
