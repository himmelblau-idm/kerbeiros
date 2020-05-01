use crate::{Error, Result};
use red_asn1::*;

/// (*Int32*) Kerberos i32.
pub type Int32 = i32;

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Int32Asn1 {
    subtype: Integer,
}

impl Int32Asn1 {
    pub fn no_asn1_type(&self) -> Result<Int32> {
        let value = self
            .subtype
            .value()
            .ok_or_else(|| Error::NotAvailableData("Int32".to_string()))?;
        return Ok(value as Int32);
    }
}

impl From<Int32> for Int32Asn1 {
    fn from(value: Int32) -> Int32Asn1 {
        return Int32Asn1 {
            subtype: Integer::from(value as i64),
        };
    }
}

impl Asn1Object for Int32Asn1 {
    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        let previous_value = self.subtype.value().clone();
        self.subtype.decode_value(raw)?;
        let new_value = self.subtype.value().unwrap().clone();

        if new_value > 2147483647 || new_value < -2147483648 {
            match previous_value {
                Some(val) => {
                    self.subtype.set_value(val);
                }
                None => {
                    self.subtype.unset_value();
                }
            };

            return Err(red_asn1::ValueErrorKind::ConstraintError(format!(
                "{} is not valid, must be between -2147483648 and 2147483647",
                new_value
            )))?;
        }

        return Ok(());
    }

    fn unset_value(&mut self) {
        self.subtype.unset_value();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_int32() {
        assert_eq!(
            vec![0x02, 0x02, 0xff, 0x79],
            Int32Asn1::from(-135).encode().unwrap()
        );

        assert_eq!(vec![0x02, 0x01, 0x03], Int32Asn1::from(3).encode().unwrap());
    }

    #[test]
    fn test_decode_int32() {
        let mut int32_asn1 = Int32Asn1::default();

        int32_asn1.decode(&[0x02, 0x02, 0xff, 0x79]).unwrap();

        assert_eq!(-135, int32_asn1.no_asn1_type().unwrap());

        int32_asn1.decode(&[0x02, 0x01, 0x03]).unwrap();
        assert_eq!(3, int32_asn1.no_asn1_type().unwrap());
    }

    #[should_panic(expected = "Invalid value")]
    #[test]
    fn test_decode_higher_value_than_int32() {
        let mut int32_asn1 = Int32Asn1::default();
        int32_asn1
            .decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
    }

    #[should_panic(expected = "Invalid value")]
    #[test]
    fn test_decode_lower_value_than_int32() {
        let mut int32_asn1 = Int32Asn1::default();
        int32_asn1
            .decode(&[0x02, 0x05, 0xf1, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
    }

    #[test]
    fn test_decode_not_change_value_after_decode_failure() {
        let mut int32_asn1 = Int32Asn1::default();
        int32_asn1
            .decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00])
            .err();
        assert_eq!(None, int32_asn1.subtype.value());

        int32_asn1.subtype.set_value(1);
        int32_asn1
            .decode(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00])
            .err();
        assert_eq!(1, int32_asn1.subtype.value().unwrap());
    }
}
