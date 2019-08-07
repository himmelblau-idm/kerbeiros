use red_asn1::*;
use crate::error::{ErrorKind, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Microseconds{
    value: u32
}


impl Microseconds {
    pub fn new(x: u32) -> Result<Self> {
        if x > 999999 {
            return Err(ErrorKind::InvalidMicroseconds(x))?;
        }
        return Ok(Self{
            value: x
        });
    }

    pub fn get(&self) -> u32 {
        return self.value;
    }

    fn _set(&mut self, x: u32) -> Result<()> {
        if x > 999999 {
            return Err(ErrorKind::InvalidMicroseconds(x))?;
        }

        self.value = x;
        return Ok(());
    }

    pub fn asn1_type(&self) -> MicrosecondsAsn1 {
        return MicrosecondsAsn1::new(self);
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct MicrosecondsAsn1 {
    subtype: Integer
}

impl MicrosecondsAsn1 {
    
    fn new(value: &Microseconds) -> Self {
        return Self{
            subtype: Integer::from(value.get() as i64)
        };
    }

    pub fn no_asn1_type(&self) -> Result<Microseconds> {
        let value = self.subtype.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("Microseconds".to_string())
        )?;
        return Microseconds::new(value as u32);
    }

}

impl Asn1Object for MicrosecondsAsn1 {
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

        if new_value > 999999 || new_value < 0 {
            match previous_value {
                Some(val) => {
                    self.subtype.set_value(val);
                },
                None => {
                    self.subtype.unset_value();
                }
            };

            return Err(red_asn1::ValueErrorKind::ConstraintError(
                        format!("{} is not valid, must be between 0 and 999999", new_value)
                        ))?; 
        }

        return Ok(());
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_microseconds() {
        for i in 0..1000000 {
            assert_eq!(i, Microseconds::new(i).unwrap().get());
        }
    }

    #[should_panic(expected = "Invalid microseconds value")]
    #[test]
    fn test_create_too_high_microseconds() {
        Microseconds::new(1000000).unwrap();
    }

    #[test]
    fn test_setting_microseconds() {
        let mut mic = Microseconds::new(0).unwrap();
        for i in 0..1000000 {
            mic._set(i).unwrap();
            assert_eq!(i, mic.get());
        }
    }

    #[should_panic(expected = "Invalid microseconds value")]
    #[test]
    fn test_set_too_high_microseconds() {
        let mut mic = Microseconds::new(0).unwrap();
        mic._set(1000000).unwrap();
    }


    #[test]
    fn test_encode_microseconds() {
        assert_eq!(vec![0x02, 0x03, 0x05, 0x34, 0x2f],
            Microseconds::new(341039).unwrap().asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_microseconds() {
        let mut mic_asn1 = MicrosecondsAsn1::default();
        mic_asn1.decode(&[0x02, 0x03, 0x05, 0x34, 0x2f]).unwrap();

        assert_eq!(341039, mic_asn1.no_asn1_type().unwrap().value);
    }

    #[should_panic (expected = "Invalid value")]
    #[test]
    fn test_decode_high_value_of_microseconds() {
        let mut mic_asn1 = MicrosecondsAsn1::default();
        mic_asn1.decode(&[0x02, 0x04, 0x01, 0x05, 0x34, 0x2f]).unwrap();
    }

    #[should_panic (expected = "Invalid value")]
    #[test]
    fn test_decode_low_value_of_microseconds() {
        let mut mic_asn1 = MicrosecondsAsn1::default();
        mic_asn1.decode(&[0x02, 0x04, 0xff, 0x05, 0x34, 0x2f]).unwrap();
    }


    #[test]
    fn test_decode_not_change_value_after_decode_failure() {
        let mut mic_asn1 = MicrosecondsAsn1::default();
        mic_asn1.decode(&[0x02, 0x04, 0x01, 0x05, 0x34, 0x2f]).err();
        assert_eq!(None, mic_asn1.subtype.value());

        mic_asn1.subtype.set_value(1);
        mic_asn1.decode(&[0x02, 0x04, 0x01, 0x05, 0x34, 0x2f]).err();
        assert_eq!(1, mic_asn1.subtype.value().unwrap());
    }


}