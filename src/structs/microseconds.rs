use asn1::*;

use super::super::error::*;

pub struct Microseconds{
    value: u32
}


impl Microseconds {
    pub fn new(x: u32) -> KerberosResult<Self> {
        if x > 999999 {
            return Err(KerberosErrorKind::InvalidMicroseconds(x))?;
        }
        return Ok(Self{
            value: x
        });
    }

    pub fn get(&self) -> u32 {
        return self.value;
    }

    pub fn set(&mut self, x: u32) -> KerberosResult<()> {
        if x > 999999 {
            return Err(KerberosErrorKind::InvalidMicroseconds(x))?;
        }

        self.value = x;
        return Ok(());
    }

    pub fn asn1_type(&self) -> MicrosecondsAsn1 {
        return MicrosecondsAsn1::new(self);
    }
}


pub struct MicrosecondsAsn1 {
    subtype: Integer
}

impl MicrosecondsAsn1 {
    pub fn new(value: &Microseconds) -> Self {
        return Self{
            subtype: Integer::new(value.get() as i64)
        };
    }

    pub fn new_empty() -> Self {
        return Self{
            subtype: Integer::new_empty()
        };
    }

}


impl Asn1Tagged for MicrosecondsAsn1 {

    fn type_tag() -> Tag {
        return Integer::type_tag();
    }

}

impl Asn1Object for MicrosecondsAsn1 {
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


impl Asn1InstanciableObject for MicrosecondsAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
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
            mic.set(i).unwrap();
            assert_eq!(i, mic.get());
        }
    }

    #[should_panic(expected = "Invalid microseconds value")]
    #[test]
    fn test_set_too_high_microseconds() {
        let mut mic = Microseconds::new(0).unwrap();
        mic.set(1000000).unwrap();
    }


    #[test]
    fn test_encode_microseconds() {
        assert_eq!(vec![0x02, 0x03, 0x05, 0x34, 0x2f],
            Microseconds::new(341039).unwrap().asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_microseconds() {
        let mut mic_asn1 = MicrosecondsAsn1::new_default();
        mic_asn1.decode(&[0x02, 0x03, 0x05, 0x34, 0x2f]).unwrap();

        assert_eq!(&341039, mic_asn1.subtype.value().unwrap());
    }


}