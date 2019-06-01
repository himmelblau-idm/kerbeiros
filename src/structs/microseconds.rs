use asn1::*;

use super::super::error::*;

pub struct Microseconds(u32);


impl Microseconds {
    pub fn new(x: u32) -> KerberosResult<Self> {
        if x > 999999 {
            return Err(KerberosErrorKind::InvalidMicroseconds(x))?;
        }
        return Ok(Self(x));
    }

    pub fn get(&self) -> u32 {
        return self.0;
    }

    pub fn set(&mut self, x: u32) -> KerberosResult<()> {
        if x > 999999 {
            return Err(KerberosErrorKind::InvalidMicroseconds(x))?;
        }

        self.0 = x;
        return Ok(());
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
}