use nom::number::complete::be_u32;
use nom::IResult;

/// Type of [Header](./struct.Header.html).
#[derive(Debug, PartialEq, Clone)]
pub struct DeltaTime {
    pub time_offset: u32,
    pub usec_offset: u32,
}

impl DeltaTime {
    pub fn new_default() -> Self {
        return Self::new(u32::max_value(), 0);
    }

    pub fn new(time_offset: u32, usec_offset: u32) -> Self {
        return Self {
            time_offset,
            usec_offset,
        };
    }

    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.append(&mut self.time_offset.to_be_bytes().to_vec());
        bytes.append(&mut self.usec_offset.to_be_bytes().to_vec());
        return bytes;
    }

    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (raw, time_offset) = be_u32(raw)?;
        let (raw, usec_offset) = be_u32(raw)?;

        return Ok((raw, Self::new(time_offset, usec_offset)));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deltatime_to_bytes() {
        assert_eq!(
            vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            DeltaTime::new_default().build()
        )
    }

    #[test]
    fn parse_deltatime_from_bytes() {
        assert_eq!(
            DeltaTime::new_default(),
            DeltaTime::parse(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00])
                .unwrap()
                .1
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn parse_deltatime_from_bytes_error() {
        DeltaTime::parse(&[0x0]).unwrap();
    }
}
