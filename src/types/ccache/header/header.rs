pub use super::delta_time::DeltaTime;
use nom::number::complete::be_u16;
use nom::IResult;
use nom::{length_data, named};

named!(parse_length_u16_array, length_data!(be_u16));

/// Header of [CCache](./struct.CCache.html).
#[derive(Debug, PartialEq, Clone)]
pub enum Header {
    DeltaTime(DeltaTime),
    Raw(u16, Vec<u8>),
}

impl Header {
    const DELTA_TIME: u16 = 1;

    pub fn new_default() -> Self {
        return Header::DeltaTime(DeltaTime::new_default());
    }

    pub fn build(&self) -> Vec<u8> {
        match &self {
            Header::DeltaTime(delta_time) => {
                return Self::to_bytes_raw(Self::DELTA_TIME, delta_time.to_bytes());
            }
            Self::Raw(tag, data) => {
                return Self::to_bytes_raw(*tag, data.clone());
            }
        }
    }

    fn to_bytes_raw(kind: u16, mut raw: Vec<u8>) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        let raw_len = raw.len() as u16;
        bytes.append(&mut raw_len.to_be_bytes().to_vec());
        bytes.append(&mut raw);
        return bytes;
    }

    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (raw, tag) = be_u16(raw)?;

        match tag {
            Self::DELTA_TIME => {
                let (raw, _taglen) = be_u16(raw)?;
                let (raw, delta_time) = DeltaTime::parse(raw)?;
                return Ok((raw, Self::DeltaTime(delta_time)));
            }
            _ => {
                let (raw, data) = parse_length_u16_array(raw)?;
                return Ok((raw, Self::Raw(tag, data.to_vec())));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn header_to_bytes() {
        assert_eq!(
            vec![0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            Header::new_default().build()
        )
    }

    #[test]
    fn test_parse_header() {
        assert_eq!(
            Header::new_default(),
            Header::parse(&[
                0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
            ])
            .unwrap()
            .1,
        )
    }

    #[test]
    fn test_parse_non_default_header() {
        assert_eq!(
            Header::Raw(0x3, vec![0x0, 0x1, 0x2, 0x4]),
            Header::parse(&[
                0x00, 0x03, 0x00, 0x04, 0x0, 0x1, 0x2, 0x4
            ])
            .unwrap()
            .1,
        )
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_header_panic() {
        Header::parse(&[0x00]).unwrap();
    }
}
