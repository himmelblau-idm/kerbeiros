pub use super::delta_time::*;

/// Header of [CCache](./struct.CCache.html).
#[derive(Debug, PartialEq, Clone)]
pub enum Header {
    DeltaTime(DeltaTime),
}

impl Header {
    pub fn new_default() -> Self {
        return Header::DeltaTime(DeltaTime::new_default());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match &self {
            Header::DeltaTime(delta_time) => {
                return Self::to_bytes_raw(0x1, delta_time.to_bytes());
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn header_to_bytes() {
        assert_eq!(
            vec![0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            Header::new_default().to_bytes()
        )
    }

    #[test]
    fn test_parse_header() {
        assert_eq!(
            Header::new_default().to_bytes(),
            Header::parse(&[
                0x00, 0x01, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
            ])
            .unwrap()
            .1,
        )
    }

    #[test]
    #[should_panic(expected = "Error parsing binary data")]
    fn test_parse_header_panic() {
        Header::parse(&[0x00]).unwrap();
    }
}
