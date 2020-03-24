/// Type of [Header](./struct.Header.html).
#[derive(Debug, PartialEq, Clone)]
pub struct DeltaTime {
    time_offset: u32,
    usec_offset: u32,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.append(&mut self.time_offset.to_be_bytes().to_vec());
        bytes.append(&mut self.usec_offset.to_be_bytes().to_vec());
        return bytes;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deltatime_to_bytes() {
        assert_eq!(
            vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
            DeltaTime::new_default().to_bytes()
        )
    }

    #[test]
    fn parse_deltatime_from_bytes() {
        assert_eq!(
            DeltaTime::new_default().to_bytes(),
            DeltaTime::parse(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]).unwrap().1
        )
    }
}
