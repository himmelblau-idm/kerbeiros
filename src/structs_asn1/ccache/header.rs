use super::deltatime::*;

pub enum Header {
    DeltaTime(DeltaTime)
}

impl Header {

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
            Header::DeltaTime(DeltaTime::new(u32::max_value(), 0)).to_bytes()
        )
    }
}