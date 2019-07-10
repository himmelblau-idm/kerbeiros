
#[derive(Debug, PartialEq, Clone)]
pub struct KeyBlock {
    keytype: u16,
    etype: u16,
    keyvalue: Vec<u8>
}


impl KeyBlock {

    pub fn new(keytype: u16, keyvalue: Vec<u8>) -> Self {
        return Self {
            keytype,
            etype: 0,
            keyvalue
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.keytype.to_be_bytes().to_vec();
        bytes.append(&mut self.etype.to_be_bytes().to_vec());
        let keylen = self.keyvalue.len() as u16;
        bytes.append(&mut keylen.to_be_bytes().to_vec());
        bytes.append(&mut self.keyvalue.clone());

        return bytes;
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn keyblock_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x12,
                0x00, 0x00, 
                0x00, 0x20, 
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 
                0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 
                0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28, 
                0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2, 
            ],
            KeyBlock::new(
                AES256_CTS_HMAC_SHA1_96 as u16, 
                vec![
                    0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 
                    0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 
                    0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28, 
                    0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2
                ]
            ).to_bytes()
        )
    }

}