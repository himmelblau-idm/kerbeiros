use std::convert::From;
use super::super::structs_asn1;

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedData {
    etype: i32,
    cipher: Vec<u8>
}

impl EncryptedData {

    pub fn new(etype: i32, cipher: Vec<u8>) -> Self {
        return Self {
            etype,
            cipher
        };
    }

    pub fn get_etype(&self) -> &i32 {
        return &self.etype;
    }

    pub fn get_cipher(&self) -> &Vec<u8> {
        return &self.cipher;
    }
}

impl From<&structs_asn1::EncryptedData> for EncryptedData {
    fn from(enc_data: &structs_asn1::EncryptedData) -> Self {
        return Self::new(
            enc_data.get_etype(),
            enc_data.get_cipher().clone()
        );
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_encrypted_data_asn1() {
        let enc_data_asn1 = structs_asn1::EncryptedData::new(5, vec![1,2,3,4]);
        let enc_data = EncryptedData::new(5, vec![1,2,3,4]);

        assert_eq!(enc_data, EncryptedData::from(&enc_data_asn1));
    }

}