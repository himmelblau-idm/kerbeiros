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
}

impl From<&structs_asn1::EncryptedData> for EncryptedData {
    fn from(enc_data: &structs_asn1::EncryptedData) -> Self {
        return Self::new(
            enc_data.get_etype_int32(),
            enc_data.get_cipher().clone()
        );
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_encrypted_data_asn1() {
        let enc_data_asn1 = structs_asn1::EncryptedData::new(structs_asn1::Int32::new(5), vec![1,2,3,4]);
        let enc_data = EncryptedData::new(5, vec![1,2,3,4]);

        assert_eq!(enc_data, EncryptedData::from(&enc_data_asn1));
    }

}