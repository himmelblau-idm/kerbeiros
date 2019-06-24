
use crate::structs_asn1;
use std::convert::From;

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionKey {
    keytype: i32,
    keyvalue: Vec<u8>
}

impl EncryptionKey {

    fn new(keytype: i32, keyvalue: Vec<u8>) -> Self {
        return Self {
            keytype,
            keyvalue
        };
    }
}

impl From<&structs_asn1::EncryptionKey> for EncryptionKey {
    fn from(enc_key: &structs_asn1::EncryptionKey) -> Self {
        return Self::new(
            *enc_key.get_keytype(),
            enc_key.get_keyvalue().clone()
        );
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_convert_from_asn1_encryption_key() {
        let encryption_key_asn1 = structs_asn1::EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );


        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );

        assert_eq!(encryption_key, EncryptionKey::from(&encryption_key_asn1));
    }

}