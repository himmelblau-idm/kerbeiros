use red_asn1::*;
use super::int32::*;
use crate::error::{ErrorKind, Result};

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionKey {
    keytype: Int32,
    keyvalue: Vec<u8>
}

impl EncryptionKey {

    pub fn new(keytype: Int32, keyvalue: Vec<u8>) -> Self {
        return Self {
            keytype,
            keyvalue
        };
    }

    pub fn get_keytype(&self) -> Int32 {
        return self.keytype;
    }

    pub fn get_keyvalue(&self) -> &Vec<u8> {
        return &self.keyvalue;
    }

    pub(crate) fn asn1_type(&self) -> EncryptionKeyAsn1 {
        return EncryptionKeyAsn1::new(self);
    }

}


#[derive(Sequence, Default, PartialEq, Debug)]
pub(crate) struct EncryptionKeyAsn1 {
    #[seq_field(context_tag = 0)]
    keytype: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 1)]
    keyvalue: SeqField<OctetString>
}


impl EncryptionKeyAsn1 {

    fn new(encryption_key: &EncryptionKey) -> Self {
        let mut  encryption_key_asn1 = Self::default();
        encryption_key_asn1.set_keytype(encryption_key.get_keytype().into());
        encryption_key_asn1.set_keyvalue(encryption_key.get_keyvalue().clone().into());
        return encryption_key_asn1;
    }

    pub fn no_asn1_type(&self) -> Result<EncryptionKey> {
        let keytype = self.get_keytype().ok_or_else(|| 
            ErrorKind::NotAvailableData("EncryptionKey::keytype".to_string())
        )?;
        let keyvalue = self.get_keyvalue().ok_or_else(|| 
            ErrorKind::NotAvailableData("EncryptionKey::keyvalue".to_string())
        )?;
        let keyvalue_value = keyvalue.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("EncryptionKey::keyvalue".to_string())
        )?;
        
        let encryption_key = EncryptionKey::new(
            keytype.no_asn1_type()?, 
            keyvalue_value.clone()
        );

        return Ok(encryption_key);
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn create_default_encryption_key_asn1() {
        assert_eq!(
            EncryptionKeyAsn1 {
                keytype: SeqField::default(),
                keyvalue: SeqField::default()
            },
            EncryptionKeyAsn1::default()
        )
    }

    #[test]
    fn test_decode_encryption_key (){
        let raw: Vec<u8> = vec![
            0x30, 0x29, 0xa0, 0x03, 0x02, 0x01,
            0x12, 0xa1, 0x22, 0x04, 0x20, 0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff
        ];

        let mut encryption_key_asn1 = EncryptionKeyAsn1::default();
        encryption_key_asn1.decode(&raw).unwrap();

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );

        assert_eq!(encryption_key, encryption_key_asn1.no_asn1_type().unwrap());
        
    }
}