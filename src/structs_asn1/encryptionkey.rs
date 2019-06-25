use asn1::*;
use asn1_derive::*;
pub use super::int32::*;
pub use asn1::OctetString;
use super::super::error::*;

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

}


#[derive(Asn1Sequence)]
pub struct EncryptionKeyAsn1 {
    #[seq_comp(context_tag = 0)]
    keytype: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1)]
    keyvalue: SeqField<OctetString>
}


impl EncryptionKeyAsn1 {

    fn new_empty() -> Self {
        return Self {
            keytype: SeqField::new(),
            keyvalue: SeqField::new()
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<EncryptionKey> {
        let keytype = self.get_keytype().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncryptionKey::keytype".to_string())
        )?;
        let keyvalue = self.get_keyvalue().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncryptionKey::keyvalue".to_string())
        )?;
        let keyvalue_value = keyvalue.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncryptionKey::keyvalue".to_string())
        )?;
        
        let encryption_key = EncryptionKey::new(
            keytype.no_asn1_type()?, 
            keyvalue_value.clone()
        );

        return Ok(encryption_key);
    }

}

impl Asn1InstanciableObject for EncryptionKeyAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

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

        let mut encryption_key_asn1 = EncryptionKeyAsn1::new_empty();
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