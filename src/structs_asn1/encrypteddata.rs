use asn1::*;
use asn1_derive::*;
use super::int32::*;
use super::uint32::*;
use super::super::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedData {
    etype: Int32,
    kvno: Option<UInt32>,
    cipher: Vec<u8>
}


impl EncryptedData {

    pub fn new(etype: Int32, cipher: Vec<u8>) -> Self {
        return Self {
            etype: etype,
            kvno: None,
            cipher: cipher
        };
    }

    pub fn set_kvno(&mut self, kvno: UInt32) {
        self.kvno = Some(kvno);
    }

    pub fn get_etype_int32(&self) -> i32 {
        return *self.etype;
    }

    pub fn get_cipher(&self) -> &Vec<u8> {
        return &self.cipher;
    }

    pub fn asn1_type(&self) -> EncryptedDataAsn1 {
        return EncryptedDataAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
pub struct EncryptedDataAsn1 {
    #[seq_comp(context_tag = 0)]
    etype: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1, optional)]
    kvno: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 2)]
    cipher: SeqField<OctetString>
}

impl EncryptedDataAsn1 {

    fn new(enc_data: &EncryptedData) -> EncryptedDataAsn1 {
        let mut enc_data_asn1 = Self::new_empty();

        enc_data_asn1.set_etype(enc_data.etype.asn1_type());
        enc_data_asn1.set_cipher(OctetString::new(enc_data.cipher.clone()));

        if let Some(kvno) = &enc_data.kvno {
            enc_data_asn1.set_kvno(kvno.asn1_type());
        }

        return enc_data_asn1;
    }

    fn new_empty() -> EncryptedDataAsn1 {
        return EncryptedDataAsn1{
            etype: SeqField::new(),
            kvno: SeqField::new(),
            cipher: SeqField::new()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<EncryptedData> {
        let etype = self.get_etype().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let cipher = self.get_cipher().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let cipher_value = cipher.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;

        let mut enc_data = EncryptedData::new(etype.no_asn1_type()?, cipher_value.clone());

        if let Some(kvno) = self.get_kvno() {
            enc_data.set_kvno(kvno.no_asn1_type()?);
        }

        return Ok(enc_data);
    }

}

impl Asn1Tagged for EncryptedDataAsn1 {
    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }
}

impl Asn1InstanciableObject for EncryptedDataAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}

#[cfg(test)]

mod test {
    use super::*;
    use super::super::super::constants::etypes::*;

    #[test]
    fn encode_encrypted_data(){
        let enc_data = EncryptedData::new(Int32::new(AES256_CTS_HMAC_SHA1_96), vec![
            0x64, 0x67, 0x3f, 0x70, 0x45, 
            0x50, 0x57, 0xa5, 0x16, 0x16, 0xf6, 0xa9, 0x0b, 0x8c, 
            0x04, 0xe6, 0xa9, 0x5d, 0x8e, 0x1d, 0x95, 0xdf, 0x98, 
            0x67, 0x29, 0x16, 0x9a, 0x54, 0xbc, 0x66, 0xae, 0x29, 
            0x9d, 0xd1, 0xec, 0x62, 0xbc, 0x99, 0xce, 0x2c, 0x9f, 
            0x6a, 0x4e, 0xf1, 0xf0, 0x25, 0xf9, 0x9e, 0x13, 0xa5, 
            0x94, 0xa2, 0x39, 0x80, 0x7f, 0xdf
        ]);

        assert_eq!(vec![0x30, 0x41, 
                        0xa0, 0x03, 0x02, 0x01, 0x12, 
                        0xa2, 0x3a, 0x04, 0x38, 0x64, 0x67, 0x3f, 0x70, 0x45, 
                        0x50, 0x57, 0xa5, 0x16, 0x16, 0xf6, 0xa9, 0x0b, 0x8c, 
                        0x04, 0xe6, 0xa9, 0x5d, 0x8e, 0x1d, 0x95, 0xdf, 0x98, 
                        0x67, 0x29, 0x16, 0x9a, 0x54, 0xbc, 0x66, 0xae, 0x29, 
                        0x9d, 0xd1, 0xec, 0x62, 0xbc, 0x99, 0xce, 0x2c, 0x9f, 
                        0x6a, 0x4e, 0xf1, 0xf0, 0x25, 0xf9, 0x9e, 0x13, 0xa5, 
                        0x94, 0xa2, 0x39, 0x80, 0x7f, 0xdf], enc_data.asn1_type().encode().unwrap());
    }

    #[test]
    fn decode_encrypted_data() {
        let mut enc_data_asn1 = EncryptedDataAsn1::new_empty();
        enc_data_asn1.decode(&[0x30, 0x41, 
            0xa0, 0x03, 0x02, 0x01, 0x12, 
            0xa2, 0x3a, 0x04, 0x38, 0x64, 0x67, 0x3f, 0x70, 0x45, 
            0x50, 0x57, 0xa5, 0x16, 0x16, 0xf6, 0xa9, 0x0b, 0x8c, 
            0x04, 0xe6, 0xa9, 0x5d, 0x8e, 0x1d, 0x95, 0xdf, 0x98, 
            0x67, 0x29, 0x16, 0x9a, 0x54, 0xbc, 0x66, 0xae, 0x29, 
            0x9d, 0xd1, 0xec, 0x62, 0xbc, 0x99, 0xce, 0x2c, 0x9f, 
            0x6a, 0x4e, 0xf1, 0xf0, 0x25, 0xf9, 0x9e, 0x13, 0xa5, 
            0x94, 0xa2, 0x39, 0x80, 0x7f, 0xdf]).unwrap();

        let enc_data = EncryptedData::new(Int32::new(AES256_CTS_HMAC_SHA1_96), vec![
            0x64, 0x67, 0x3f, 0x70, 0x45, 
            0x50, 0x57, 0xa5, 0x16, 0x16, 0xf6, 0xa9, 0x0b, 0x8c, 
            0x04, 0xe6, 0xa9, 0x5d, 0x8e, 0x1d, 0x95, 0xdf, 0x98, 
            0x67, 0x29, 0x16, 0x9a, 0x54, 0xbc, 0x66, 0xae, 0x29, 
            0x9d, 0xd1, 0xec, 0x62, 0xbc, 0x99, 0xce, 0x2c, 0x9f, 
            0x6a, 0x4e, 0xf1, 0xf0, 0x25, 0xf9, 0x9e, 0x13, 0xa5, 
            0x94, 0xa2, 0x39, 0x80, 0x7f, 0xdf
        ]);

        assert_eq!(enc_data, enc_data_asn1.no_asn1_type().unwrap());
    }

}