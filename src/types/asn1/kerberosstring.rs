use ascii::*;
use red_asn1::*;
use crate::error::{ErrorKind, Result};

pub type KerberosString = AsciiString;

#[derive(Default, Debug, PartialEq)]
pub(crate) struct KerberosStringAsn1 {
    subtype: IA5String
}

impl KerberosStringAsn1 {
    pub fn new(value: AsciiString) -> KerberosStringAsn1 {
        return KerberosStringAsn1 {
            subtype: IA5String::from(value),
        }
    }

    pub fn no_asn1_type(&self) -> Result<KerberosString> {
        let ascii_string = self.subtype.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("KerberosString".to_string())
        )?;
        return Ok(ascii_string.clone());
    }

}

impl Asn1Object for KerberosStringAsn1 {
    
    fn tag(&self) -> Tag {
        return GeneralString::default().tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    
    #[should_panic]
    #[test]
    fn test_convert_non_ascii_strings(){
        KerberosString::from_ascii("ñ").unwrap();
    }

    #[test]
    fn test_convert_ascii_strings(){
        let ascii_string = KerberosString::from_ascii("abcd_/").unwrap();
        assert_eq!("abcd_/", ascii_string);
    }

    #[test]
    fn test_encode_kerberos_string() {
        let kerberos_string = KerberosString::from_ascii("KINGDOM.HEARTS").unwrap();

        assert_eq!(vec![0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 
                        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53],
                   KerberosStringAsn1::new(kerberos_string).encode().unwrap());
    }

    #[test]
    fn test_decode_kerberos_string() {
        let mut kerberos_string_asn1 = KerberosStringAsn1::default();

        kerberos_string_asn1.decode(&[0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 
                        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53]).unwrap();

        assert_eq!(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap(), kerberos_string_asn1.no_asn1_type().unwrap());
    }


    #[test]
    fn test_kerberos_string_to_string() {
        let ascii_string = KerberosString::from_ascii("abcd_/").unwrap();
        assert_eq!("abcd_/", ascii_string.to_ascii_string());
    }

}