pub use ascii::*;
use asn1::*;
use std::result::Result;
use super::super::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct KerberosString {
    string: AsciiString
}


impl KerberosString {

    pub fn _from(string: &str) -> KerberosString {
        return Self::new(AsciiString::from_ascii(string).unwrap());
    }

    pub fn new(string: AsciiString) -> Self {
        return Self { string };
    }

    pub fn to_ascii_string(&self) -> AsciiString {
        return self.string.clone();
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return self.string.as_bytes().to_vec();
    }

    pub fn asn1_type(&self) -> KerberosStringAsn1 {
        return KerberosStringAsn1::new(self.string.clone());
    }

}


pub struct KerberosStringAsn1 {
    tag: Tag,
    subtype: IA5String
}

impl KerberosStringAsn1 {
    fn new(value: AsciiString) -> KerberosStringAsn1 {
        return KerberosStringAsn1 {
            tag: KerberosStringAsn1::type_tag(),
            subtype: IA5String::new(value),
        }
    }

    fn new_empty() -> KerberosStringAsn1 {
        return KerberosStringAsn1 {
            tag: KerberosStringAsn1::type_tag(),
            subtype: IA5String::new_empty(),
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<KerberosString> {
        let ascii_string = self.subtype.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        return Ok(KerberosString::new(ascii_string.clone()));
    }

}

impl Asn1Object for KerberosStringAsn1 {
    
    fn tag(&self) -> Tag {
        return self.tag.clone();
    }

    fn encode_value(&self) -> Result<Vec<u8>,Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}

impl Asn1InstanciableObject for KerberosStringAsn1 {

    fn new_default() -> KerberosStringAsn1 {
        return KerberosStringAsn1::new_empty();
    }
}

impl Asn1Tagged for KerberosStringAsn1 {
    fn type_tag() -> Tag {
        return GeneralString::type_tag();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
    #[should_panic]
    #[test]
    fn test_convert_non_ascii_strings(){
        KerberosString::_from("ñ");
    }

    #[test]
    fn test_convert_ascii_strings(){
        let ascii_string = KerberosString::_from("abcd_/");
        assert_eq!("abcd_/", ascii_string.string);
    }

    #[test]
    fn test_encode_kerberos_string() {
        let kerberos_string = KerberosString::_from("KINGDOM.HEARTS");

        assert_eq!(vec![0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 
                        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53],
                   kerberos_string.asn1_type().encode().unwrap());
    }

    #[test]
    fn test_decode_kerberos_string() {
        let mut kerberos_string_asn1 = KerberosStringAsn1::new_default();

        kerberos_string_asn1.decode(&[0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 
                        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53]).unwrap();

        assert_eq!(KerberosString::_from("KINGDOM.HEARTS"), kerberos_string_asn1.no_asn1_type().unwrap());
    }


    #[test]
    fn test_kerberos_string_to_string() {
        let ascii_string = KerberosString::_from("abcd_/");
        assert_eq!("abcd_/", ascii_string.to_ascii_string());
    }

}