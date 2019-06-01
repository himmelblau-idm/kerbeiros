use ascii::AsciiString;
use asn1::*;
use std::result::Result;
use super::super::error::*;

pub struct KerberosString {
    string: AsciiString
}


impl KerberosString {

    pub fn from(string: &str) -> KerberosResult<KerberosString> {
        return Ok(KerberosString{
            string: AsciiString::from_ascii(string)?
        });
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
    pub fn new(value: AsciiString) -> KerberosStringAsn1 {
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
        KerberosString::from("ñ").unwrap();
    }

    #[test]
    fn test_convert_ascii_strings(){
        let ascii_string = KerberosString::from("abcd_/").unwrap();
        assert_eq!("abcd_/", ascii_string.string);
    }

}