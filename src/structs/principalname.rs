use ascii::*;
use crate::structs_asn1;
use std::convert::From;

#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalName {
    name_type: i32,
    name_string: Vec<AsciiString>
}

impl PrincipalName {

    fn new(name_type: i32, name_string: Vec<AsciiString>) -> Self {
        return Self {
            name_type,
            name_string
        };
    }

}


impl From<&structs_asn1::PrincipalName> for PrincipalName {
    fn from(principal_name_asn1: &structs_asn1::PrincipalName) -> Self {
        let name_string_asn1 = principal_name_asn1.get_name_string();
        let mut name_string : Vec<AsciiString> = Vec::with_capacity(name_string_asn1.len());

        for name in name_string_asn1.iter() {
            name_string.push(name.to_ascii_string());
        }
        
        return Self::new(
            *principal_name_asn1.get_name_type_i32(),
            name_string
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn convert_from_principal_name() {
        let mut sname_asn1 =  structs_asn1::PrincipalName::new(
            NT_SRV_INST, 
            structs_asn1::KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname_asn1.push(structs_asn1::KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let sname = PrincipalName::new(
            NT_SRV_INST, 
            vec![
                AsciiString::from_ascii("krbtgt").unwrap(),
                AsciiString::from_ascii("KINGDOM.HEARTS").unwrap()
            ]
        );

        assert_eq!(sname, PrincipalName::from(&sname_asn1));
    }
}