use super::kerberosstring::*;
use asn1::*;
use asn1_derive::*;
use super::int32::{Int32,Int32Asn1};
use super::super::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalName {
    name_type: Int32,
    name_string: Vec<KerberosString>
}

impl PrincipalName {
    
    pub fn new (name_type: i32, string: KerberosString) -> PrincipalName {
        let mut principal_name = PrincipalName{
            name_type: Int32::new(name_type),
            name_string: Vec::new()
        };

        principal_name.name_string.push(string);

        return principal_name;
    }

    fn new_empty() -> Self {
        return Self {
            name_type: Int32::new(0),
            name_string: Vec::new()
        };
    }

    pub fn get_name_type_i32(&self) -> &i32 {
        return &self.name_type;
    }

    pub fn get_name_string(&self) -> &Vec<KerberosString> {
        return &self.name_string;
    }

    pub fn asn1_type(&self) -> PrincipalNameAsn1 {
        return PrincipalNameAsn1::new(&self);
    }

    pub fn push(&mut self, string: KerberosString) {
        self.name_string.push(string);
    }

    pub fn to_ascii_string(&self) -> AsciiString {
        if self.name_string.len() == 0 {
            return AsciiString::new();
        }

        let mut string = self.name_string[0].to_ascii_string();

        for name_string in self.name_string[1..].iter() {
            string.push(AsciiChar::from('/').unwrap());
            string.push_str(&name_string.to_ascii_string());
        }

        return string;
    }

}


#[derive(Asn1Sequence)]
pub struct PrincipalNameAsn1 {
    #[seq_comp(context_tag = 0)]
    name_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1)]
    name_string: SeqField<SequenceOf<KerberosStringAsn1>>
}

impl PrincipalNameAsn1 {

    fn new(principal_name: &PrincipalName) -> PrincipalNameAsn1 {
        let mut asn1_principal_name = Self::new_empty();
        asn1_principal_name._set_asn1_values(principal_name);

        return asn1_principal_name;
    }

    fn new_empty() -> PrincipalNameAsn1 {
        return PrincipalNameAsn1{
            name_type: SeqField::new(),
            name_string: SeqField::new()
        };
    }

    fn _set_asn1_values(&mut self, principal_name: &PrincipalName) {
        self.set_name_type(principal_name.name_type.asn1_type());
        self.set_name_string(self._seq_of_kerberos_strings(principal_name));
    }

    fn _seq_of_kerberos_strings(&self, principal_name: &PrincipalName) -> SequenceOf<KerberosStringAsn1> {
        let mut seq_of_kerberos_strings: SequenceOf<KerberosStringAsn1> = SequenceOf::new();

        for kerb_string in principal_name.name_string.iter() {
            seq_of_kerberos_strings.push(kerb_string.asn1_type());
        }

        return seq_of_kerberos_strings;
    }

    pub fn no_asn1_type(&self) -> KerberosResult<PrincipalName> {
        let mut principal_name = PrincipalName::new_empty();

        let name_type = self.get_name_type().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("PrincipalName::name_type".to_string())
        )?;
        principal_name.name_type = name_type.no_asn1_type()?;

        let name_string = self.get_name_string().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("PrincipalName::name_string".to_string())
        )?;

        for kerb_string in name_string.iter() {
            principal_name.name_string.push(kerb_string.no_asn1_type()?);
        }

        return Ok(principal_name);
    }

}

impl Asn1InstanciableObject for PrincipalNameAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}

impl Asn1Tagged for PrincipalNameAsn1 {
    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::constants::principalnametypes::*;

    #[test]
    fn test_encode_principal_name(){
        let principal_name = PrincipalName::new(NT_PRINCIPAL, KerberosString::_from("mickey"));
        let principal_name_asn1 = principal_name.asn1_type();

        assert_eq!(
            vec![0x30 ,0x11 ,0xa0 ,0x03 ,0x02 ,0x01 ,0x01 ,
            0xa1 ,0x0a ,0x30 ,0x08 ,0x1b ,0x06 ,0x6d ,0x69 ,0x63 ,0x6b ,0x65 ,0x79],
            principal_name_asn1.encode().unwrap()
        )

    }

    #[test]
    fn test_encode_many_principal_name_strings(){
        let mut principal_name = PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        principal_name.push(KerberosString::_from("KINGDOM.HEARTS"));
        let principal_name_asn1 = principal_name.asn1_type();

        assert_eq!(
            vec![0x30, 0x21, 
            0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 
            0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53],
            principal_name_asn1.encode().unwrap()
        )

    }

    #[test]
    fn test_decode_principal_name(){
        let mut principal_name_asn1 = PrincipalNameAsn1::new_empty();

        principal_name_asn1.decode(&[0x30 ,0x11 ,0xa0 ,0x03 ,0x02 ,0x01 ,0x01 ,
            0xa1 ,0x0a ,0x30 ,0x08 ,0x1b ,0x06 ,0x6d ,0x69 ,0x63 ,0x6b ,0x65 ,0x79]).unwrap();

        assert_eq!(PrincipalName::new(NT_PRINCIPAL, KerberosString::_from("mickey")), 
                   principal_name_asn1.no_asn1_type().unwrap());
    }

    #[test]
    fn test_decode_many_principal_name_strings(){
        let mut principal_name_asn1 = PrincipalNameAsn1::new_empty();

        principal_name_asn1.decode(&[0x30, 0x21, 
            0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 
            0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53]).unwrap();

        let mut principal_name = PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        principal_name.push(KerberosString::_from("KINGDOM.HEARTS"));

        assert_eq!(principal_name, 
                   principal_name_asn1.no_asn1_type().unwrap());
    }

    #[test]
    fn test_principal_name_with_multiple_names_to_string() {
        let mut principal_name = PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        principal_name.push(KerberosString::_from("KINGDOM.HEARTS"));

        assert_eq!("krbtgt/KINGDOM.HEARTS", principal_name.to_ascii_string())
    }

    #[test]
    fn test_principal_name_with_single_name_to_string() {
        let principal_name = PrincipalName::new(NT_PRINCIPAL, KerberosString::_from("mickey"));
        assert_eq!("mickey", principal_name.to_ascii_string())
    }

    #[test]
    fn test_principal_name_with_no_name_to_string() {
        let principal_name = PrincipalName::new_empty();
        assert_eq!("", principal_name.to_ascii_string())
    }
 
}
