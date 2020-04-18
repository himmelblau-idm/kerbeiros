use super::int32::{Int32, Int32Asn1};
use super::primitives::kerberos_string::*;
use crate::error::{ErrorKind, Result};
use red_asn1::*;
use std::fmt;

/// (*PrincipalName*) Name of some Kerberos entity.
///
/// Used for client name and service name.
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalName {
    pub name_type: Int32,
    pub name_string: Vec<KerberosString>,
}

impl PrincipalName {
    pub fn new(name_type: i32, string: KerberosString) -> PrincipalName {
        let mut principal_name = PrincipalName {
            name_type: name_type,
            name_string: Vec::new(),
        };

        principal_name.name_string.push(string);

        return principal_name;
    }

    pub fn main_name(&self) -> &KerberosString {
        return &self.name_string[0];
    }
    pub fn push(&mut self, string: KerberosString) {
        self.name_string.push(string);
    }

    pub fn to_string(&self) -> String {
        let mut names = self.main_name().to_string();

        for name in self.name_string[1..].iter() {
            names += &format!("/{}", name);
        }

        return names;
    }
}

impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[derive(Sequence, Default, Debug, PartialEq)]
pub(crate) struct PrincipalNameAsn1 {
    #[seq_field(context_tag = 0)]
    name_type: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 1)]
    name_string: SeqField<SequenceOf<KerberosStringAsn1>>,
}

impl PrincipalNameAsn1 {
    fn set_asn1_values(&mut self, principal_name: PrincipalName) {
        self.set_name_type(principal_name.name_type.into());
        self.set_name_string(self.seq_of_kerberos_strings(principal_name));
    }

    fn seq_of_kerberos_strings(
        &self,
        principal_name: PrincipalName,
    ) -> SequenceOf<KerberosStringAsn1> {
        let mut seq_of_kerberos_strings: SequenceOf<KerberosStringAsn1> = SequenceOf::default();

        for kerb_string in principal_name.name_string.into_iter() {
            seq_of_kerberos_strings.push(kerb_string.into());
        }

        return seq_of_kerberos_strings;
    }

    pub fn no_asn1_type(&self) -> Result<PrincipalName> {
        let name_type = self
            .get_name_type()
            .ok_or_else(|| ErrorKind::NotAvailableData("PrincipalName::name_type".to_string()))?;

        let name_string = self
            .get_name_string()
            .ok_or_else(|| ErrorKind::NotAvailableData("PrincipalName::name_string".to_string()))?;

        if name_string.len() == 0 {
            return Err(ErrorKind::NotAvailableData(
                "PrincipalName::name_string".to_string(),
            ))?;
        }

        let mut principal_name =
            PrincipalName::new(name_type.no_asn1_type()?, name_string[0].no_asn1_type()?);

        if name_string.len() > 1 {
            for kerb_string in name_string[1..].iter() {
                principal_name.name_string.push(kerb_string.no_asn1_type()?);
            }
        }

        return Ok(principal_name);
    }
}

impl From<PrincipalName> for PrincipalNameAsn1 {
    fn from(principal_name: PrincipalName) -> Self {
        let mut asn1_principal_name = Self::default();
        asn1_principal_name.set_asn1_values(principal_name);

        return asn1_principal_name;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::principal_name_types::*;

    #[test]
    fn create_default_principal_name_asn1() {
        assert_eq!(
            PrincipalNameAsn1 {
                name_type: SeqField::default(),
                name_string: SeqField::default()
            },
            PrincipalNameAsn1::default()
        )
    }

    #[test]
    fn test_encode_principal_name() {
        let principal_name =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());
        let principal_name_asn1 = PrincipalNameAsn1::from(principal_name);

        assert_eq!(
            vec![
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79
            ],
            principal_name_asn1.encode().unwrap()
        )
    }

    #[test]
    fn test_encode_many_principal_name_strings() {
        let mut principal_name =
            PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        let principal_name_asn1 = PrincipalNameAsn1::from(principal_name);

        assert_eq!(
            vec![
                0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b,
                0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
                0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            principal_name_asn1.encode().unwrap()
        )
    }

    #[test]
    fn test_decode_principal_name() {
        let mut principal_name_asn1 = PrincipalNameAsn1::default();

        principal_name_asn1
            .decode(&[
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
                0x69, 0x63, 0x6b, 0x65, 0x79,
            ])
            .unwrap();

        assert_eq!(
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap()),
            principal_name_asn1.no_asn1_type().unwrap()
        );
    }

    #[test]
    fn test_decode_many_principal_name_strings() {
        let mut principal_name_asn1 = PrincipalNameAsn1::default();

        principal_name_asn1
            .decode(&[
                0x30, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b,
                0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
                0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            ])
            .unwrap();

        let mut principal_name =
            PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        assert_eq!(principal_name, principal_name_asn1.no_asn1_type().unwrap());
    }

    #[test]
    fn principal_name_get_main_name_one_string() {
        let main_name = KerberosString::from_ascii("krbtgt").unwrap();
        let principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());

        assert_eq!(&main_name, principal_name.main_name())
    }

    #[test]
    fn principal_name_get_main_name_many_strings() {
        let main_name = KerberosString::from_ascii("krbtgt").unwrap();
        let mut principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        assert_eq!(&main_name, principal_name.main_name())
    }

    #[test]
    fn principal_name_to_string_with_one_string() {
        let main_name = KerberosString::from_ascii("krbtgt").unwrap();
        let principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());

        assert_eq!("krbtgt".to_string(), principal_name.to_string())
    }

    #[test]
    fn principal_name_to_string_with_many_strings() {
        let main_name = KerberosString::from_ascii("krbtgt").unwrap();
        let mut principal_name = PrincipalName::new(NT_SRV_INST, main_name.clone());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        assert_eq!(
            "krbtgt/KINGDOM.HEARTS".to_string(),
            principal_name.to_string()
        )
    }
}
