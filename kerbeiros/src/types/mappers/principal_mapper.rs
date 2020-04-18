use super::CountedOctetStringMapper;
use crate::error::{ErrorKind, Result};
use crate::types::*;
use kerberos_ccache::Principal;

pub struct PrincipalMapper {}

impl PrincipalMapper {
    pub fn realm_and_principal_name_to_principal(
        realm: &Realm,
        principal_name: &PrincipalName,
    ) -> Principal {
        let mut components = Vec::new();

        for name in principal_name.name_string().iter() {
            components.push(
                CountedOctetStringMapper::kerberos_string_to_counted_octet_string(name)
            );
        }

        return Principal::new(
            principal_name.name_type() as u32,
            CountedOctetStringMapper::kerberos_string_to_counted_octet_string(
                realm,
            ),
            components,
        );
    }

    pub fn principal_to_realm_and_principal_name(
        principal: Principal,
    ) -> Result<(Realm, PrincipalName)> {
        let components = principal.components;
        let mut names = Vec::with_capacity(components.len());
        for component in components.into_iter() {
            names.push(
                CountedOctetStringMapper::counted_octet_string_to_kerberos_string(component)?
               );
        }

        if names.len() == 0 {
            return Err(ErrorKind::NoPrincipalName)?;
        }

        let main_name = names.remove(0);
        let mut principal_name =
            PrincipalName::new(principal.name_type as i32, main_name);

        while names.len() > 0 {
            principal_name.push(names.remove(0));
        }

        let realm =
            CountedOctetStringMapper::counted_octet_string_to_kerberos_string(
                principal.realm,
            )?;

        return Ok((realm, principal_name));
    }
}

#[cfg(test)]

mod test {
    use super::*;
    use crate::constants::*;
    use kerberos_ccache::CountedOctetString;

    #[test]
    fn realm_and_principal_name_to_principal() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let principal_name = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from_ascii("mickey").unwrap(),
        );

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())],
        );

        assert_eq!(
            principal,
            PrincipalMapper::realm_and_principal_name_to_principal(
                &realm,
                &principal_name
            )
        );
    }

    #[test]
    fn test_principal_to_realm_and_principal_name() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let principal_name = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from_ascii("mickey").unwrap(),
        );

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())],
        );

        assert_eq!(
            (realm, principal_name),
            PrincipalMapper::principal_to_realm_and_principal_name(principal)
                .unwrap(),
        );
    }

    #[test]
    #[should_panic(expected = "No principal name found")]
    fn test_principal_to_realm_and_principal_name_panic() {
        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![],
        );

        PrincipalMapper::principal_to_realm_and_principal_name(principal)
            .unwrap();
    }

    #[test]
    fn test_principal_to_realm_and_principal_name_multiple_names() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let mut principal_name = PrincipalName::new(
            NT_PRINCIPAL,
            KerberosString::from_ascii("mickey").unwrap(),
        );

        principal_name.push(KerberosString::from_ascii("user2").unwrap());

        let principal = Principal::new(
            NT_PRINCIPAL as u32,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![
                CountedOctetString::new("mickey".as_bytes().to_vec()),
                CountedOctetString::new("user2".as_bytes().to_vec()),
            ],
        );

        assert_eq!(
            (realm, principal_name),
            PrincipalMapper::principal_to_realm_and_principal_name(principal)
                .unwrap(),
        );
    }
}
