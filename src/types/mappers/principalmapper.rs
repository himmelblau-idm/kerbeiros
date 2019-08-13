use crate::types::*;

pub struct PrincipalMapper{}

impl PrincipalMapper {

    pub fn realm_and_principal_name_to_principal(realm: &Realm, principal_name: &PrincipalName) -> Principal {
        let mut components = Vec::new();

        for name in principal_name.get_name_string().iter() {
            components.push(CountedOctetString::from(name));
        }

        return Principal::new(
            principal_name.get_name_type() as u32, 
            CountedOctetString::from(realm),
            components
        )
    }


}


#[cfg(test)]

mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn realm_and_principal_name_to_principal() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let principal_name = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("mickey").unwrap()
        );


        let principal = Principal::new(
            NT_PRINCIPAL as u32, 
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
            vec![CountedOctetString::new("mickey".as_bytes().to_vec())]
        );

        assert_eq!(principal, PrincipalMapper::realm_and_principal_name_to_principal(&realm, &principal_name));

    }

}