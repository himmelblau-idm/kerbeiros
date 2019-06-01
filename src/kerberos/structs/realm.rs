use super::kerberosstring::{KerberosString, KerberosStringAsn1};

pub type Realm = KerberosString;
pub type RealmAsn1 = KerberosStringAsn1;

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::*;

    #[test]
    fn test_encode_realm() {
        let realm = Realm::from("KINGDOM.HEARTS").unwrap();

        assert_eq!(vec![0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 
                        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53],
                   realm.asn1_type().encode().unwrap());
    }
}