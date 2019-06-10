use super::super::structs;
use super::super::error::*;

struct AsRep {
    client_realm: String,
    client_name: String
}


impl AsRep {

    fn new(client_realm: String, client_name: String) -> Self {
        return Self {
            client_realm,
            client_name
        };
    }

    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let as_rep = structs::AsRep::parse(raw)?;

        return Ok(Self::new(
            as_rep.get_crealm(),
            as_rep.get_cname()
        ));
    }

}