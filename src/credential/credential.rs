use crate::structs_asn1::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    client_part: EncKdcRepPart
}


impl Credential {

    pub fn new(
        crealm: Realm, cname: PrincipalName, 
        ticket: Ticket, client_part: EncKdcRepPart 
    ) -> Self {
        return Self{
            crealm,
            cname,
            ticket,
            client_part
        };
    }


}
