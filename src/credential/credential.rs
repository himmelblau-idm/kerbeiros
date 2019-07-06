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

    pub fn get_ticket(&self) -> &Ticket {
        return &self.ticket;
    }

    pub fn to_krb_info(&self) -> KrbCredInfo {
        let mut krb_cred_info = self.client_part.to_krb_cred_info();

        krb_cred_info.set_prealm(self.crealm.clone());
        krb_cred_info.set_pname(self.cname.clone());
        return krb_cred_info;
    }

}


hacer test de convertir credencial en krb-info
