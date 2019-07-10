use crate::structs::*;

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

    pub fn get_crealm(&self) -> &Realm {
        return &self.crealm;
    }

    pub fn get_cname(&self) -> &PrincipalName {
        return &self.cname;
    }
 
    pub fn get_ticket(&self) -> &Ticket {
        return &self.ticket;
    }

    pub fn get_client_part(&self) -> &EncKdcRepPart {
        return &self.client_part;
    }

    pub fn to_ccache_credential(&self) -> ccache::CredentialEntry {

        let is_skey = 0;

        let time = TimesMapper::authtime_starttime_endtime_renew_till_to_times(
            self.client_part.get_authtime(),
            self.client_part.get_starttime(),
            self.client_part.get_endtime(),
            self.client_part.get_renew_till(),
        );

        let tktflags = TicketFlagsMapper::ticket_flags_to_tktflags(self.client_part.get_flags());
        let key = KeyBlockMapper::encryption_key_to_keyblock(self.client_part.get_key());

        let ticket = ccache::CountedOctetString::new(self.ticket.build());

        let client = PrincipalMapper::realm_and_principal_name_to_principal(&self.crealm, &self.cname);
        let server = PrincipalMapper::realm_and_principal_name_to_principal(
            self.client_part.get_srealm(), 
            self.client_part.get_sname(),
        );

        let ccache_credential = ccache::CredentialEntry::new(
            client, 
            server, 
            key, 
            time, 
            is_skey, 
            tktflags, 
            ticket
        );

        return ccache_credential;
    }

}

