use crate::structs::*;
use super::super::credential::*;

pub struct CredentialCCacheMapper{}


impl CredentialCCacheMapper {

     pub fn credential_to_ccache_credential(credential: &Credential) -> ccache::CredentialEntry {

        let is_skey = 0;

        let time = TimesMapper::authtime_starttime_endtime_renew_till_to_times(
            credential.get_authtime(),
            credential.get_starttime(),
            credential.get_endtime(),
            credential.get_renew_till(),
        );

        let tktflags = TicketFlagsMapper::ticket_flags_to_tktflags(credential.get_flags());
        let key = KeyBlockMapper::encryption_key_to_keyblock(credential.get_key());

        let ticket = ccache::CountedOctetString::new(credential.get_ticket().build());

        let client = PrincipalMapper::realm_and_principal_name_to_principal(credential.get_crealm(), credential.get_cname());
        let server = PrincipalMapper::realm_and_principal_name_to_principal(
            credential.get_srealm(), 
            credential.get_sname(),
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

