use crate::structs::*;
use crate::error::*;
use super::credentialwarehouse::*;

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

    pub fn get_authtime(&self) -> &KerberosTime {
        return self.client_part.get_authtime();
    }

    pub fn get_starttime(&self) -> Option<&KerberosTime> {
        return self.client_part.get_starttime();
    }

    pub fn get_endtime(&self) -> &KerberosTime {
        return self.client_part.get_endtime();
    }

    pub fn get_renew_till(&self) -> Option<&KerberosTime> {
        return self.client_part.get_renew_till();
    }

    pub fn get_flags(&self) -> &TicketFlags {
        return self.client_part.get_flags();
    }

    pub fn get_key(&self) -> &EncryptionKey {
        return self.client_part.get_key();
    }

    pub fn get_srealm(&self) -> &KerberosString {
        return self.client_part.get_srealm();
    }

    pub fn get_sname(&self) -> &PrincipalName {
        return self.client_part.get_sname();
    }

    pub fn get_caddr(&self) -> Option<&HostAddresses> {
        return self.client_part.get_caddr();
    }
   
    pub fn get_encrypted_pa_data(&self) -> Option<&MethodData> {
        return self.client_part.get_encrypted_pa_data();
    }

    pub fn save_into_ccache_file(&self, path: &str) -> KerberosResult<()> {
        return CredentialWarehouse::new(self.clone()).save_into_ccache_file(path);
    }

}

