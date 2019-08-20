use crate::types::*;
use crate::error::*;
use super::credential_warehouse::*;


/// Represents a Kerberos credential, which includes one Ticket and session information.
/// 
/// Session information includes data such as session key, client name, realm, ticket flags and ticket expiration time.
/// 
/// It can be saved converted and save into Windows or Linux credential formats.
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

    pub fn crealm(&self) -> &Realm {
        return &self.crealm;
    }

    pub fn cname(&self) -> &PrincipalName {
        return &self.cname;
    }
 
    pub fn ticket(&self) -> &Ticket {
        return &self.ticket;
    }

    pub fn authtime(&self) -> &KerberosTime {
        return self.client_part.authtime();
    }

    pub fn starttime(&self) -> Option<&KerberosTime> {
        return self.client_part.starttime();
    }

    pub fn endtime(&self) -> &KerberosTime {
        return self.client_part.endtime();
    }

    pub fn renew_till(&self) -> Option<&KerberosTime> {
        return self.client_part.renew_till();
    }

    pub fn flags(&self) -> &TicketFlags {
        return self.client_part.flags();
    }

    pub fn key(&self) -> &EncryptionKey {
        return self.client_part.key();
    }

    pub fn srealm(&self) -> &KerberosString {
        return self.client_part.srealm();
    }

    pub fn sname(&self) -> &PrincipalName {
        return self.client_part.sname();
    }

    pub fn caddr(&self) -> Option<&HostAddresses> {
        return self.client_part.caddr();
    }
   
    pub fn encrypted_pa_data(&self) -> Option<&MethodData> {
        return self.client_part.encrypted_pa_data();
    }

    /// Saves the credential into a file by using the ccache format, used by Linux.
    pub fn save_into_ccache_file(&self, path: &str) -> Result<()> {
        return CredentialWarehouse::new(self.clone()).save_into_ccache_file(path);
    }

    /// Saves the credential into a file by using the KRB-CRED format, used by Windows.
    pub fn save_into_krb_cred_file(&self, path: &str) -> Result<()> {
        return CredentialWarehouse::new(self.clone()).save_into_krb_cred_file(path);
    }

}

