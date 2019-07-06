use super::credential::*;
use crate::error::*;
use crate::structs_asn1::*;
use crate::constants::*;
use std::fs::File;
use failure::ResultExt;
use std::io::Write;

pub struct CredentialFileConverter {
}

impl CredentialFileConverter {

    pub fn save_into_krb_cred_file(credentials: &[Credential], path: String) -> KerberosResult<()> {
        let data = Self::build_krb_cred(credentials);
        return Self::save_data_to_file(path, &data);
    }

    fn save_data_to_file(path: String, data: &[u8]) -> KerberosResult<()> {
        let mut fp = File::create(path).context(
            KerberosErrorKind::IOError
        )?;

        fp.write_all(data).context(
            KerberosErrorKind::IOError
        )?;

        return Ok(());
    }

    fn build_krb_cred(credentials: &[Credential]) -> Vec<u8> {
        return Self::to_krb_cred(credentials).build();
    }

    fn to_krb_cred(credentials: &[Credential]) -> KrbCred {
        let mut seq_of_tickets = SeqOfTickets::new_empty();
        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::new_empty();

        for credential in credentials.iter() {
            seq_of_tickets.push(credential.get_ticket().clone());
            seq_of_krb_cred_info.push(credential.to_krb_info());
        }
        
        let enc_krb_cred_part = EncKrbCredPart::new(
            seq_of_krb_cred_info
        );

        return KrbCred::new(
            seq_of_tickets,
            EncryptedData::new(NO_ENCRYPTION, enc_krb_cred_part.build())
        )
    }

}

hacer test de convertir credencial en krb-cred