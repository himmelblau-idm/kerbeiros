use crate::structs_asn1::*;
use crate::constants::*;
use std::fs::File;
use crate::error::*;
use failure::ResultExt;
use std::io::Write;

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

    pub fn save_to_file(&self, path: String) -> KerberosResult<()> {
        let data = self.build_krb_cred();

        let mut fp = File::create(path).context(
            KerberosErrorKind::IOError
        )?;

        fp.write_all(&data).context(
            KerberosErrorKind::IOError
        )?;

        return Ok(());
    }

    fn build_krb_cred(&self) -> Vec<u8> {
        return self.to_krb_cred().build();
    }

    fn to_krb_cred(&self) -> KrbCred {
        let mut seq_of_tickets = SeqOfTickets::new_empty();
        seq_of_tickets.push(self.ticket.clone());

        return KrbCred::new(
            seq_of_tickets,
            EncryptedData::new(NO_ENCRYPTION, self.to_enc_krb_cred_part().build())
        );

    }

    fn to_krb_info(&self) -> KrbCredInfo {
        let mut krb_cred_info = self.client_part.to_krb_cred_info();

        krb_cred_info.set_prealm(self.crealm.clone());
        krb_cred_info.set_pname(self.cname.clone());
        return krb_cred_info;
    }

    fn to_enc_krb_cred_part(&self) -> EncKrbCredPart {
        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::new_empty();
        seq_of_krb_cred_info.push(self.to_krb_info());

        let enc_krb_cred_part = EncKrbCredPart::new(
            seq_of_krb_cred_info
        );

        return enc_krb_cred_part;
    }

}


hacer test de convertir credencial en krb-cred, igual credencial solo debería devolver el ticket y el krb-info y que otra entidad se encargase de recolectarlas y guardas/cargalas de fichero...