use super::credential_to_krb_cred_info_and_ticket;
use super::ConvertResult;
use kerberos_asn1::{KrbCred, EncKrbCredPart, EncryptedData, Asn1Object};
use crate::CCache;
use kerberos_constants::etypes::NO_ENCRYPTION;

pub fn ccache_to_krb_cred(ccache: CCache) -> ConvertResult<KrbCred> {

    let mut infos = Vec::new();
    let mut tickets = Vec::new();

    for credential in ccache.credentials {
        let (krb_cred_info, ticket) =
            credential_to_krb_cred_info_and_ticket(credential)?;

        infos.push(krb_cred_info);
        tickets.push(ticket);
    }

    let mut enc_krb_cred_part = EncKrbCredPart::default();
    enc_krb_cred_part.ticket_info = infos;

    let mut krb_cred = KrbCred::default();
    krb_cred.tickets = tickets;
    krb_cred.enc_part = EncryptedData {
        etype: NO_ENCRYPTION,
        kvno: None,
        cipher: enc_krb_cred_part.build()
    };

    
    return Ok(krb_cred);
}

