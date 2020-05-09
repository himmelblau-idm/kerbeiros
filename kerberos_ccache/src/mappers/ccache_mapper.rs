use super::{
    credential_to_krb_cred_info_and_ticket,
    krb_cred_info_and_ticket_to_credential,
    realm_and_principal_name_to_principal,
};
use crate::{ConvertError, ConvertResult};
use crate::{CCache, Header};
use kerberos_asn1::{Asn1Object, EncKrbCredPart, EncryptedData, KrbCred};
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
        cipher: enc_krb_cred_part.build(),
    };

    return Ok(krb_cred);
}

pub fn krb_cred_to_ccache(krb_cred: KrbCred) -> ConvertResult<CCache> {
    if krb_cred.enc_part.etype != NO_ENCRYPTION {
        return Err(ConvertError::KrbCredError(
            "User part is encrypted".into(),
        ));
    }

    let (_, enc_krb_cred_part) =
        EncKrbCredPart::parse(&krb_cred.enc_part.cipher)?;

    if krb_cred.tickets.len() == 0 || enc_krb_cred_part.ticket_info.len() == 0 {
        return Err(ConvertError::KrbCredError(
            "No credentials contained".into(),
        ));
    }

    let ticket_infos = enc_krb_cred_part.ticket_info;

    let realm_primary = &(&ticket_infos[0]).prealm.as_ref()
        .ok_or(ConvertError::MissingField("prealm".into()))?;

    let principal_name_primary = &(&ticket_infos[0]).pname.as_ref()
        .ok_or(ConvertError::MissingField("pname".into()))?;

    let primary_principal = realm_and_principal_name_to_principal(
        realm_primary,
        principal_name_primary,
    );

    let mut credentials = Vec::new();

    for (krb_cred_info, ticket) in
        ticket_infos.into_iter().zip(krb_cred.tickets)
    {
        let credential = krb_cred_info_and_ticket_to_credential(krb_cred_info, ticket)?;

        credentials.push(credential);
    }

    return Ok(CCache::new(
        Header::default(),
        primary_principal,
        credentials,
    ));
}
