use super::ConvertResult;
use super::{
    address_vector_to_host_addresses, keyblock_to_encryption_key,
    principal_to_realm_and_principal_name,
    times_to_authtime_starttime_endtime_renew_till, tktflags_to_ticket_flags,
};
use crate::Credential;
use kerberos_asn1::{Asn1Object, KrbCredInfo, Ticket};

pub fn credential_to_krb_cred_info_and_ticket(
    credential: Credential,
) -> ConvertResult<(KrbCredInfo, Ticket)> {
    let (authtime, starttime, endtime, renew_till) =
        times_to_authtime_starttime_endtime_renew_till(&credential.time);

    let ticket_flags = tktflags_to_ticket_flags(credential.tktflags);

    let encryption_key = keyblock_to_encryption_key(credential.key);

    let (crealm, cname) =
        principal_to_realm_and_principal_name(credential.client)?;

    let (srealm, sname) =
        principal_to_realm_and_principal_name(credential.server)?;

    let caddr_result = address_vector_to_host_addresses(credential.addrs);

    let ticket_bytes = &credential.ticket.data;
    let (_, ticket) = Ticket::parse(ticket_bytes)?;

    let mut krb_cred_info = KrbCredInfo {
        key: encryption_key,
        prealm: Some(crealm),
        pname: Some(cname),
        flags: Some(ticket_flags),
        authtime: Some(authtime),
        starttime: Some(starttime),
        endtime: Some(endtime),
        renew_till: renew_till,
        srealm: Some(srealm),
        sname: Some(sname),
        caddr: None,
    };

    if let Ok(caddr) = caddr_result {
        krb_cred_info.caddr = Some(caddr);
    }

    return Ok((krb_cred_info, ticket));
}

