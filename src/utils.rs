use dns_lookup;
use std::net::IpAddr;
use crate::error::*;
use ascii::AsciiString;

pub fn resolve_realm_kdc(realm: &AsciiString) -> KerberosResult<IpAddr> {
    let ips = dns_lookup::lookup_host(&realm.to_string()).map_err(|_|
        KerberosErrorKind::NameResolutionError(realm.to_string())
    )?;

    if ips.len() == 0 {
        return Err(KerberosErrorKind::NameResolutionError(realm.to_string()))?;
    }

    return Ok(ips[0]);
}



