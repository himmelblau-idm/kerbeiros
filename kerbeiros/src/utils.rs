//! Implement functions that can be useful to support the main library functionality.

use crate::{Error, Result};
use ascii::AsciiString;
use dns_lookup;
use std::net::IpAddr;

/// Resolve the address of the KDC from the name of the realm.
///
/// # Errors
/// Returns [`Error`](../error/struct.Error.html) if it is not possible to resolve the domain name or the resolution does not include any IP address.
pub fn resolve_realm_kdc(realm: &AsciiString) -> Result<IpAddr> {
    let ips = dns_lookup::lookup_host(realm.as_ref())
        .map_err(|_| Error::NameResolutionError(realm.to_string()))?;

    if ips.is_empty() {
        return Err(Error::NameResolutionError(realm.to_string()));
    }

    return Ok(ips[0]);
}
