use super::credential::Credential;
use super::file::CredentialFileConverter;
use super::mappers::CredentialWarehouseKrbCredMapper;
use crate::error;
use crate::mappers::PrincipalMapper;
use getset::Getters;
use kerberos_asn1::{KrbCred, PrincipalName, Realm};
use kerberos_ccache::{CCache, Header};
use std::convert::TryFrom;
///
/// # Example
/// Load from ccache file:
/// ```no_run
/// use kerbeiros::credentials::CredentialWarehouse;
/// use kerberos_ccache::CCache;
/// use std::convert::TryFrom;
/// use std::fs;
///
/// let file_data = fs::read("./bob_tgt.ccache").expect("Unable to read file");
///
/// let ccache = CCache::parse(&file_data).expect("Unable to parse file content").1;
/// let credentials = CredentialWarehouse::try_from(ccache).expect("Unable to parse CCache");
/// ```

/// To store several credentials related to the same user and realm
#[derive(Debug, PartialEq, Clone, Getters)]
#[getset(get = "pub")]
pub struct CredentialWarehouse {
    credentials: Vec<Credential>,
    realm: Realm,
    client: PrincipalName,
}

impl CredentialWarehouse {
    pub fn new(
        realm: Realm,
        client: PrincipalName,
        credentials: Vec<Credential>,
    ) -> Self {
        return Self {
            realm,
            client,
            credentials,
        };
    }

    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn into_krb_cred(&self) -> KrbCred {
        return CredentialWarehouseKrbCredMapper::credential_warehouse_to_krb_cred(self);
    }

    /// Saves the credentials into a file by using the ccache format, used by Linux.
    pub fn save_into_ccache_file(&self, path: &str) -> error::Result<()> {
        return CredentialFileConverter::save_into_ccache_file(self, path);
    }

    /// Saves the credentials into a file by using the KRB-CRED format, used by Windows.
    pub fn save_into_krb_cred_file(&self, path: &str) -> error::Result<()> {
        return CredentialFileConverter::save_into_krb_cred_file(self, path);
    }
}

impl From<Credential> for CredentialWarehouse {
    fn from(credential: Credential) -> Self {
        return Self::new(
            credential.crealm().clone(),
            credential.cname().clone(),
            vec![credential],
        );
    }
}

impl TryFrom<CCache> for CredentialWarehouse {
    type Error = error::Error;

    fn try_from(ccache: CCache) -> Result<Self, Self::Error> {
        let (realm, client) =
            PrincipalMapper::principal_to_realm_and_principal_name(
                ccache.primary_principal,
            )?;

        let ccache_credentials = ccache.credentials;
        let mut credentials = Vec::with_capacity(ccache_credentials.len());

        for credential_entry in ccache_credentials.into_iter() {
            let credential = Credential::try_from(credential_entry)?;
            credentials.push(credential);
        }

        return Ok(CredentialWarehouse::new(realm, client, credentials));
    }
}

impl From<CredentialWarehouse> for CCache {
    fn from(val: CredentialWarehouse) -> Self {
        let header = Header::default();
        let primary_principal =
            PrincipalMapper::realm_and_principal_name_to_principal(
                val.realm(),
                val.client(),
            );

        let credentials = val.credentials();

        let mut ccache_credentials = Vec::with_capacity(credentials.len());

        for credential in credentials.iter() {
            ccache_credentials.push(credential.clone().into());
        }

        let ccache = CCache::new(header, primary_principal, ccache_credentials);

        return ccache;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use kerberos_asn1::*;
    use kerberos_ccache as ccache;
    use kerberos_constants::etypes::*;
    use kerberos_constants::principal_names::*;
    use kerberos_constants::ticket_flags;

    fn create_credential(
        encryption_key: EncryptionKey,
        prealm: Realm,
        pname: PrincipalName,
        ticket_flags: TicketFlags,
        authtime: KerberosTime,
        starttime: KerberosTime,
        endtime: KerberosTime,
        renew_till: KerberosTime,
        srealm: Realm,
        sname: PrincipalName,
        caddr: Option<HostAddresses>,
        ticket: Ticket,
    ) -> Credential {
        let nonce = 0;
        let enc_as_rep_part = EncAsRepPart {
            key: encryption_key,
            last_req: LastReq::default(),
            nonce,
            key_expiration: None,
            flags: ticket_flags,
            authtime,
            starttime: Some(starttime),
            endtime,
            renew_till: Some(renew_till),
            srealm: srealm.clone(),
            sname: sname.clone(),
            caddr: caddr,
            encrypted_pa_data: None,
        };

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket,
            enc_as_rep_part,
        );

        return credential;
    }

    static RAW_TICKET: &'static [u8] = &[
        0x61, 0x82, 0x04, 0x13, 0x30, 0x82, 0x04, 0x0f, 0xa0, 0x03, 0x02, 0x01,
        0x05, 0xa1, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d,
        0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa2, 0x23, 0x30, 0x21, 0xa0,
        0x03, 0x02, 0x01, 0x01, 0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72,
        0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
        0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0xa3, 0x82, 0x03, 0xcf,
        0x30, 0x82, 0x03, 0xcb, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x03, 0x02,
        0x01, 0x02, 0xa2, 0x82, 0x03, 0xbd, 0x04, 0x82, 0x03, 0xb9, 0x0a, 0x33,
        0x84, 0xdb, 0x8b, 0x31, 0x15, 0x29, 0x20, 0x37, 0xe5, 0xe7, 0xb0, 0x50,
        0x1f, 0xbe, 0x91, 0x11, 0xff, 0x69, 0x28, 0x6f, 0xc4, 0x9e, 0x79, 0xf8,
        0x79, 0x88, 0xb1, 0x7b, 0xcd, 0xc5, 0xe1, 0x87, 0x91, 0xf8, 0x44, 0x95,
        0x2f, 0x35, 0x0e, 0xe9, 0xd5, 0x83, 0x74, 0x18, 0x2b, 0x84, 0xe0, 0xa8,
        0xd1, 0x21, 0xcf, 0xe0, 0x40, 0x42, 0x63, 0xb7, 0x42, 0x60, 0xe8, 0x3d,
        0x56, 0x2a, 0x08, 0x96, 0x39, 0x8e, 0x1f, 0xfa, 0xb2, 0x11, 0x35, 0x09,
        0x61, 0xba, 0xdd, 0x8e, 0xfc, 0x71, 0xf9, 0x0f, 0x39, 0x46, 0x43, 0x50,
        0xd9, 0x32, 0x24, 0xcc, 0x64, 0xa1, 0x46, 0xe0, 0x1b, 0x86, 0x0f, 0xac,
        0x86, 0x6e, 0x64, 0xcc, 0x01, 0x1f, 0xcd, 0x50, 0xb3, 0xa0, 0x43, 0x93,
        0x83, 0x9c, 0x6e, 0x73, 0xec, 0xee, 0x7f, 0x8b, 0x52, 0xb3, 0xa3, 0x0b,
        0xcd, 0xbf, 0xd2, 0x51, 0xdf, 0x05, 0x4c, 0x6b, 0x77, 0x99, 0x35, 0x54,
        0x83, 0x9f, 0x29, 0xef, 0x69, 0x7e, 0x31, 0xbd, 0x1a, 0x38, 0x2d, 0x63,
        0xb0, 0x00, 0xb2, 0x42, 0x9c, 0x3e, 0xe9, 0x82, 0x29, 0xde, 0xfd, 0xb7,
        0x9d, 0x4c, 0x89, 0x28, 0xdf, 0xac, 0xab, 0x36, 0x85, 0xda, 0xd0, 0x03,
        0x05, 0xa4, 0x12, 0x24, 0x3a, 0x18, 0xf7, 0xdb, 0xbe, 0x2a, 0xd8, 0x8d,
        0xaa, 0x2c, 0x76, 0xe7, 0x21, 0xe7, 0x6c, 0xde, 0x02, 0x17, 0xc6, 0x4c,
        0xfe, 0x49, 0x0e, 0xb2, 0x4a, 0x65, 0xd5, 0x44, 0xee, 0x3f, 0xef, 0x1a,
        0x43, 0x54, 0xfa, 0xd2, 0x9e, 0xd9, 0xf4, 0xbf, 0x40, 0x93, 0x3b, 0x1e,
        0x92, 0x9f, 0x1e, 0xcf, 0x9a, 0xbe, 0xdc, 0xfc, 0xd4, 0xd0, 0xcc, 0x29,
        0xe5, 0x51, 0xf8, 0x94, 0xde, 0xe8, 0xa6, 0x2e, 0x20, 0x60, 0xed, 0xdd,
        0x51, 0x07, 0xd1, 0xbe, 0x5f, 0x65, 0x45, 0x7e, 0x96, 0x47, 0xa3, 0x29,
        0x67, 0x22, 0x66, 0x35, 0x61, 0xa7, 0x39, 0x18, 0x19, 0x35, 0x9f, 0xe4,
        0x74, 0x50, 0xce, 0x2b, 0x41, 0x58, 0xe7, 0x8a, 0x19, 0xbd, 0x2f, 0x4d,
        0x76, 0x37, 0xed, 0xa4, 0x93, 0x00, 0xd7, 0x0b, 0x2b, 0xea, 0x45, 0x46,
        0x8b, 0xc0, 0xaa, 0x7d, 0xb5, 0xd9, 0x61, 0x73, 0x3b, 0x6a, 0xc5, 0x5a,
        0x93, 0xef, 0xee, 0xb9, 0xe4, 0x10, 0x37, 0xbd, 0xf0, 0x96, 0x70, 0x98,
        0x85, 0xb8, 0x99, 0x8c, 0x53, 0x94, 0x38, 0x66, 0x18, 0x34, 0x1b, 0x3b,
        0x08, 0x0e, 0xd0, 0x4b, 0x9c, 0x03, 0x54, 0xe5, 0x6b, 0x7e, 0x66, 0xd6,
        0x74, 0x2b, 0xca, 0x9a, 0xaa, 0x3a, 0xc1, 0x3e, 0xc9, 0xf5, 0x75, 0x1c,
        0xff, 0xc2, 0xdf, 0x1e, 0xd7, 0x0b, 0xca, 0x55, 0x4c, 0x50, 0x2b, 0x80,
        0x89, 0xde, 0x2c, 0x51, 0x8d, 0x4c, 0x3f, 0x8b, 0x16, 0x22, 0xec, 0x3e,
        0x04, 0x05, 0x58, 0xae, 0x09, 0xe6, 0x80, 0x02, 0x21, 0xac, 0xee, 0x86,
        0x1f, 0xbb, 0xb0, 0x91, 0x69, 0xb9, 0x15, 0xdf, 0xb9, 0x86, 0xe5, 0xcf,
        0xc1, 0x0e, 0xb7, 0x92, 0xb8, 0xe4, 0x55, 0x4d, 0x00, 0x90, 0xb6, 0xb0,
        0x67, 0x28, 0x1d, 0xcd, 0x4b, 0x57, 0x98, 0x86, 0x7f, 0xee, 0x60, 0x17,
        0x00, 0x0b, 0x1a, 0xf7, 0x02, 0xac, 0x37, 0xd5, 0x9b, 0xfc, 0xfa, 0xa2,
        0x1f, 0xaa, 0x9a, 0x88, 0xa2, 0xbc, 0x10, 0xbd, 0xb8, 0x4f, 0xb8, 0xa6,
        0x5b, 0xab, 0x0b, 0x25, 0x57, 0xad, 0xe4, 0x91, 0xbb, 0x05, 0x39, 0x68,
        0xfe, 0x91, 0x6a, 0xdf, 0xb0, 0x05, 0x68, 0x7e, 0x76, 0xc2, 0x04, 0x72,
        0x71, 0x36, 0x56, 0x87, 0x1f, 0x88, 0x7a, 0x1f, 0xc5, 0x22, 0x5a, 0x1a,
        0x3d, 0x0b, 0x7b, 0x21, 0x32, 0xf3, 0x4f, 0xc4, 0x5a, 0x09, 0xa1, 0x9e,
        0x9c, 0x16, 0xa7, 0x5d, 0xc0, 0xc8, 0x94, 0x47, 0x28, 0xad, 0x94, 0xac,
        0x79, 0x16, 0xeb, 0x54, 0x71, 0x4c, 0x98, 0x92, 0x68, 0x8a, 0x3f, 0xd8,
        0xb5, 0xc9, 0x70, 0x20, 0x4a, 0x4e, 0xb2, 0x57, 0x7c, 0x95, 0x99, 0xed,
        0xb7, 0x29, 0x3a, 0x39, 0x81, 0x84, 0xe6, 0x33, 0x90, 0x8c, 0xfd, 0x0c,
        0xbc, 0x4f, 0x9d, 0x6a, 0xd0, 0xde, 0x05, 0x60, 0x3d, 0x9f, 0x1a, 0xa7,
        0x71, 0xa3, 0x2f, 0x83, 0x77, 0x4e, 0xb0, 0x11, 0x80, 0x05, 0xb4, 0xd0,
        0x00, 0x82, 0x73, 0x64, 0x68, 0xae, 0xbc, 0x20, 0x1a, 0x2a, 0x8a, 0x18,
        0x48, 0x43, 0xbf, 0x32, 0x64, 0x6b, 0xad, 0x66, 0x78, 0x8e, 0x24, 0xb1,
        0x5f, 0xf7, 0xd7, 0x2d, 0x9a, 0x86, 0x9e, 0x25, 0x12, 0x8d, 0x90, 0x00,
        0x32, 0x46, 0x70, 0x34, 0xcb, 0x9d, 0xa9, 0x3c, 0x84, 0x4c, 0x60, 0xc4,
        0x4c, 0x39, 0xf0, 0x4c, 0xfb, 0x8e, 0x91, 0xb7, 0x3b, 0xbf, 0xb0, 0xe9,
        0xf4, 0xa3, 0x9b, 0x7b, 0x57, 0xcf, 0xd9, 0xfb, 0x46, 0x81, 0xa9, 0xd5,
        0x8f, 0x54, 0xc2, 0x2b, 0xc2, 0x35, 0x4d, 0xb0, 0xc3, 0x84, 0xd4, 0x97,
        0x07, 0x6e, 0x3c, 0xa5, 0xe6, 0x40, 0xac, 0xad, 0x2b, 0xf9, 0xff, 0x62,
        0x68, 0xea, 0x69, 0x41, 0x31, 0xe6, 0x31, 0x69, 0x40, 0x69, 0x1f, 0x3a,
        0x03, 0x9b, 0x15, 0xd3, 0x19, 0x16, 0x7d, 0x87, 0xa0, 0xbb, 0xb2, 0xaf,
        0x5c, 0x91, 0xd4, 0x41, 0x7c, 0x85, 0xcd, 0xbe, 0x1a, 0x99, 0xab, 0xf7,
        0x9c, 0xeb, 0x1a, 0x8f, 0x0b, 0x97, 0xf1, 0xda, 0xc0, 0xe5, 0x18, 0xb1,
        0xbe, 0x08, 0x20, 0x7d, 0x27, 0x75, 0x0c, 0xc9, 0x15, 0xee, 0x07, 0x18,
        0x4b, 0x17, 0x6c, 0x90, 0xb9, 0x26, 0x83, 0xd0, 0x93, 0x0d, 0x5d, 0x6c,
        0x7a, 0xa9, 0x32, 0xa5, 0x49, 0xd8, 0x32, 0xc8, 0xc0, 0x3f, 0x8a, 0x43,
        0x6d, 0xb4, 0xe4, 0xe6, 0xe7, 0x60, 0x18, 0x40, 0xc7, 0x48, 0x69, 0xfb,
        0x37, 0xfc, 0x77, 0x84, 0x6a, 0x8a, 0xb6, 0x2d, 0xf4, 0xce, 0x62, 0xda,
        0x14, 0xe2, 0x60, 0xd0, 0x1b, 0xfd, 0xfa, 0x74, 0xde, 0xf9, 0xe8, 0xdc,
        0x55, 0xcd, 0x31, 0x87, 0xd6, 0xa0, 0xf7, 0x96, 0xc8, 0x65, 0x31, 0xf9,
        0x0a, 0x86, 0x73, 0x7f, 0x8e, 0xa7, 0xf7, 0xa1, 0x77, 0x54, 0x91, 0x9a,
        0xd1, 0x05, 0x7c, 0xc2, 0xd7, 0xdb, 0x41, 0x63, 0x5c, 0x9b, 0xc9, 0x21,
        0x5e, 0x8f, 0x53, 0xcf, 0xfd, 0xba, 0x9c, 0x0b, 0xde, 0xe4, 0xea, 0x3e,
        0x42, 0x51, 0xc6, 0x56, 0x13, 0xe2, 0x5b, 0x3e, 0xee, 0x8b, 0x21, 0xe2,
        0x77, 0xd4, 0x81, 0x42, 0x8a, 0xa6, 0xc3, 0x2e, 0xa5, 0xe8, 0x05, 0xf4,
        0x17, 0xd3, 0x2c, 0x34, 0x89, 0x42, 0x0a, 0xcb, 0x0b, 0xd7, 0xbf, 0x4e,
        0x35, 0x3b, 0x28, 0x38, 0x16, 0xc9, 0x43, 0xae, 0x3e, 0xd7, 0xb1, 0x25,
        0x61, 0x42, 0xe7, 0xbb, 0x5f, 0xf0, 0x2d, 0xc7, 0x20, 0x0f, 0xdf, 0xe6,
        0x3c, 0x3d, 0x46, 0x0a, 0xae, 0xee, 0xa3, 0xc6, 0x59, 0x04, 0x25, 0xd2,
        0x3d, 0x3c, 0xce, 0xe6, 0x05, 0xc3, 0xab, 0xbc, 0xb5, 0xaf, 0x75, 0x96,
        0xdf, 0xb6, 0x13, 0x7a, 0x0a, 0xfb, 0x6e, 0xb2, 0x80, 0x16, 0xc5, 0xd4,
        0x75, 0x81, 0x1d, 0x1e, 0x26, 0xf5, 0x1f, 0x14, 0x75, 0x4a, 0xde, 0x3d,
        0x65, 0x6e, 0xb7, 0x13, 0x3c, 0x8d, 0xbe, 0x40, 0xbe, 0xa0, 0x15, 0xd8,
        0x36, 0xd8, 0x88,
    ];

    static RAW_TICKET_ENCRYPTED: &'static [u8] = &[
        0x0a, 0x33, 0x84, 0xdb, 0x8b, 0x31, 0x15, 0x29, 0x20, 0x37, 0xe5, 0xe7,
        0xb0, 0x50, 0x1f, 0xbe, 0x91, 0x11, 0xff, 0x69, 0x28, 0x6f, 0xc4, 0x9e,
        0x79, 0xf8, 0x79, 0x88, 0xb1, 0x7b, 0xcd, 0xc5, 0xe1, 0x87, 0x91, 0xf8,
        0x44, 0x95, 0x2f, 0x35, 0x0e, 0xe9, 0xd5, 0x83, 0x74, 0x18, 0x2b, 0x84,
        0xe0, 0xa8, 0xd1, 0x21, 0xcf, 0xe0, 0x40, 0x42, 0x63, 0xb7, 0x42, 0x60,
        0xe8, 0x3d, 0x56, 0x2a, 0x08, 0x96, 0x39, 0x8e, 0x1f, 0xfa, 0xb2, 0x11,
        0x35, 0x09, 0x61, 0xba, 0xdd, 0x8e, 0xfc, 0x71, 0xf9, 0x0f, 0x39, 0x46,
        0x43, 0x50, 0xd9, 0x32, 0x24, 0xcc, 0x64, 0xa1, 0x46, 0xe0, 0x1b, 0x86,
        0x0f, 0xac, 0x86, 0x6e, 0x64, 0xcc, 0x01, 0x1f, 0xcd, 0x50, 0xb3, 0xa0,
        0x43, 0x93, 0x83, 0x9c, 0x6e, 0x73, 0xec, 0xee, 0x7f, 0x8b, 0x52, 0xb3,
        0xa3, 0x0b, 0xcd, 0xbf, 0xd2, 0x51, 0xdf, 0x05, 0x4c, 0x6b, 0x77, 0x99,
        0x35, 0x54, 0x83, 0x9f, 0x29, 0xef, 0x69, 0x7e, 0x31, 0xbd, 0x1a, 0x38,
        0x2d, 0x63, 0xb0, 0x00, 0xb2, 0x42, 0x9c, 0x3e, 0xe9, 0x82, 0x29, 0xde,
        0xfd, 0xb7, 0x9d, 0x4c, 0x89, 0x28, 0xdf, 0xac, 0xab, 0x36, 0x85, 0xda,
        0xd0, 0x03, 0x05, 0xa4, 0x12, 0x24, 0x3a, 0x18, 0xf7, 0xdb, 0xbe, 0x2a,
        0xd8, 0x8d, 0xaa, 0x2c, 0x76, 0xe7, 0x21, 0xe7, 0x6c, 0xde, 0x02, 0x17,
        0xc6, 0x4c, 0xfe, 0x49, 0x0e, 0xb2, 0x4a, 0x65, 0xd5, 0x44, 0xee, 0x3f,
        0xef, 0x1a, 0x43, 0x54, 0xfa, 0xd2, 0x9e, 0xd9, 0xf4, 0xbf, 0x40, 0x93,
        0x3b, 0x1e, 0x92, 0x9f, 0x1e, 0xcf, 0x9a, 0xbe, 0xdc, 0xfc, 0xd4, 0xd0,
        0xcc, 0x29, 0xe5, 0x51, 0xf8, 0x94, 0xde, 0xe8, 0xa6, 0x2e, 0x20, 0x60,
        0xed, 0xdd, 0x51, 0x07, 0xd1, 0xbe, 0x5f, 0x65, 0x45, 0x7e, 0x96, 0x47,
        0xa3, 0x29, 0x67, 0x22, 0x66, 0x35, 0x61, 0xa7, 0x39, 0x18, 0x19, 0x35,
        0x9f, 0xe4, 0x74, 0x50, 0xce, 0x2b, 0x41, 0x58, 0xe7, 0x8a, 0x19, 0xbd,
        0x2f, 0x4d, 0x76, 0x37, 0xed, 0xa4, 0x93, 0x00, 0xd7, 0x0b, 0x2b, 0xea,
        0x45, 0x46, 0x8b, 0xc0, 0xaa, 0x7d, 0xb5, 0xd9, 0x61, 0x73, 0x3b, 0x6a,
        0xc5, 0x5a, 0x93, 0xef, 0xee, 0xb9, 0xe4, 0x10, 0x37, 0xbd, 0xf0, 0x96,
        0x70, 0x98, 0x85, 0xb8, 0x99, 0x8c, 0x53, 0x94, 0x38, 0x66, 0x18, 0x34,
        0x1b, 0x3b, 0x08, 0x0e, 0xd0, 0x4b, 0x9c, 0x03, 0x54, 0xe5, 0x6b, 0x7e,
        0x66, 0xd6, 0x74, 0x2b, 0xca, 0x9a, 0xaa, 0x3a, 0xc1, 0x3e, 0xc9, 0xf5,
        0x75, 0x1c, 0xff, 0xc2, 0xdf, 0x1e, 0xd7, 0x0b, 0xca, 0x55, 0x4c, 0x50,
        0x2b, 0x80, 0x89, 0xde, 0x2c, 0x51, 0x8d, 0x4c, 0x3f, 0x8b, 0x16, 0x22,
        0xec, 0x3e, 0x04, 0x05, 0x58, 0xae, 0x09, 0xe6, 0x80, 0x02, 0x21, 0xac,
        0xee, 0x86, 0x1f, 0xbb, 0xb0, 0x91, 0x69, 0xb9, 0x15, 0xdf, 0xb9, 0x86,
        0xe5, 0xcf, 0xc1, 0x0e, 0xb7, 0x92, 0xb8, 0xe4, 0x55, 0x4d, 0x00, 0x90,
        0xb6, 0xb0, 0x67, 0x28, 0x1d, 0xcd, 0x4b, 0x57, 0x98, 0x86, 0x7f, 0xee,
        0x60, 0x17, 0x00, 0x0b, 0x1a, 0xf7, 0x02, 0xac, 0x37, 0xd5, 0x9b, 0xfc,
        0xfa, 0xa2, 0x1f, 0xaa, 0x9a, 0x88, 0xa2, 0xbc, 0x10, 0xbd, 0xb8, 0x4f,
        0xb8, 0xa6, 0x5b, 0xab, 0x0b, 0x25, 0x57, 0xad, 0xe4, 0x91, 0xbb, 0x05,
        0x39, 0x68, 0xfe, 0x91, 0x6a, 0xdf, 0xb0, 0x05, 0x68, 0x7e, 0x76, 0xc2,
        0x04, 0x72, 0x71, 0x36, 0x56, 0x87, 0x1f, 0x88, 0x7a, 0x1f, 0xc5, 0x22,
        0x5a, 0x1a, 0x3d, 0x0b, 0x7b, 0x21, 0x32, 0xf3, 0x4f, 0xc4, 0x5a, 0x09,
        0xa1, 0x9e, 0x9c, 0x16, 0xa7, 0x5d, 0xc0, 0xc8, 0x94, 0x47, 0x28, 0xad,
        0x94, 0xac, 0x79, 0x16, 0xeb, 0x54, 0x71, 0x4c, 0x98, 0x92, 0x68, 0x8a,
        0x3f, 0xd8, 0xb5, 0xc9, 0x70, 0x20, 0x4a, 0x4e, 0xb2, 0x57, 0x7c, 0x95,
        0x99, 0xed, 0xb7, 0x29, 0x3a, 0x39, 0x81, 0x84, 0xe6, 0x33, 0x90, 0x8c,
        0xfd, 0x0c, 0xbc, 0x4f, 0x9d, 0x6a, 0xd0, 0xde, 0x05, 0x60, 0x3d, 0x9f,
        0x1a, 0xa7, 0x71, 0xa3, 0x2f, 0x83, 0x77, 0x4e, 0xb0, 0x11, 0x80, 0x05,
        0xb4, 0xd0, 0x00, 0x82, 0x73, 0x64, 0x68, 0xae, 0xbc, 0x20, 0x1a, 0x2a,
        0x8a, 0x18, 0x48, 0x43, 0xbf, 0x32, 0x64, 0x6b, 0xad, 0x66, 0x78, 0x8e,
        0x24, 0xb1, 0x5f, 0xf7, 0xd7, 0x2d, 0x9a, 0x86, 0x9e, 0x25, 0x12, 0x8d,
        0x90, 0x00, 0x32, 0x46, 0x70, 0x34, 0xcb, 0x9d, 0xa9, 0x3c, 0x84, 0x4c,
        0x60, 0xc4, 0x4c, 0x39, 0xf0, 0x4c, 0xfb, 0x8e, 0x91, 0xb7, 0x3b, 0xbf,
        0xb0, 0xe9, 0xf4, 0xa3, 0x9b, 0x7b, 0x57, 0xcf, 0xd9, 0xfb, 0x46, 0x81,
        0xa9, 0xd5, 0x8f, 0x54, 0xc2, 0x2b, 0xc2, 0x35, 0x4d, 0xb0, 0xc3, 0x84,
        0xd4, 0x97, 0x07, 0x6e, 0x3c, 0xa5, 0xe6, 0x40, 0xac, 0xad, 0x2b, 0xf9,
        0xff, 0x62, 0x68, 0xea, 0x69, 0x41, 0x31, 0xe6, 0x31, 0x69, 0x40, 0x69,
        0x1f, 0x3a, 0x03, 0x9b, 0x15, 0xd3, 0x19, 0x16, 0x7d, 0x87, 0xa0, 0xbb,
        0xb2, 0xaf, 0x5c, 0x91, 0xd4, 0x41, 0x7c, 0x85, 0xcd, 0xbe, 0x1a, 0x99,
        0xab, 0xf7, 0x9c, 0xeb, 0x1a, 0x8f, 0x0b, 0x97, 0xf1, 0xda, 0xc0, 0xe5,
        0x18, 0xb1, 0xbe, 0x08, 0x20, 0x7d, 0x27, 0x75, 0x0c, 0xc9, 0x15, 0xee,
        0x07, 0x18, 0x4b, 0x17, 0x6c, 0x90, 0xb9, 0x26, 0x83, 0xd0, 0x93, 0x0d,
        0x5d, 0x6c, 0x7a, 0xa9, 0x32, 0xa5, 0x49, 0xd8, 0x32, 0xc8, 0xc0, 0x3f,
        0x8a, 0x43, 0x6d, 0xb4, 0xe4, 0xe6, 0xe7, 0x60, 0x18, 0x40, 0xc7, 0x48,
        0x69, 0xfb, 0x37, 0xfc, 0x77, 0x84, 0x6a, 0x8a, 0xb6, 0x2d, 0xf4, 0xce,
        0x62, 0xda, 0x14, 0xe2, 0x60, 0xd0, 0x1b, 0xfd, 0xfa, 0x74, 0xde, 0xf9,
        0xe8, 0xdc, 0x55, 0xcd, 0x31, 0x87, 0xd6, 0xa0, 0xf7, 0x96, 0xc8, 0x65,
        0x31, 0xf9, 0x0a, 0x86, 0x73, 0x7f, 0x8e, 0xa7, 0xf7, 0xa1, 0x77, 0x54,
        0x91, 0x9a, 0xd1, 0x05, 0x7c, 0xc2, 0xd7, 0xdb, 0x41, 0x63, 0x5c, 0x9b,
        0xc9, 0x21, 0x5e, 0x8f, 0x53, 0xcf, 0xfd, 0xba, 0x9c, 0x0b, 0xde, 0xe4,
        0xea, 0x3e, 0x42, 0x51, 0xc6, 0x56, 0x13, 0xe2, 0x5b, 0x3e, 0xee, 0x8b,
        0x21, 0xe2, 0x77, 0xd4, 0x81, 0x42, 0x8a, 0xa6, 0xc3, 0x2e, 0xa5, 0xe8,
        0x05, 0xf4, 0x17, 0xd3, 0x2c, 0x34, 0x89, 0x42, 0x0a, 0xcb, 0x0b, 0xd7,
        0xbf, 0x4e, 0x35, 0x3b, 0x28, 0x38, 0x16, 0xc9, 0x43, 0xae, 0x3e, 0xd7,
        0xb1, 0x25, 0x61, 0x42, 0xe7, 0xbb, 0x5f, 0xf0, 0x2d, 0xc7, 0x20, 0x0f,
        0xdf, 0xe6, 0x3c, 0x3d, 0x46, 0x0a, 0xae, 0xee, 0xa3, 0xc6, 0x59, 0x04,
        0x25, 0xd2, 0x3d, 0x3c, 0xce, 0xe6, 0x05, 0xc3, 0xab, 0xbc, 0xb5, 0xaf,
        0x75, 0x96, 0xdf, 0xb6, 0x13, 0x7a, 0x0a, 0xfb, 0x6e, 0xb2, 0x80, 0x16,
        0xc5, 0xd4, 0x75, 0x81, 0x1d, 0x1e, 0x26, 0xf5, 0x1f, 0x14, 0x75, 0x4a,
        0xde, 0x3d, 0x65, 0x6e, 0xb7, 0x13, 0x3c, 0x8d, 0xbe, 0x40, 0xbe, 0xa0,
        0x15, 0xd8, 0x36, 0xd8, 0x88,
    ];

    #[test]
    fn convert_credential_warehouse_to_ccache() {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("krbtgt"));
        sname.push(KerberosString::from("KINGDOM.HEARTS"));

        let pname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let key = ccache::KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let authtime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let starttime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let endtime = Utc.ymd(2019, 7, 8).and_hms(0, 23, 33);
        let renew_till = Utc.ymd(2019, 7, 8).and_hms(14, 23, 30);

        let time = ccache::Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        let ticket_flags = TicketFlags::from(tktflags);

        let mut ticket_encrypted_data = EncryptedData::new(
            AES256_CTS_HMAC_SHA1_96,
            None,
            RAW_TICKET_ENCRYPTED.to_vec(),
        );
        ticket_encrypted_data.kvno = Some(2);

        let ticket_credential =
            Ticket::new(realm.clone(), sname.clone(), ticket_encrypted_data);

        let credential = create_credential(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            authtime.into(),
            starttime.into(),
            endtime.into(),
            renew_till.into(),
            realm.clone(),
            sname.clone(),
            None,
            ticket_credential,
        );

        let credential_warehouse = CredentialWarehouse::from(credential);

        let ticket = ccache::CountedOctetString::new(RAW_TICKET.to_vec());

        let realm_string = ccache::CountedOctetString::new(
            "KINGDOM.HEARTS".as_bytes().to_vec(),
        );

        let client_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![ccache::CountedOctetString::new(
                "mickey".as_bytes().to_vec(),
            )],
        );
        let server_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![
                ccache::CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone(),
            ],
        );

        let is_skey = 0;

        let ccache_credential = ccache::Credential::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket,
        );

        let ccache_header = ccache::Header::new(
            ccache::Header::DELTA_TIME,
            ccache::DeltaTime::new(u32::max_value(), 0).build(),
        );

        let ccache = CCache::new(
            ccache_header,
            client_principal,
            vec![ccache_credential],
        );

        assert_eq!(ccache, credential_warehouse.into());
    }

    #[test]
    fn convert_ccache_to_credential_warehouse() {
        let realm = Realm::from("KINGDOM.HEARTS");

        let mut sname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("krbtgt"));
        sname.push(KerberosString::from("KINGDOM.HEARTS"));

        let pname =
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from("mickey"));

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let key = ccache::KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let authtime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let starttime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let endtime = Utc.ymd(2019, 7, 8).and_hms(0, 23, 33);
        let renew_till = Utc.ymd(2019, 7, 8).and_hms(14, 23, 30);

        let time = ccache::Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        let ticket_flags = TicketFlags::from(tktflags);

        let mut ticket_encrypted_data = EncryptedData::new(
            AES256_CTS_HMAC_SHA1_96,
            None,
            vec![
                0x0a, 0x33, 0x84, 0xdb, 0x8b, 0x31, 0x15, 0x29, 0x20, 0x37,
                0xe5, 0xe7, 0xb0, 0x50, 0x1f, 0xbe, 0x91, 0x11, 0xff, 0x69,
                0x28, 0x6f, 0xc4, 0x9e, 0x79, 0xf8, 0x79, 0x88, 0xb1, 0x7b,
                0xcd, 0xc5, 0xe1, 0x87, 0x91, 0xf8, 0x44, 0x95, 0x2f, 0x35,
                0x0e, 0xe9, 0xd5, 0x83, 0x74, 0x18, 0x2b, 0x84, 0xe0, 0xa8,
                0xd1, 0x21, 0xcf, 0xe0, 0x40, 0x42, 0x63, 0xb7, 0x42, 0x60,
                0xe8, 0x3d, 0x56, 0x2a, 0x08, 0x96, 0x39, 0x8e, 0x1f, 0xfa,
                0xb2, 0x11, 0x35, 0x09, 0x61, 0xba, 0xdd, 0x8e, 0xfc, 0x71,
                0xf9, 0x0f, 0x39, 0x46, 0x43, 0x50, 0xd9, 0x32, 0x24, 0xcc,
                0x64, 0xa1, 0x46, 0xe0, 0x1b, 0x86, 0x0f, 0xac, 0x86, 0x6e,
                0x64, 0xcc, 0x01, 0x1f, 0xcd, 0x50, 0xb3, 0xa0, 0x43, 0x93,
                0x83, 0x9c, 0x6e, 0x73, 0xec, 0xee, 0x7f, 0x8b, 0x52, 0xb3,
                0xa3, 0x0b, 0xcd, 0xbf, 0xd2, 0x51, 0xdf, 0x05, 0x4c, 0x6b,
                0x77, 0x99, 0x35, 0x54, 0x83, 0x9f, 0x29, 0xef, 0x69, 0x7e,
                0x31, 0xbd, 0x1a, 0x38, 0x2d, 0x63, 0xb0, 0x00, 0xb2, 0x42,
                0x9c, 0x3e, 0xe9, 0x82, 0x29, 0xde, 0xfd, 0xb7, 0x9d, 0x4c,
                0x89, 0x28, 0xdf, 0xac, 0xab, 0x36, 0x85, 0xda, 0xd0, 0x03,
                0x05, 0xa4, 0x12, 0x24, 0x3a, 0x18, 0xf7, 0xdb, 0xbe, 0x2a,
                0xd8, 0x8d, 0xaa, 0x2c, 0x76, 0xe7, 0x21, 0xe7, 0x6c, 0xde,
                0x02, 0x17, 0xc6, 0x4c, 0xfe, 0x49, 0x0e, 0xb2, 0x4a, 0x65,
                0xd5, 0x44, 0xee, 0x3f, 0xef, 0x1a, 0x43, 0x54, 0xfa, 0xd2,
                0x9e, 0xd9, 0xf4, 0xbf, 0x40, 0x93, 0x3b, 0x1e, 0x92, 0x9f,
                0x1e, 0xcf, 0x9a, 0xbe, 0xdc, 0xfc, 0xd4, 0xd0, 0xcc, 0x29,
                0xe5, 0x51, 0xf8, 0x94, 0xde, 0xe8, 0xa6, 0x2e, 0x20, 0x60,
                0xed, 0xdd, 0x51, 0x07, 0xd1, 0xbe, 0x5f, 0x65, 0x45, 0x7e,
                0x96, 0x47, 0xa3, 0x29, 0x67, 0x22, 0x66, 0x35, 0x61, 0xa7,
                0x39, 0x18, 0x19, 0x35, 0x9f, 0xe4, 0x74, 0x50, 0xce, 0x2b,
                0x41, 0x58, 0xe7, 0x8a, 0x19, 0xbd, 0x2f, 0x4d, 0x76, 0x37,
                0xed, 0xa4, 0x93, 0x00, 0xd7, 0x0b, 0x2b, 0xea, 0x45, 0x46,
                0x8b, 0xc0, 0xaa, 0x7d, 0xb5, 0xd9, 0x61, 0x73, 0x3b, 0x6a,
                0xc5, 0x5a, 0x93, 0xef, 0xee, 0xb9, 0xe4, 0x10, 0x37, 0xbd,
                0xf0, 0x96, 0x70, 0x98, 0x85, 0xb8, 0x99, 0x8c, 0x53, 0x94,
                0x38, 0x66, 0x18, 0x34, 0x1b, 0x3b, 0x08, 0x0e, 0xd0, 0x4b,
                0x9c, 0x03, 0x54, 0xe5, 0x6b, 0x7e, 0x66, 0xd6, 0x74, 0x2b,
                0xca, 0x9a, 0xaa, 0x3a, 0xc1, 0x3e, 0xc9, 0xf5, 0x75, 0x1c,
                0xff, 0xc2, 0xdf, 0x1e, 0xd7, 0x0b, 0xca, 0x55, 0x4c, 0x50,
                0x2b, 0x80, 0x89, 0xde, 0x2c, 0x51, 0x8d, 0x4c, 0x3f, 0x8b,
                0x16, 0x22, 0xec, 0x3e, 0x04, 0x05, 0x58, 0xae, 0x09, 0xe6,
                0x80, 0x02, 0x21, 0xac, 0xee, 0x86, 0x1f, 0xbb, 0xb0, 0x91,
                0x69, 0xb9, 0x15, 0xdf, 0xb9, 0x86, 0xe5, 0xcf, 0xc1, 0x0e,
                0xb7, 0x92, 0xb8, 0xe4, 0x55, 0x4d, 0x00, 0x90, 0xb6, 0xb0,
                0x67, 0x28, 0x1d, 0xcd, 0x4b, 0x57, 0x98, 0x86, 0x7f, 0xee,
                0x60, 0x17, 0x00, 0x0b, 0x1a, 0xf7, 0x02, 0xac, 0x37, 0xd5,
                0x9b, 0xfc, 0xfa, 0xa2, 0x1f, 0xaa, 0x9a, 0x88, 0xa2, 0xbc,
                0x10, 0xbd, 0xb8, 0x4f, 0xb8, 0xa6, 0x5b, 0xab, 0x0b, 0x25,
                0x57, 0xad, 0xe4, 0x91, 0xbb, 0x05, 0x39, 0x68, 0xfe, 0x91,
                0x6a, 0xdf, 0xb0, 0x05, 0x68, 0x7e, 0x76, 0xc2, 0x04, 0x72,
                0x71, 0x36, 0x56, 0x87, 0x1f, 0x88, 0x7a, 0x1f, 0xc5, 0x22,
                0x5a, 0x1a, 0x3d, 0x0b, 0x7b, 0x21, 0x32, 0xf3, 0x4f, 0xc4,
                0x5a, 0x09, 0xa1, 0x9e, 0x9c, 0x16, 0xa7, 0x5d, 0xc0, 0xc8,
                0x94, 0x47, 0x28, 0xad, 0x94, 0xac, 0x79, 0x16, 0xeb, 0x54,
                0x71, 0x4c, 0x98, 0x92, 0x68, 0x8a, 0x3f, 0xd8, 0xb5, 0xc9,
                0x70, 0x20, 0x4a, 0x4e, 0xb2, 0x57, 0x7c, 0x95, 0x99, 0xed,
                0xb7, 0x29, 0x3a, 0x39, 0x81, 0x84, 0xe6, 0x33, 0x90, 0x8c,
                0xfd, 0x0c, 0xbc, 0x4f, 0x9d, 0x6a, 0xd0, 0xde, 0x05, 0x60,
                0x3d, 0x9f, 0x1a, 0xa7, 0x71, 0xa3, 0x2f, 0x83, 0x77, 0x4e,
                0xb0, 0x11, 0x80, 0x05, 0xb4, 0xd0, 0x00, 0x82, 0x73, 0x64,
                0x68, 0xae, 0xbc, 0x20, 0x1a, 0x2a, 0x8a, 0x18, 0x48, 0x43,
                0xbf, 0x32, 0x64, 0x6b, 0xad, 0x66, 0x78, 0x8e, 0x24, 0xb1,
                0x5f, 0xf7, 0xd7, 0x2d, 0x9a, 0x86, 0x9e, 0x25, 0x12, 0x8d,
                0x90, 0x00, 0x32, 0x46, 0x70, 0x34, 0xcb, 0x9d, 0xa9, 0x3c,
                0x84, 0x4c, 0x60, 0xc4, 0x4c, 0x39, 0xf0, 0x4c, 0xfb, 0x8e,
                0x91, 0xb7, 0x3b, 0xbf, 0xb0, 0xe9, 0xf4, 0xa3, 0x9b, 0x7b,
                0x57, 0xcf, 0xd9, 0xfb, 0x46, 0x81, 0xa9, 0xd5, 0x8f, 0x54,
                0xc2, 0x2b, 0xc2, 0x35, 0x4d, 0xb0, 0xc3, 0x84, 0xd4, 0x97,
                0x07, 0x6e, 0x3c, 0xa5, 0xe6, 0x40, 0xac, 0xad, 0x2b, 0xf9,
                0xff, 0x62, 0x68, 0xea, 0x69, 0x41, 0x31, 0xe6, 0x31, 0x69,
                0x40, 0x69, 0x1f, 0x3a, 0x03, 0x9b, 0x15, 0xd3, 0x19, 0x16,
                0x7d, 0x87, 0xa0, 0xbb, 0xb2, 0xaf, 0x5c, 0x91, 0xd4, 0x41,
                0x7c, 0x85, 0xcd, 0xbe, 0x1a, 0x99, 0xab, 0xf7, 0x9c, 0xeb,
                0x1a, 0x8f, 0x0b, 0x97, 0xf1, 0xda, 0xc0, 0xe5, 0x18, 0xb1,
                0xbe, 0x08, 0x20, 0x7d, 0x27, 0x75, 0x0c, 0xc9, 0x15, 0xee,
                0x07, 0x18, 0x4b, 0x17, 0x6c, 0x90, 0xb9, 0x26, 0x83, 0xd0,
                0x93, 0x0d, 0x5d, 0x6c, 0x7a, 0xa9, 0x32, 0xa5, 0x49, 0xd8,
                0x32, 0xc8, 0xc0, 0x3f, 0x8a, 0x43, 0x6d, 0xb4, 0xe4, 0xe6,
                0xe7, 0x60, 0x18, 0x40, 0xc7, 0x48, 0x69, 0xfb, 0x37, 0xfc,
                0x77, 0x84, 0x6a, 0x8a, 0xb6, 0x2d, 0xf4, 0xce, 0x62, 0xda,
                0x14, 0xe2, 0x60, 0xd0, 0x1b, 0xfd, 0xfa, 0x74, 0xde, 0xf9,
                0xe8, 0xdc, 0x55, 0xcd, 0x31, 0x87, 0xd6, 0xa0, 0xf7, 0x96,
                0xc8, 0x65, 0x31, 0xf9, 0x0a, 0x86, 0x73, 0x7f, 0x8e, 0xa7,
                0xf7, 0xa1, 0x77, 0x54, 0x91, 0x9a, 0xd1, 0x05, 0x7c, 0xc2,
                0xd7, 0xdb, 0x41, 0x63, 0x5c, 0x9b, 0xc9, 0x21, 0x5e, 0x8f,
                0x53, 0xcf, 0xfd, 0xba, 0x9c, 0x0b, 0xde, 0xe4, 0xea, 0x3e,
                0x42, 0x51, 0xc6, 0x56, 0x13, 0xe2, 0x5b, 0x3e, 0xee, 0x8b,
                0x21, 0xe2, 0x77, 0xd4, 0x81, 0x42, 0x8a, 0xa6, 0xc3, 0x2e,
                0xa5, 0xe8, 0x05, 0xf4, 0x17, 0xd3, 0x2c, 0x34, 0x89, 0x42,
                0x0a, 0xcb, 0x0b, 0xd7, 0xbf, 0x4e, 0x35, 0x3b, 0x28, 0x38,
                0x16, 0xc9, 0x43, 0xae, 0x3e, 0xd7, 0xb1, 0x25, 0x61, 0x42,
                0xe7, 0xbb, 0x5f, 0xf0, 0x2d, 0xc7, 0x20, 0x0f, 0xdf, 0xe6,
                0x3c, 0x3d, 0x46, 0x0a, 0xae, 0xee, 0xa3, 0xc6, 0x59, 0x04,
                0x25, 0xd2, 0x3d, 0x3c, 0xce, 0xe6, 0x05, 0xc3, 0xab, 0xbc,
                0xb5, 0xaf, 0x75, 0x96, 0xdf, 0xb6, 0x13, 0x7a, 0x0a, 0xfb,
                0x6e, 0xb2, 0x80, 0x16, 0xc5, 0xd4, 0x75, 0x81, 0x1d, 0x1e,
                0x26, 0xf5, 0x1f, 0x14, 0x75, 0x4a, 0xde, 0x3d, 0x65, 0x6e,
                0xb7, 0x13, 0x3c, 0x8d, 0xbe, 0x40, 0xbe, 0xa0, 0x15, 0xd8,
                0x36, 0xd8, 0x88,
            ],
        );
        ticket_encrypted_data.kvno = Some(2);

        let ticket_credential =
            Ticket::new(realm.clone(), sname.clone(), ticket_encrypted_data);

        let credential = create_credential(
            encryption_key.clone(),
            realm.clone(),
            pname.clone(),
            ticket_flags.clone(),
            authtime.into(),
            starttime.into(),
            endtime.into(),
            renew_till.into(),
            realm.clone(),
            sname.clone(),
            None,
            ticket_credential,
        );

        let credential_warehouse = CredentialWarehouse::from(credential);

        let ticket = ccache::CountedOctetString::new(RAW_TICKET.to_vec());

        let realm_string = ccache::CountedOctetString::new(
            "KINGDOM.HEARTS".as_bytes().to_vec(),
        );

        let client_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![ccache::CountedOctetString::new(
                "mickey".as_bytes().to_vec(),
            )],
        );
        let server_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32,
            realm_string.clone(),
            vec![
                ccache::CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone(),
            ],
        );

        let is_skey = 0;

        let ccache_credential = ccache::Credential::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket,
        );

        let ccache_header = ccache::Header::default();

        let ccache = CCache::new(
            ccache_header,
            client_principal,
            vec![ccache_credential],
        );

        assert_eq!(
            credential_warehouse,
            CredentialWarehouse::try_from(ccache).unwrap()
        );
    }
}
