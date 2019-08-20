use super::credential::*;
use super::mappers::*;
use crate::types::*;
use crate::error::*;
use super::file::*;

/// To store several credentials related to the same user and realm
pub struct CredentialWarehouse {
    credentials: Vec<Credential>,
    realm: Realm,
    client: PrincipalName
}


impl CredentialWarehouse {

    pub fn new(credential: Credential) -> Self {
        return Self {
            realm: credential.crealm().clone(),
            client: credential.cname().clone(),
            credentials: vec![credential],
        }
    }

    pub fn realm(&self) -> &Realm {
        return &self.realm;
    }

    pub fn credentials(&self) -> &Vec<Credential> {
        return &self.credentials;
    }

    pub fn client(&self) -> &PrincipalName {
        return &self.client;
    }

    pub(crate) fn into_krb_cred(&self) -> KrbCred {
        return CredentialWarehouseKrbCredMapper::credential_warehouse_to_krb_cred(self);
    }

    pub(crate) fn into_ccache(&self) -> CCache {
        return CredentialWarehouseCCacheMapper::credential_warehouse_to_ccache(self);
    }

    /// Saves the credentials into a file by using the ccache format, used by Linux.
    pub fn save_into_ccache_file(&self, path: &str) -> Result<()> {
        return CredentialFileConverter::save_into_ccache_file(self, path);
    }

    /// Saves the credentials into a file by using the KRB-CRED format, used by Windows.
    pub fn save_into_krb_cred_file(&self, path: &str) -> Result<()> {
        return CredentialFileConverter::save_into_krb_cred_file(self, path);
    }
}

