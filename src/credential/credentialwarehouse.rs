use super::credential::*;
use super::mappers::*;
use crate::structs::*;
use crate::error::*;
use super::file::*;

pub struct CredentialWarehouse {
    credentials: Vec<Credential>,
    realm: Realm,
    client: PrincipalName
}


impl CredentialWarehouse {

    pub fn new(credential: Credential) -> Self {
        return Self {
            realm: credential.get_crealm().clone(),
            client: credential.get_cname().clone(),
            credentials: vec![credential],
        }
    }

    pub fn get_realm(&self) -> &Realm {
        return &self.realm;
    }

    pub fn get_credentials(&self) -> &Vec<Credential> {
        return &self.credentials;
    }

    pub fn get_client(&self) -> &PrincipalName {
        return &self.client;
    }

    pub fn to_krb_cred(&self) -> KrbCred {
        return CredentialWarehouseKrbCredMapper::credential_warehouse_to_krb_cred(self);
    }

    pub fn to_ccache(&self) -> CCache {
        return CredentialWarehouseCCacheMapper::credential_warehouse_to_ccache(self);
    }

    pub fn save_into_ccache_file(&self, path: &str) -> KerberosResult<()> {
        return CredentialFileConverter::save_into_ccache_file(self, path);
    }
}

