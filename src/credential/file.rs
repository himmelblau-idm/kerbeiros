use super::credentialwarehouse::*;
use crate::error::*;
use std::fs::File;
use failure::ResultExt;
use std::io::Write;

pub struct CredentialFileConverter<'a> {
    credentials: &'a CredentialWarehouse,
    path: &'a str
}

impl<'a> CredentialFileConverter<'a> {

    pub fn save_into_krb_cred_file(credentials: &'a CredentialWarehouse, path: &'a str) -> KerberosResult<()> {
        let converter = Self::new(credentials, path);
        let data = converter.build_krb_cred();
        return converter.save_data_to_file(&data);
    }

    
    pub fn save_into_ccache_file(credentials: &'a CredentialWarehouse, path: &'a str) -> KerberosResult<()> {
        let converter = Self::new(credentials, path);
        let data = converter.build_ccache();
        return converter.save_data_to_file(&data);
    }


    fn new(credentials: &'a CredentialWarehouse, path: &'a str) -> Self {
        return Self {
            credentials,
            path
        };
    }

    fn save_data_to_file(&self, data: &[u8]) -> KerberosResult<()> {
        let mut fp = File::create(self.path).context(
            KerberosErrorKind::IOError
        )?;

        fp.write_all(data).context(
            KerberosErrorKind::IOError
        )?;

        return Ok(());
    }

    fn build_krb_cred(&self) -> Vec<u8> {
        return self.credentials.to_krb_cred().build();
    }

    
    fn build_ccache(&self) -> Vec<u8> {
        return self.credentials.to_ccache().build();
    }

}
