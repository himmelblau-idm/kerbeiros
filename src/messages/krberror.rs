use super::super::error::*;
use super::super::structs;


pub struct KrbError {
    error_code: i32
}


impl KrbError {

    fn new(error_code: i32) -> Self {
        return Self{
            error_code: error_code
        }
    }

    pub fn get_error_code(&self) -> &i32 {
        return &self.error_code;
    }

    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let krb_error = structs::KrbError::parse(raw)?;

        return Ok(Self::new(
            krb_error.get_error_code()
        ));
    }

}