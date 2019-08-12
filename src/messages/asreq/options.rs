use crate::constants::etypes::*;
use crate::constants::kdc_options::*;
use std::collections::HashSet;
use crate::error::*;
use crate::crypter::*;

#[derive(Debug, PartialEq)]
pub struct AsReqOptions {
    etypes: HashSet<i32>,
    kdc_options: u32
}

impl Default for AsReqOptions {
    fn default() -> Self {
        return Self {
            kdc_options: FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            etypes: [ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC ].iter().cloned().collect()
        }
    }
}

impl AsReqOptions {

    pub fn get_etypes(&self) -> &HashSet<i32> {
        return &self.etypes;
    }

    pub fn set_etypes(&mut self, etypes: HashSet<i32>) -> Result<()> {
        self.error_if_unsupported_etypes(&etypes)?;
        self.etypes = etypes;
        return Ok(());
    }

    pub fn add_etype(&mut self, etype: i32) -> Result<()> {
        self.error_if_unsupported_etype(etype)?;
        self.etypes.insert(etype);

        return Ok(());
    }

    fn error_if_unsupported_etypes(&self, etypes: &HashSet<i32>) -> Result<()> {
        for etype in etypes.iter() {
            self.error_if_unsupported_etype(*etype)?;
        }
        return Ok(());
    }

    fn error_if_unsupported_etype(&self, etype: i32) -> Result<()> {
        if !is_supported_etype(etype) {
            return Err(CryptographyErrorKind::UnsupportedCipherAlgorithm(etype))?;
        }
        return Ok(());
    }

    pub fn get_kdc_options(&self) -> u32 {
        return self.kdc_options;
    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_default() {

        assert_eq!(
            AsReqOptions {
                kdc_options: FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
                etypes: [ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC ].iter().cloned().collect()
            },
            AsReqOptions::default()
        );

    }

    #[test]
    fn get_default_etypes() {
        let options = AsReqOptions::default();
        let etypes: HashSet<i32> = [ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC ].iter().cloned().collect();

        assert_eq!(
            &etypes,
            options.get_etypes()
        );

    }

    #[test]
    fn get_default_kdc_options() {
        let options = AsReqOptions::default();

        assert_eq!(
            FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK,
            options.get_kdc_options()
        );
    }

    #[test]
    fn set_etypes() {
        let mut options = AsReqOptions::default();

        let etypes: HashSet<i32> = [ RC4_HMAC ].iter().cloned().collect();

        options.set_etypes(etypes.clone()).unwrap();
        assert_eq!(&etypes, options.get_etypes());

        let etypes: HashSet<i32> = [ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96 ].iter().cloned().collect();

        options.set_etypes(etypes.clone()).unwrap();
        assert_eq!(&etypes, options.get_etypes());
    }

    #[should_panic(expected="Cipher algorithm with etype = 3 is not supported")]
    #[test]
    fn error_setting_unsupported_etypes() {

        let mut options = AsReqOptions::default();

        let etypes: HashSet<i32> = [ RC4_HMAC, DES_CBC_MD5 ].iter().cloned().collect();

        options.set_etypes(etypes.clone()).unwrap();
    }

    #[test]
    fn add_etype() {
        let mut options = AsReqOptions::default();
        options.set_etypes([ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96 ].iter().cloned().collect()).unwrap();
        options.add_etype(RC4_HMAC).unwrap();

        let etypes: HashSet<i32> = [ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC ].iter().cloned().collect();
        assert_eq!(
            &etypes,
            options.get_etypes()
        );
    }

    #[should_panic(expected="Cipher algorithm with etype = 3 is not supported")]
    #[test]
    fn add_unsupported_etype() {
        let mut options = AsReqOptions::default();
        options.set_etypes([ AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96 ].iter().cloned().collect()).unwrap();
        options.add_etype(DES_CBC_MD5).unwrap();
    }

}