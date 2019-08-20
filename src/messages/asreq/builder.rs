use ascii::AsciiString;
use crate::key::Key;
use crate::types::asn1;
use crate::error::*;
use super::options::AsReqOptions;
use super::timestampcrypter::*;

pub(crate) struct AsReqBuilder<'a>{
    username: &'a AsciiString, 
    user_key: Option<&'a Key>,
    options: &'a AsReqOptions

}

impl<'a> AsReqBuilder<'a> {

    fn new(
        username: &'a AsciiString, 
        user_key: Option<&'a Key>,
        options: &'a AsReqOptions
    ) -> Self {
        return Self { username, user_key, options };
    }

    pub fn build_as_req(
        username: &'a AsciiString, 
        user_key: Option<&'a Key>,
        options: &'a AsReqOptions
    ) -> Result<Vec<u8>> {
        let builder = Self::new(username, user_key, options);
        let as_req = builder.create_as_req_struct()?;
        return Ok(as_req.build());
    }

    fn create_as_req_struct(&self) -> Result<asn1::AsReq> {
        let mut as_req = asn1::AsReq::new(self.options.realm().clone(), self.username.clone());
        as_req.set_kdc_options(self.options.kdc_options());

        if self.options.should_be_pac_included() {
            as_req.include_pac();
        }

        if let Some(user_key) = &self.user_key {
            let (etype, encrypted_data) = self.produce_encrypted_timestamp(user_key)?;
            as_req.set_encrypted_timestamp(etype, encrypted_data);
            as_req.push_etype(etype);
        } else {
            for etype in self.options.sorted_etypes().iter() {
                as_req.push_etype(*etype);
            }
        }

        return Ok(as_req);
    }


    fn produce_encrypted_timestamp(&self, user_key: &Key) -> Result<(i32, Vec<u8>)>{
        return AsReqTimestampCrypter::build_encrypted_timestamp(
            self.options.realm(),
            &self.username,
            user_key,
            &self.options.sorted_etypes()
        );
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::etypes::*;

    #[test]
    fn as_req_with_supported_rc4_and_aes_by_default() {
        let as_req_struct = create_as_req_struct_with_key(None);
        assert_eq!(vec![AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96, RC4_HMAC], **as_req_struct.etypes());
    }

    #[test]
    fn as_req_with_only_supported_rc4_when_rc4_key_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let as_req_struct = create_as_req_struct_with_key(Some(&Key::RC4Key(key)));

        assert_eq!(vec![RC4_HMAC], **as_req_struct.etypes());
    }


    #[test]
    fn as_req_with_only_supported_aes128_when_aes128_key_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let as_req_struct = create_as_req_struct_with_key(Some(&Key::AES128Key(key)));

        assert_eq!(vec![AES128_CTS_HMAC_SHA1_96], **as_req_struct.etypes());

    }


    #[test]
    fn as_req_with_only_supported_aes256_when_aes256_key_is_provided() {
        let key = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        ];

        let as_req_struct = create_as_req_struct_with_key(Some(&Key::AES256Key(key)));

        assert_eq!(vec![AES256_CTS_HMAC_SHA1_96], **as_req_struct.etypes());

    }

    fn create_as_req_struct_with_key(user_key: Option<&Key>) -> asn1::AsReq {
        let username = AsciiString::from_ascii("Mickey").unwrap();
        let options = AsReqOptions::new(AsciiString::from_ascii("KINGDOM.HEARTS").unwrap());
        let builder = AsReqBuilder::new(
            &username,
            user_key,
            &options
        );

        return builder.create_as_req_struct().unwrap();
    }

}