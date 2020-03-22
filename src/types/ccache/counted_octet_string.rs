use crate::error;
use crate::types::KerberosString;
use nom::number::complete::be_u32;
use nom::{length_data, named};
use std::convert::{From, TryInto};

named!(parse_length_array, length_data!(be_u32));

/// String used by ccache.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct CountedOctetString {
    data: Vec<u8>,
}

impl CountedOctetString {
    pub fn new(data: Vec<u8>) -> Self {
        return CountedOctetString { data };
    }

    pub fn data(&self) -> &Vec<u8> {
        return &self.data;
    }

    pub fn data_move(self) -> Vec<u8> {
        return self.data;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len() as u32;
        let mut bytes = data_len.to_be_bytes().to_vec();
        bytes.append(&mut self.data.clone());
        return bytes;
    }

    pub fn parse(raw: &[u8]) -> error::Result<(&[u8], Self)> {
        let (rest, data) = parse_length_array(raw)?;
        return Ok((rest, Self::new(data.to_vec())));
    }
}

impl From<&KerberosString> for CountedOctetString {
    fn from(kerberos_string: &KerberosString) -> Self {
        return Self::new(kerberos_string.as_bytes().to_vec());
    }
}

impl TryInto<KerberosString> for CountedOctetString {
    type Error = error::Error;

    fn try_into(self) -> Result<KerberosString, Self::Error> {
        return Ok(KerberosString::from_ascii(self.data)?);
    }
}

impl From<&str> for CountedOctetString {
    fn from(string: &str) -> Self {
        return Self::new(string.as_bytes().to_vec());
    }
}

impl TryInto<String> for CountedOctetString {
    type Error = error::Error;

    fn try_into(self) -> Result<String, Self::Error> {
        return Ok(String::from_utf8(self.data)?);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_default_octet_string() {
        let octet_string = CountedOctetString::default();
        assert_eq!(Vec::<u8>::new(), octet_string.data);
    }

    #[test]
    fn counted_octet_string_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
                0x41, 0x52, 0x54, 0x53
            ],
            CountedOctetString::from("KINGDOM.HEARTS").to_bytes()
        );
    }

    #[test]
    fn test_counted_octet_string_from_bytes() {
        assert_eq!(
            CountedOctetString::from("KINGDOM.HEARTS"),
            CountedOctetString::parse(&[
                0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45,
                0x41, 0x52, 0x54, 0x53
            ])
            .unwrap().1
        );
    }

    #[test]
    #[should_panic(expected = "Error parsing binary data")]
    fn test_counted_octet_string_from_bytes_panic() {
        CountedOctetString::parse(&[0x00]).unwrap();
    }

    #[test]
    fn test_counted_octet_string_to_kerberos_string() {
        let k_string: KerberosString = CountedOctetString::from("ABC").try_into().unwrap();
        assert_eq!(KerberosString::from_ascii("ABC").unwrap(), k_string)
    }

    #[test]
    #[should_panic(expected = "Invalid ascii string")]
    fn test_counted_octet_string_to_kerberos_string_fail() {
        let _: KerberosString = CountedOctetString::new(vec![0xff]).try_into().unwrap();
    }

    #[test]
    fn test_counted_octet_string_to_string() {
        let string: String = CountedOctetString::from("ABC").try_into().unwrap();
        assert_eq!("ABC".to_string(), string)
    }

    #[test]
    #[should_panic(expected = "Invalid utf-8 string")]
    fn test_counted_octet_string_to_string_panic() {
        let _: String = CountedOctetString::new(vec![0xff]).try_into().unwrap();
    }
}
