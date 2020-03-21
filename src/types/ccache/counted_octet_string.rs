use crate::error;
use crate::types::KerberosString;
use std::convert::{From, TryInto};

/// String used by ccache.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct CountedOctetString {
    data: Vec<u8>,
}

impl CountedOctetString {
    pub fn new(data: Vec<u8>) -> Self {
        return CountedOctetString { data };
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len() as u32;
        let mut bytes = data_len.to_be_bytes().to_vec();
        bytes.append(&mut self.data.clone());
        return bytes;
    }
}

impl From<&KerberosString> for CountedOctetString {
    fn from(kerberos_string: &KerberosString) -> Self {
        return Self::new(kerberos_string.as_bytes().to_vec());
    }
}

impl From<&str> for CountedOctetString {
    fn from(string: &str) -> Self {
        return Self::new(string.as_bytes().to_vec());
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
    fn test_counted_octet_string_to_kerberos_string() {
        assert_eq!(
            KerberosString::from_ascii("ABC"),
            CountedOctetString::from("ABC").try_into().unwrap()
        )
    }

    #[test]
    #[should_panic(expected = "Invalid ascii string")]
    fn test_counted_octet_string_to_kerberos_string_fail() {
            CountedOctetString::new(vec![0xff]).try_into().unwrap()
    }
}
