use crate::{Error, Result};
use red_asn1::{Asn1Object, BitSring, Tag};

/// (*KerberosFlags*) Flags used for different entities.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct KerberosFlags {
    flags: u32,
}

impl KerberosFlags {
    pub fn new(flags: u32) -> KerberosFlags {
        return KerberosFlags { flags };
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.flags |= flags
    }

    #[cfg(test)]
    pub fn has_flag(&self, flag: u32) -> bool {
        return (self.flags & flag) != 0;
    }

    #[cfg(test)]
    pub fn del_flags(&mut self, flags: u32) {
        self.flags &= !flags;
    }

    pub fn flags(&self) -> u32 {
        return self.flags;
    }
}

impl From<u32> for KerberosFlags {
    fn from(flags: u32) -> Self {
        return Self::new(flags);
    }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct KerberosFlagsAsn1 {
    subtype: BitSring,
}

impl KerberosFlagsAsn1 {
    pub fn no_asn1_type(&self) -> Result<KerberosFlags> {
        let value = self
            .subtype
            .value()
            .ok_or_else(|| Error::NotAvailableData("KerberosFlags".to_string()))?;
        let mut flags = KerberosFlags::default();

        let mut bytes = value.get_bytes().clone();

        let mut i = bytes.len();
        while i < 4 {
            bytes.push(0);
            i += 1;
        }

        let mut array_bytes = [0; 4];
        let array_bytes_len = array_bytes.len();
        array_bytes.copy_from_slice(&bytes[..array_bytes_len]);

        flags.set_flags(u32::from_be_bytes(array_bytes));

        return Ok(flags);
    }
}

impl From<u32> for KerberosFlagsAsn1 {
    fn from(flags: u32) -> Self {
        let flags_bytes: Vec<u8> = flags.to_be_bytes().to_vec();

        return KerberosFlagsAsn1 {
            subtype: BitSring::new(flags_bytes, 0),
        };
    }
}

impl From<&KerberosFlags> for KerberosFlagsAsn1 {
    fn from(flags: &KerberosFlags) -> Self {
        return Self::from(flags.flags());
    }
}

impl Asn1Object for KerberosFlagsAsn1 {
    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_asn1::BIT_STRING_TAG_NUMBER;
    use std::u32;

    #[test]
    fn test_create_default_flags() {
        let kdc_flags = KerberosFlags::default();
        assert_eq!(0, kdc_flags.flags);
    }

    #[test]
    fn test_kerberos_flags_from_u32() {
        let test_numbers = vec![0, 1, u32::MAX, 2344, 546];

        for i in test_numbers.iter() {
            let kdc_flags = KerberosFlags::from(*i);
            assert_eq!(*i, kdc_flags.flags);
        }
    }

    #[test]
    fn test_convert_flags_to_bit_string() {
        let kdc_flags = KerberosFlagsAsn1::from(0x40000000);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40, 0x0, 0x0, 0x0],
            kdc_flags.encode().unwrap()
        );

        let kdc_flags = KerberosFlagsAsn1::from(0x01);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1],
            kdc_flags.encode().unwrap()
        );

        let kdc_flags = KerberosFlagsAsn1::from(0x0000800002);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80, 0x0, 0x2],
            kdc_flags.encode().unwrap()
        );

        let kdc_flags = KerberosFlagsAsn1::from(0x0028144812);
        assert_eq!(
            vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28, 0x14, 0x48, 0x12],
            kdc_flags.encode().unwrap()
        );
    }

    #[test]
    fn test_decode_kerberos_flags() {
        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40, 0x0, 0x0, 0x0])
            .unwrap();
        assert_eq!(
            KerberosFlags::new(0x40000000),
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1])
            .unwrap();
        assert_eq!(KerberosFlags::new(0x01), kdc_flags.no_asn1_type().unwrap());

        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80, 0x0, 0x2])
            .unwrap();
        assert_eq!(
            KerberosFlags::new(0x0000800002),
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28, 0x14, 0x48, 0x12])
            .unwrap();
        assert_eq!(
            KerberosFlags::new(0x0028144812),
            kdc_flags.no_asn1_type().unwrap()
        );
    }

    #[test]
    fn test_decode_short_kerberos_flags() {
        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x2, 0x0, 0x40])
            .unwrap();
        assert_eq!(
            KerberosFlags::new(0x40000000),
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::default();
        kdc_flags
            .decode(&[BIT_STRING_TAG_NUMBER, 0x3, 0x0, 0x28, 0x14])
            .unwrap();
        assert_eq!(
            KerberosFlags::new(0x28140000),
            kdc_flags.no_asn1_type().unwrap()
        );
    }
}
