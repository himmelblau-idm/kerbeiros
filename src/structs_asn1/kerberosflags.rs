use asn1::*;
use super::super::byteparser;
use super::super::error::*;

#[derive(Debug, PartialEq, Clone)]
pub struct KerberosFlags {
    flags: u32
}

impl KerberosFlags {

    pub fn new_empty() -> KerberosFlags {
        return KerberosFlags{
            flags: 0
        };
    }

    pub fn new(flags: u32) -> KerberosFlags {
        return KerberosFlags{
            flags
        };
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.flags |= flags
    }

    pub fn _has_flag(&self, flag: u32) -> bool {
        return (self.flags & flag) != 0;
    }

    pub fn _del_flags(&mut self, flags: u32) {
        self.flags &= !flags;
    }

    pub fn asn1_type(&self) -> KerberosFlagsAsn1 {
        return KerberosFlagsAsn1::new(self.flags);
    }

}


pub struct KerberosFlagsAsn1 {
    subtype: BitSring
}

impl KerberosFlagsAsn1 {
    fn new(flags: u32) -> KerberosFlagsAsn1 {
        let flags_bytes: Vec<u8> = byteparser::u32_to_le_bytes(flags).to_vec();

        return KerberosFlagsAsn1{
            subtype: BitSring::new(flags_bytes, 0)
        };
    }

    fn new_empty() -> Self {
        return Self{
            subtype: BitSring::new_empty()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<KerberosFlags> {
        let value = self.subtype.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("KerberosFlags".to_string())
        )?;
        let mut flags = KerberosFlags::new_empty();
        
        let mut bytes = value.get_bytes().clone();

        let mut i = bytes.len();
        while i < 4 {
            bytes.push(0);
            i += 1;
        }

        let mut array_bytes = [0; 4];
        let array_bytes_len = array_bytes.len();
        array_bytes.copy_from_slice(&bytes[..array_bytes_len]);
        
        
        flags.set_flags(byteparser::le_bytes_to_u32(&array_bytes));

        return Ok(flags);
    }

    
 
}

impl Asn1Object for KerberosFlagsAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>,Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }

}

impl Asn1Tagged for KerberosFlagsAsn1 {
    fn type_tag() -> Tag {
        return BitSring::type_tag();
    }
}

impl Asn1InstanciableObject for KerberosFlagsAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_flags_to_bit_string() {
        let kdc_flags = KerberosFlagsAsn1::new(0x40);
        assert_eq!(vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40,0x0,0x0,0x0], kdc_flags.encode().unwrap());

        let kdc_flags = KerberosFlagsAsn1::new(0x01000000);
        assert_eq!(vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0,0x0,0x0,0x1], kdc_flags.encode().unwrap()); 

        let kdc_flags = KerberosFlagsAsn1::new(0x02008000);
        assert_eq!(vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80,0x0,0x2], kdc_flags.encode().unwrap()); 

        let kdc_flags = KerberosFlagsAsn1::new(0x12481428);
        assert_eq!(vec![BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28,0x14,0x48,0x12], kdc_flags.encode().unwrap()); 
    }

    #[test]
    fn test_decode_kerberos_flags() {
        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x40,0x0,0x0,0x0]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x40), 
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0,0x0,0x0,0x1]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x01000000),
            kdc_flags.no_asn1_type().unwrap()
        ); 

        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x0, 0x80,0x0,0x2]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x02008000),
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x5, 0x0, 0x28,0x14,0x48,0x12]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x12481428),
            kdc_flags.no_asn1_type().unwrap()
        );

    }

     #[test]
    fn test_decode_short_kerberos_flags() {
        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x2, 0x0, 0x40]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x40), 
            kdc_flags.no_asn1_type().unwrap()
        );

        let mut kdc_flags = KerberosFlagsAsn1::new_empty();
        kdc_flags.decode(&[BIT_STRING_TAG_NUMBER, 0x3, 0x0, 0x28,0x14]).unwrap();
        assert_eq!(
            KerberosFlags::new(0x1428),
            kdc_flags.no_asn1_type().unwrap()
        );
    }

}
