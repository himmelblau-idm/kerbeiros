use asn1::*;
use asn1_derive::*;
use super::super::super::int32::*;
use super::super::super::kerberosstring::*;
use super::super::super::super::error::*;


#[derive(Debug, Clone, PartialEq)]
pub struct EtypeInfo2Entry {
    etype: Int32,
    salt: Option<KerberosString>,
    s2kparams: Option<Vec<u8>>
}

impl EtypeInfo2Entry {

    pub fn _new(etype: i32) -> Self {
        return Self {
            etype: Int32::new(etype),
            salt: None,
            s2kparams: None
        };
    }

    pub fn _set_salt(&mut self, salt: KerberosString) {
        self.salt = Some(salt);
    }

    fn new_empty() -> Self {
        return Self {
            etype: Int32::new(0),
            salt: None,
            s2kparams: None
        };
    }

    pub fn asn1_type(&self) -> EtypeInfo2EntryAsn1 {
        return EtypeInfo2EntryAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
pub struct EtypeInfo2EntryAsn1{
    #[seq_comp(context_tag = 0)]
    etype: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1, optional)]
    salt: SeqField<KerberosStringAsn1>,
    #[seq_comp(context_tag = 2, optional)]
    s2kparams: SeqField<OctetString>
}


impl EtypeInfo2EntryAsn1 {

    fn new(entry: &EtypeInfo2Entry) -> Self {
        let mut entry_asn1 = Self::new_empty();

        entry_asn1.set_etype(entry.etype.asn1_type());
        
        if let Some(salt) = &entry.salt {
            entry_asn1.set_salt(salt.asn1_type());
        }

        if let Some(s2kparams) = &entry.s2kparams {
            entry_asn1.set_s2kparams(OctetString::new(s2kparams.clone()));
        }

        return entry_asn1;
    }

    fn new_empty() -> Self {
        return Self {
            etype: SeqField::new(),
            salt: SeqField::new(),
            s2kparams: SeqField::new()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<EtypeInfo2Entry> {
        let mut entry = EtypeInfo2Entry::new_empty();

        let etype_asn1 = self.get_etype().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        entry.etype = etype_asn1.no_asn1_type()?;

        if let Some(salt_asn1) = self.get_salt() {
            entry.salt = Some(salt_asn1.no_asn1_type()?);
        }
        
        if let Some(s2kparams_asn1) = self.get_s2kparams() {
            let s2kparams = s2kparams_asn1.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
            entry.s2kparams = Some(s2kparams.clone());
        }

        return Ok(entry);
    }

}


impl Asn1InstanciableObject for EtypeInfo2EntryAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::super::super::constants::etypes::*;

    #[test]
    fn decode_etypeinfo2entry() {
        let mut entry_asn1 = EtypeInfo2EntryAsn1::new_empty();

        entry_asn1.decode(&[0x30, 0x1d, 
                            0xa0, 0x03, 0x02, 0x01, 0x12, 
                            0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 
                            0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 
                            0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79]).unwrap();

        let mut entry = EtypeInfo2Entry::new_empty();
        entry.etype = Int32::new(AES256_CTS_HMAC_SHA1_96);
        entry.salt = Some(KerberosString::from("KINGDOM.HEARTSmickey").unwrap());

        assert_eq!(entry, entry_asn1.no_asn1_type().unwrap());

    }
}
