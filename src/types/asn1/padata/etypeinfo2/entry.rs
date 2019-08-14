use red_asn1::*;
use super::super::super::int32::*;
use super::super::super::kerberosstring::*;
use crate::error::{ErrorKind, Result};


#[derive(Debug, Clone, PartialEq, Default)]
pub struct EtypeInfo2Entry {
    etype: Int32,
    salt: Option<KerberosString>,
    s2kparams: Option<Vec<u8>>
}

impl EtypeInfo2Entry {

    #[cfg(test)]
    pub fn new(etype: i32) -> Self {
        return Self {
            etype: etype,
            salt: None,
            s2kparams: None
        };
    }

    pub fn get_etype(&self) -> Int32 {
        return self.etype;
    }

    pub fn get_salt(&self) -> &Option<KerberosString> {
        return &self.salt;
    }

    #[cfg(test)]
    pub fn set_salt(&mut self, salt: KerberosString) {
        self.salt = Some(salt);
    }

    pub fn get_salt_bytes(&self) -> Vec<u8> {
        if let Some(salt) = &self.salt {
            return salt.as_bytes().to_vec();
        }
        return Vec::new();
    }

    pub fn get_s2kparams(&self) -> &Option<Vec<u8>> {
        return &self.s2kparams;
    }

}

#[derive(Sequence, Debug, Default, PartialEq)]
pub(crate) struct EtypeInfo2EntryAsn1{
    #[seq_field(context_tag = 0)]
    etype: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 1, optional)]
    salt: SeqField<KerberosStringAsn1>,
    #[seq_field(context_tag = 2, optional)]
    s2kparams: SeqField<OctetString>
}


impl EtypeInfo2EntryAsn1 {

    pub fn no_asn1_type(&self) -> Result<EtypeInfo2Entry> {
        let mut entry = EtypeInfo2Entry::default();

        let etype_asn1 = self.get_etype().ok_or_else(|| 
            ErrorKind::NotAvailableData("EtypeInfo2Entry::etype".to_string())
        )?;
        entry.etype = etype_asn1.no_asn1_type()?;

        if let Some(salt_asn1) = self.get_salt() {
            entry.salt = Some(salt_asn1.no_asn1_type()?);
        }
        
        if let Some(s2kparams_asn1) = self.get_s2kparams() {
            let s2kparams = s2kparams_asn1.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("EtypeInfo2Entry::s2kparams".to_string())
        )?;
            entry.s2kparams = Some(s2kparams.clone());
        }

        return Ok(entry);
    }

}

impl From<&EtypeInfo2Entry> for EtypeInfo2EntryAsn1 {
    fn from(entry: &EtypeInfo2Entry) -> Self {
        let mut entry_asn1 = Self::default();

        entry_asn1.set_etype(entry.get_etype().into());
        
        if let Some(salt) = entry.get_salt() {
            entry_asn1.set_salt(salt.into());
        }

        if let Some(s2kparams) = entry.get_s2kparams() {
            entry_asn1.set_s2kparams(OctetString::from(s2kparams.clone()));
        }

        return entry_asn1;
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::etypes::*;

    #[test]
    fn create_default_etypeinfo2_entry_asn1() {
        assert_eq!(
            EtypeInfo2EntryAsn1 {
                etype: SeqField::default(),
                salt: SeqField::default(),
                s2kparams: SeqField::default()
            },
            EtypeInfo2EntryAsn1::default()
        )
    }

    #[test]
    fn decode_etypeinfo2entry() {
        let mut entry_asn1 = EtypeInfo2EntryAsn1::default();

        entry_asn1.decode(&[0x30, 0x1d, 
                            0xa0, 0x03, 0x02, 0x01, 0x12, 
                            0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 
                            0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 
                            0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79]).unwrap();

        let mut entry = EtypeInfo2Entry::default();
        entry.etype = AES256_CTS_HMAC_SHA1_96;
        entry.salt = Some(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        assert_eq!(entry, entry_asn1.no_asn1_type().unwrap());

    }
}
