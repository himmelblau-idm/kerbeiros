use red_asn1::*;
use super::super::basics::*;
use crate::error::{ErrorKind, Result};
use super::edata::Edata;
use crate::constants::error_codes::*;

use std::fmt;

/// (*KRB-ERROR*) Message used to indicate an error.
#[derive(Debug, Clone, PartialEq)]
pub struct KrbError {
    pvno: i8,
    msg_type: i8,
    ctime: Option<KerberosTime>,
    cusec: Option<Microseconds>,
    stime: KerberosTime,
    susec: Microseconds,
    error_code: Int32,
    crealm: Option<Realm>,
    cname: Option<PrincipalName>,
    realm: Realm,
    sname: PrincipalName,
    e_text: Option<KerberosString>,
    e_data: Option<Edata>
}

impl KrbError {

    fn new(
        stime: KerberosTime, 
        susec: Microseconds,
        error_code: Int32,
        realm: Realm,
        sname: PrincipalName
    ) -> Self {
        return Self {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime,
            susec,
            error_code,
            crealm: None,
            cname: None,
            realm,
            sname,
            e_text: None,
            e_data: None
        }
    }

    pub fn pvno(&self) -> i8 {
        return self.pvno;
    }

    fn set_pvno(&mut self, pvno: i8) {
        self.pvno = pvno;
    }

    pub fn msg_type(&self) -> i8 {
        return self.msg_type;
    }

    fn set_msg_type(&mut self, msg_type: i8) {
        self.msg_type = msg_type;
    }

    pub fn ctime(&self) -> &Option<KerberosTime> {
        return &self.ctime;
    }

    fn set_ctime(&mut self, ctime: KerberosTime) {
        self.ctime = Some(ctime);
    } 

    pub fn cusec(&self) -> &Option<Microseconds> {
        return &self.cusec;
    }

    fn set_cusec(&mut self, cusec: Microseconds) {
        self.cusec = Some(cusec);
    }

    pub fn stime(&self) -> &KerberosTime {
        return &self.stime;
    }

    pub fn susec(&self) -> &Microseconds {
        return &self.susec;
    }

    pub fn error_code(&self) -> i32 {
        return self.error_code;
    }

    pub fn error_code_message(&self) -> String {
        return error_code_to_string(self.error_code);
    }

    pub fn crealm(&self) -> &Option<Realm> {
        return &self.crealm;
    }

    fn set_crealm(&mut self, crealm: Realm) {
        self.crealm = Some(crealm);
    }

    pub fn cname(&self) -> &Option<PrincipalName> {
        return &self.cname;
    }

    fn set_cname(&mut self, cname: PrincipalName) {
        self.cname = Some(cname);
    }

    pub fn realm(&self) -> &Realm {
        return &self.realm;
    }

    pub fn sname(&self) -> &PrincipalName {
        return &self.sname;
    }

    pub fn e_text(&self) -> &Option<KerberosString> {
        return &self.e_text;
    }

    fn set_e_text(&mut self, e_text: KerberosString) {
        self.e_text = Some(e_text);
    }

    pub fn e_data(&self) -> &Option<Edata> {
        return &self.e_data;
    }

    fn set_e_data(&mut self, e_data: Edata) {
        self.e_data = Some(e_data);
    }

    pub fn parse(raw: &[u8]) -> Result<KrbError> {
        let mut krb_error_asn1 = KrbErrorAsn1::default();
        krb_error_asn1.decode(raw)?;
        return Ok(krb_error_asn1.no_asn1_type().unwrap());
    }
}

impl fmt::Display for KrbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KRB-ERROR [{}] {}", self.error_code(), self.error_code_message())
    }
}


#[derive(Sequence, Default, Debug, PartialEq)]
#[seq(application_tag = 30)]
pub(crate) struct KrbErrorAsn1 {
    #[seq_field(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_field(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_field(context_tag = 2, optional)]
    ctime: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 3, optional)]
    cusec: SeqField<MicrosecondsAsn1>,
    #[seq_field(context_tag = 4)]
    stime: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 5)]
    susec: SeqField<MicrosecondsAsn1>,
    #[seq_field(context_tag = 6)]
    error_code: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 7, optional)]
    crealm: SeqField<RealmAsn1>,
    #[seq_field(context_tag = 8, optional)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_field(context_tag = 9)]
    realm: SeqField<RealmAsn1>,
    #[seq_field(context_tag = 10)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_field(context_tag = 11, optional)]
    e_text: SeqField<KerberosStringAsn1>,
    #[seq_field(context_tag = 12, optional)]
    e_data: SeqField<OctetString>
}

impl KrbErrorAsn1 {

    fn no_asn1_type(&self) -> Result<KrbError> {
        
        let stime = self.get_stime().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::stime".to_string())
        )?;

        let susec = self.get_susec().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::susec".to_string())
        )?;

        let error_code = self.get_error_code().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::error_code".to_string())
        )?;

        let realm = self.get_realm().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::realm".to_string())
        )?;

        let sname = self.get_sname().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::sname".to_string())
        )?;

        let mut krb_error = KrbError::new(
            stime.no_asn1_type()?, 
            susec.no_asn1_type()?, 
            error_code.no_asn1_type()?, 
            realm.no_asn1_type()?, 
            sname.no_asn1_type()?
        );

        let pvno = self.get_pvno().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::pvno".to_string())
        )?;
        let pvno_value = pvno.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::pvno".to_string())
        )?;
        krb_error.set_pvno(pvno_value as i8);

        let msg_type = self.get_msg_type().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::msg_type".to_string())
        )?;
        let msg_type_value = msg_type.value().ok_or_else(|| 
            ErrorKind::NotAvailableData("KrbError::msg_type".to_string())
        )?;
        krb_error.set_msg_type(msg_type_value as i8);

        if let Some(ctime) = self.get_ctime() {
            krb_error.set_ctime(ctime.no_asn1_type()?);
        }

        if let Some(cusec) = self.get_cusec() {
            krb_error.set_cusec(cusec.no_asn1_type()?);
        }

        if let Some(crealm) = self.get_crealm() {
            krb_error.set_crealm(crealm.no_asn1_type()?);
        }

        if let Some(cname) = self.get_cname() {
            krb_error.set_cname(cname.no_asn1_type()?);
        }

        if let Some(e_text) = self.get_e_text() {
            krb_error.set_e_text(e_text.no_asn1_type()?);
        }

        if let Some(e_data) = self.get_e_data() {
            let e_data_value = e_data.value().ok_or_else(|| 
                ErrorKind::NotAvailableData("KrbError::e_data".to_string())
            )?;
            
            if krb_error.error_code == KDC_ERR_PREAUTH_REQUIRED {
                match MethodData::parse(e_data_value) {
                    Ok(method_data) => {
                        krb_error.set_e_data(Edata::MethodData(method_data));
                    },
                    Err(_) => {
                        krb_error.set_e_data(Edata::Raw(e_data_value.clone()));
                    }
                }
            }
            else {
                krb_error.set_e_data(Edata::Raw(e_data_value.clone()));
            }
        }

        return Ok(krb_error);
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crate::constants::*;

    #[test]
    fn create_default_krb_error_asn1() {
        assert_eq!(
            KrbErrorAsn1 {
                pvno: SeqField::default(),
                msg_type: SeqField::default(),
                ctime: SeqField::default(),
                cusec: SeqField::default(),
                stime: SeqField::default(),
                susec: SeqField::default(),
                error_code: SeqField::default(),
                crealm: SeqField::default(),
                cname: SeqField::default(),
                realm: SeqField::default(),
                sname: SeqField::default(),
                e_text: SeqField::default(),
                e_data: SeqField::default(),
            },
            KrbErrorAsn1::default()
        )
    }

    #[test]
    fn test_decode_krb_error() {
        let mut krb_error_asn1 = KrbErrorAsn1::default();
        krb_error_asn1.decode(&[
            0x7e, 0x81, 0xdc, 0x30, 0x81, 0xd9, 
            0xa0, 0x03, 0x02, 0x01, 0x05, 
            0xa1, 0x03, 0x02, 0x01, 0x1e, 
            0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30, 0x33, 0x31, 0x5a, 
            0xa5, 0x05, 0x02, 0x03, 0x05, 0x34, 0x2f, 
            0xa6, 0x03, 0x02, 0x01, 0x19, 
            0xa9, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
            0xaa, 0x23, 0x30, 0x21, 
                0xa0, 0x03, 0x02, 0x01, 0x02, 
                0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
            0xac, 0x77, 0x04, 0x75, 0x30, 0x73, 
                0x30, 0x50, 
                    0xa1, 0x03, 0x02, 0x01, 0x13, 
                    0xa2, 0x49, 0x04, 0x47, 
                        0x30, 0x45, 0x30, 0x1d, 
                            0xa0, 0x03, 0x02, 0x01, 0x12, 
                            0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                        0x30, 0x05, 
                            0xa0, 0x03, 0x02, 0x01, 0x17, 
                        0x30, 0x1d, 
                            0xa0, 0x03, 0x02, 0x01, 0x03, 
                            0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
                0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00, 
                0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x10, 0xa2, 0x02, 0x04, 0x00, 
                0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2, 0x02, 0x04, 0x00
        ]).unwrap();

        let error_code = KDC_ERR_PREAUTH_REQUIRED;
        let stime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let susec = Microseconds::new(341039).unwrap();
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let mut sname = PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());
        
        let mut krb_error = KrbError::new(stime, susec, error_code, realm, sname);

        let mut method_data = MethodData::default();

        let mut entry1 = EtypeInfo2Entry::new(AES256_CTS_HMAC_SHA1_96);
        entry1.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let entry2 = EtypeInfo2Entry::new(RC4_HMAC);

        let mut entry3 = EtypeInfo2Entry::new(DES_CBC_MD5);
        entry3.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::default();

        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);

        method_data.push(PaData::EtypeInfo2(info2));

        method_data.push(PaData::Raw(PA_ENC_TIMESTAMP, vec![]));
        method_data.push(PaData::Raw(PA_PK_AS_REQ, vec![]));
        method_data.push(PaData::Raw(PA_PK_AS_REP_OLD, vec![]));

        krb_error.set_e_data(Edata::MethodData(method_data));

        assert_eq!(krb_error, krb_error_asn1.no_asn1_type().unwrap());
    }

    #[test]
    fn krb_error_fields() {

        let error_code = KDC_ERR_PREAUTH_REQUIRED;
        let stime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let susec = Microseconds::new(341039).unwrap();
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let mut sname = PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut method_data = MethodData::default();

        let mut entry1 = EtypeInfo2Entry::new(AES256_CTS_HMAC_SHA1_96);
        entry1.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let entry2 = EtypeInfo2Entry::new(RC4_HMAC);

        let mut entry3 = EtypeInfo2Entry::new(DES_CBC_MD5);
        entry3.set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::default();

        info2.push(entry1);
        info2.push(entry2);
        info2.push(entry3);

        method_data.push(PaData::EtypeInfo2(info2));

        method_data.push(PaData::Raw(PA_ENC_TIMESTAMP, vec![]));
        method_data.push(PaData::Raw(PA_PK_AS_REQ, vec![]));
        method_data.push(PaData::Raw(PA_PK_AS_REP_OLD, vec![]));
        let e_data = Edata::MethodData(method_data);

        let mut krb_error = KrbError::new(stime, susec.clone(), error_code, realm.clone(), sname.clone());

        krb_error.set_e_data(e_data.clone());

        assert_eq!(5, krb_error.pvno());
        assert_eq!(30, krb_error.msg_type());
        assert_eq!(&None, krb_error.ctime());
        assert_eq!(&None, krb_error.cusec());
        assert_eq!(&stime, krb_error.stime());
        assert_eq!(&susec, krb_error.susec());
        assert_eq!(error_code, krb_error.error_code());
        assert_eq!(&None, krb_error.crealm());
        assert_eq!(&None, krb_error.cname());
        assert_eq!(&realm, krb_error.realm());
        assert_eq!(&sname, krb_error.sname());
        assert_eq!(&None, krb_error.e_text());
        assert_eq!(&Some(e_data), krb_error.e_data());
    }

}
