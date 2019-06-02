use super::super::error::*;
use super::kerberostime::*;
use super::microseconds::*;
use super::int32::*;
use super::realm::*;
use super::principalname::*;
use super::kerberosstring::*;
use asn1::*;
use asn1_derive::*;
use chrono::Utc;

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
    e_data: Option<Vec<u8>>
}

impl KrbError {

    fn new_empty() -> Self {
        return Self {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: KerberosTime::new(Utc::now()),
            susec: Microseconds::new(0).unwrap(),
            error_code: Int32::new(0),
            crealm: None,
            cname: None,
            realm: Realm::from("").unwrap(),
            sname: PrincipalName::new(0, KerberosString::from("").unwrap()),
            e_text: None,
            e_data: None
        }
    }

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<KrbError> {
        let mut krb_error_asn1 = KrbErrorAsn1::new_empty();
        krb_error_asn1.decode(raw)?;
        return Ok(krb_error_asn1.no_asn1_type().unwrap());
    }
}

#[derive(Asn1Sequence)]
#[seq(application_tag = 30)]
struct KrbErrorAsn1 {
    #[seq_comp(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_comp(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_comp(context_tag = 2, optional)]
    ctime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 3, optional)]
    cusec: SeqField<MicrosecondsAsn1>,
    #[seq_comp(context_tag = 4)]
    stime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 5)]
    susec: SeqField<MicrosecondsAsn1>,
    #[seq_comp(context_tag = 6)]
    error_code: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 7, optional)]
    crealm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 8, optional)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 9)]
    realm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 10)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 11, optional)]
    e_text: SeqField<KerberosStringAsn1>,
    #[seq_comp(context_tag = 12, optional)]
    e_data: SeqField<OctetString>
}

impl KrbErrorAsn1 {

    fn new_empty() -> Self {
        return Self{
            pvno: SeqField::new(),
            msg_type: SeqField::new(),
            ctime: SeqField::new(),
            cusec: SeqField::new(),
            stime: SeqField::new(),
            susec: SeqField::new(),
            error_code: SeqField::new(),
            crealm: SeqField::new(),
            cname: SeqField::new(),
            realm: SeqField::new(),
            sname: SeqField::new(),
            e_text: SeqField::new(),
            e_data: SeqField::new(),
        }
    }

    fn no_asn1_type(&self) -> KerberosResult<KrbError> {
        let mut krb_error = KrbError::new_empty();

        let pvno = self.get_pvno().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let pvno_value = pvno.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        krb_error.pvno = *pvno_value as i8;

        let msg_type = self.get_msg_type().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let msg_type_value = msg_type.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        krb_error.msg_type = *msg_type_value as i8;

        
        if let Some(ctime) = self.get_ctime() {
            krb_error.ctime = Some(ctime.no_asn1_type()?);
        }

        if let Some(cusec) = self.get_cusec() {
            krb_error.cusec = Some(cusec.no_asn1_type()?);
        }

        let stime = self.get_stime().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        krb_error.stime = stime.no_asn1_type()?;

        let susec = self.get_susec().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        krb_error.susec = susec.no_asn1_type()?;

        let error_code = self.get_error_code().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        krb_error.error_code = error_code.no_asn1_type()?;

        if let Some(crealm) = self.get_crealm() {
            krb_error.crealm = Some(crealm.no_asn1_type()?);
        }


        return Ok(krb_error);
    }

}

/*
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decode() {
        let mut krb_error_asn1 = KrbErrorAns1::new_empty();
        krb_error_asn1.decode(&[0x7e, 0x81, 0xdc, 0x30, 0x81, 0xd9, 
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
        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2, 0x02, 0x04, 0x00]);


    }

}
*/