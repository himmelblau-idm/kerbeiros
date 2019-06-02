use asn1::*;
use asn1_derive::*;
use super::pacrequest::PacRequest;
use super::super::int32::*;
use super::super::super::error::*;


pub static PA_TGS_REQ : i32 = 1;
pub static PA_ENC_TIMESTAMP : i32 = 2;
pub static PA_ETYPE_INFO : i32 = 11;
pub static PA_PK_AS_REQ_OLD : i32 = 14;
pub static PA_PK_AS_REP_OLD : i32 = 15;
pub static PA_PK_AS_REQ : i32 = 16;
pub static PA_PK_AS_REP : i32 = 17;
pub static PA_ETYPE_INFO2 : i32 = 19;
pub static PA_PAC_REQUEST : i32 = 128;
pub static PA_SVR_REFERRAL_INFO : i32 = 20;
pub static PA_FX_COOKIE : i32 = 133;
pub static PA_FX_FAST : i32 = 136;
pub static PA_FX_ERROR : i32 = 137;
pub static PA_ENCRYPTED_CHALLENGE : i32 = 138;
pub static PA_SUPPORTED_ENCTYPES : i32 = 165;
pub static PA_PAC_OPTIONS : i32 = 167;


#[derive(Debug, Clone, PartialEq)]
pub enum PaData {
    //Raw(Int32, Vec<u8>),
    /*EncTimestamp(EncTimestamp),
    PkAsReq(PkAsReq),
    PkAsRep(PkAkRep),
    EtypeInfo2(EtypeInfo2),*/
    PacRequest(PacRequest)
}

impl PaData {

    fn get_padata_type(&self) -> Int32 {
        match self {
            // PaData::Raw(padata_type,_) => padata_type.clone(),
            PaData::PacRequest(_) => Int32::new(PA_PAC_REQUEST)
        }
    } 

    fn get_padata_value_as_bytes(&self) -> Vec<u8> {
        match self {
            PaData::PacRequest(pac_request) => pac_request.asn1_type().encode().unwrap()
        }
    }

    pub fn asn1_type(&self) -> PaDataAsn1 {
        return PaDataAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
pub struct PaDataAsn1 {
    #[seq_comp(context_tag = 1)]
    padata_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 2)]
    padata_value: SeqField<OctetString>
}

impl PaDataAsn1 {

    fn new(pa_data: &PaData) -> PaDataAsn1 {
        let mut pa_data_asn1 = Self::new_empty();
        pa_data_asn1._set_asn1_values(pa_data);
        return pa_data_asn1;
    }

    fn new_empty() -> PaDataAsn1 {
        let pa_data_asn1 = PaDataAsn1 {
            padata_type: SeqField::new(),
            padata_value: SeqField::new(),
        };
        return pa_data_asn1;
    }

    fn _set_asn1_values(&mut self, pa_data: &PaData) {
        self.set_padata_type(pa_data.get_padata_type().asn1_type());
        self.set_padata_value(OctetString::new(pa_data.get_padata_value_as_bytes()));
    }

    pub fn no_asn1_type(&self) -> KerberosResult<PaData> {
        return Err(KerberosErrorKind::NotAvailableData)?;
        /*
        let padata_type_asn1 = self.get_padata_type().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let padata_type = padata_type_asn1.no_asn1_type()?;
        let padata_value_asn1 = self.get_padata_value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;
        let padata_value = padata_value_asn1.value().ok_or_else(|| KerberosErrorKind::NotAvailableData)?;

        let padata = match *padata_type {
            PA_PAC_REQUEST => {
                PaData::PacRequest()
            },
            _ => PaData::Raw(padata_type, padata_value.clone())
        };

        return Ok(padata);
        */
    }

}

impl Asn1InstanciableObject for PaDataAsn1 {

    fn new_default() -> PaDataAsn1 {
        return PaDataAsn1::new_empty();
    }
}

impl Asn1Tagged for PaDataAsn1 {
    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_padata_pac_request(){
        assert_eq!(vec![0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                        PaData::PacRequest(PacRequest::new(true)).asn1_type().encode().unwrap()
        );
        assert_eq!(vec![0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00],
                        PaData::PacRequest(PacRequest::new(false)).asn1_type().encode().unwrap()
        );
    }

    #[test]
    fn test_decode_padata_pac_request(){
        let mut padata_asn1 = PaDataAsn1::new_empty();

        padata_asn1.decode(&[0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]).unwrap();

        assert_eq!(PaData::PacRequest(PacRequest::new(true)), padata_asn1.no_asn1_type().unwrap());

        padata_asn1.decode(&[0x30, 0x11, 
                        0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 
                        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00]).unwrap();

        assert_eq!(PaData::PacRequest(PacRequest::new(true)), padata_asn1.no_asn1_type().unwrap());
    }

}