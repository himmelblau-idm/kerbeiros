use super::super::encrypted_data::{EncryptedDataAsn1, EncryptedData};
use super::super::int32::{Int32, Int32Asn1};
use super::etype_info_2::{EtypeInfo2, EtypeInfo2Asn1};
use super::pac_request::{PacRequest,PacRequestAsn1};
use crate::constants::pa_data_types::{PA_PAC_REQUEST, PA_ETYPE_INFO2, PA_ENC_TIMESTAMP};
use crate::error::{ErrorKind, Result};
use red_asn1::*;

/// (*PA-DATA*) Container that encapsules different types of preauthentication data structures.
#[derive(Debug, Clone, PartialEq)]
pub enum PaData {
    Raw(Int32, Vec<u8>),
    EtypeInfo2(EtypeInfo2),
    PacRequest(PacRequest),
    EncTimestamp(EncryptedData),
}

impl PaData {
    pub fn new(data_type: Int32, data: Vec<u8>) -> Self {
        match data_type {
            PA_PAC_REQUEST => match PacRequest::parse(&data) {
                Ok(pac_request) => PaData::PacRequest(pac_request),
                Err(_) => Self::Raw(data_type, data),
            },
            PA_ETYPE_INFO2 => match EtypeInfo2::parse(&data) {
                Ok(etype_info2) => PaData::EtypeInfo2(etype_info2),
                Err(_) => Self::Raw(data_type, data),
            },
            _ => PaData::Raw(data_type, data),
        }
    }

    pub fn padata_type(&self) -> Int32 {
        match self {
            PaData::Raw(padata_type, _) => *padata_type,
            PaData::PacRequest(_) => PA_PAC_REQUEST,
            PaData::EtypeInfo2(_) => PA_ETYPE_INFO2,
            PaData::EncTimestamp(_) => PA_ENC_TIMESTAMP,
        }
    }

    pub fn padata_value_as_bytes(&self) -> Vec<u8> {
        match self {
            PaData::Raw(_, padata_value) => padata_value.clone(),
            PaData::PacRequest(pac_request) => PacRequestAsn1::from(pac_request).encode().unwrap(),
            PaData::EtypeInfo2(etype_info2) => EtypeInfo2Asn1::from(etype_info2).encode().unwrap(),
            PaData::EncTimestamp(enc_data) => EncryptedDataAsn1::from(enc_data.clone()).encode().unwrap(),
        }
    }
}

#[derive(Sequence, Default, Debug, PartialEq)]
pub(crate) struct PaDataAsn1 {
    #[seq_field(context_tag = 1)]
    padata_type: SeqField<Int32Asn1>,
    #[seq_field(context_tag = 2)]
    padata_value: SeqField<OctetString>,
}

impl PaDataAsn1 {
    fn set_asn1_values(&mut self, pa_data: &PaData) {
        self.set_padata_type(pa_data.padata_type().into());
        self.set_padata_value(pa_data.padata_value_as_bytes().into());
    }

    pub fn no_asn1_type(&self) -> Result<PaData> {
        let padata_type_asn1 = self
            .get_padata_type()
            .ok_or_else(|| ErrorKind::NotAvailableData("PaData::type".to_string()))?;
        let padata_type = padata_type_asn1.no_asn1_type()?;
        let padata_value_asn1 = self
            .get_padata_value()
            .ok_or_else(|| ErrorKind::NotAvailableData("PaData::value".to_string()))?;
        let padata_value = padata_value_asn1
            .value()
            .ok_or_else(|| ErrorKind::NotAvailableData("PaData::value".to_string()))?;

        return Ok(PaData::new(padata_type, padata_value.clone()));
    }
}

impl From<&PaData> for PaDataAsn1 {
    fn from(pa_data: &PaData) -> PaDataAsn1 {
        let mut pa_data_asn1 = Self::default();
        pa_data_asn1.set_asn1_values(pa_data);
        return pa_data_asn1;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_default_padata_asn1() {
        assert_eq!(
            PaDataAsn1 {
                padata_type: SeqField::default(),
                padata_value: SeqField::default(),
            },
            PaDataAsn1::default()
        )
    }

    #[test]
    fn test_encode_padata_pac_request() {
        assert_eq!(
            vec![
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30, 0x05,
                0xa0, 0x03, 0x01, 0x01, 0xff
            ],
            PaDataAsn1::from(&PaData::PacRequest(PacRequest::new(true)))
                .encode()
                .unwrap()
        );
        assert_eq!(
            vec![
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30, 0x05,
                0xa0, 0x03, 0x01, 0x01, 0x00
            ],
            PaDataAsn1::from(&PaData::PacRequest(PacRequest::new(false)))
                .encode()
                .unwrap()
        );
    }

    #[test]
    fn test_decode_padata_pac_request() {
        let mut padata_asn1 = PaDataAsn1::default();

        padata_asn1
            .decode(&[
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30, 0x05,
                0xa0, 0x03, 0x01, 0x01, 0xff,
            ])
            .unwrap();

        assert_eq!(
            PaData::PacRequest(PacRequest::new(true)),
            padata_asn1.no_asn1_type().unwrap()
        );

        padata_asn1
            .decode(&[
                0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x09, 0x04, 0x07, 0x30, 0x05,
                0xa0, 0x03, 0x01, 0x01, 0x00,
            ])
            .unwrap();

        assert_eq!(
            PaData::PacRequest(PacRequest::new(false)),
            padata_asn1.no_asn1_type().unwrap()
        );
    }
}
