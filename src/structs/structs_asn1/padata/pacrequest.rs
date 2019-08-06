use red_asn1::*;
use crate::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct PacRequest {
    include_pac: bool
}

impl PacRequest {

    pub fn new(include_pac: bool) -> Self {
        return Self {
            include_pac
        };
    }

    pub fn asn1_type(&self) -> PacRequestAsn1 {
        return PacRequestAsn1::new(&self);
    }

    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let mut pac_request_asn1 = PacRequestAsn1::default();
        pac_request_asn1.decode(raw)?;
        return Ok(pac_request_asn1.no_asn1_type().unwrap());

    }

}


#[derive(Sequence)]
pub struct PacRequestAsn1 {
    #[seq_field(context_tag = 0)]
    include_pac: SeqField<Boolean>
}

impl PacRequestAsn1 {

    fn new(pac_request: &PacRequest) -> PacRequestAsn1 {
        let mut pac_request_asn1 = Self::default();
        
        pac_request_asn1.set_include_pac(Boolean::from(pac_request.include_pac));

        return pac_request_asn1;
    }

    fn default() -> Self {
        return Self{
            include_pac: SeqField::default()
        };
    }

    fn no_asn1_type(&self) -> KerberosResult<PacRequest> {
        let include_pac_asn1 =  self.get_include_pac().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("PacRequest::include_pac".to_string())
        )?;
        let include_pac = include_pac_asn1.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("PacRequest::include_pac".to_string())
        )?;

        return Ok(PacRequest::new(include_pac));
    }

}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_encode_pac_request_true() {
        assert_eq!(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
        PacRequest::new(true).asn1_type().encode().unwrap());
    }

    #[test]
    fn test_encode_pac_request_false() {
        assert_eq!(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00],
        PacRequest::new(false).asn1_type().encode().unwrap());
    }


    #[test]
    fn test_decode_pac_request_true() {
        let mut pac_request_asn1 = PacRequestAsn1::default();

        pac_request_asn1.decode(&[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]).unwrap();

        assert_eq!(PacRequest::new(true), pac_request_asn1.no_asn1_type().unwrap());
    }

    #[test]
    fn test_decode_pac_request_false() {
        let mut pac_request_asn1 = PacRequestAsn1::default();

        pac_request_asn1.decode(&[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00]).unwrap();

        assert_eq!(PacRequest::new(false), pac_request_asn1.no_asn1_type().unwrap());
    }

}