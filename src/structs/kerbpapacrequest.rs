use asn1::*;
use asn1_derive::*;

pub struct KerbPaPacRequest {
    include_pac: bool
}

impl KerbPaPacRequest {

    pub fn new(include_pac: bool) -> KerbPaPacRequest{
        return KerbPaPacRequest{
            include_pac
        };
    }

    pub fn asn1(&self) -> Box<Asn1Object> {
        return Box::new(KerbPaPacRequestAsn1::new(&self));
    }
}


#[derive(Asn1Sequence)]
struct KerbPaPacRequestAsn1 {
    #[seq_comp(context_tag = 0)]
    include_pac: SeqField<Boolean>
}

impl KerbPaPacRequestAsn1 {

    fn new(pac_request: &KerbPaPacRequest) -> KerbPaPacRequestAsn1 {
        let mut pac_request_asn1 = Self::new_empty();
        
        pac_request_asn1.set_include_pac(Boolean::new(pac_request.include_pac));

        return pac_request_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            include_pac: SeqField::new()
        };
    }

}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_encode_pac_request_true() {
        assert_eq!(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
        KerbPaPacRequest::new(true).asn1().encode().unwrap());
    }

    #[test]
    fn test_encode_pac_request_false() {
        assert_eq!(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00],
        KerbPaPacRequest::new(false).asn1().encode().unwrap());
    }


}