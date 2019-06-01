use asn1::*;
use asn1_derive::*;
use super::int32::Int32Asn1;
use super::uint32::UInt32Asn1;

pub struct EncryptedData {
}


impl EncryptedData {

    pub fn asn1_type(&self) -> EncryptedDataAsn1 {
        return EncryptedDataAsn1::new();
    }

}

#[derive(Asn1Sequence)]
pub struct EncryptedDataAsn1 {
    #[seq_comp(context_tag = 0)]
    etype: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1, optional)]
    kvno: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 2)]
    cipher: SeqField<OctetString>
}

impl EncryptedDataAsn1 {

    fn new() -> EncryptedDataAsn1 {
        return Self::new_empty();
    }

    fn new_empty() -> EncryptedDataAsn1 {
        return EncryptedDataAsn1{
            etype: SeqField::new(),
            kvno: SeqField::new(),
            cipher: SeqField::new()
        };
    }
}

impl Asn1Tagged for EncryptedDataAsn1 {
    fn type_tag() -> Tag {
        return Sequence::type_tag();
    }
}

impl Asn1InstanciableObject for EncryptedDataAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}
