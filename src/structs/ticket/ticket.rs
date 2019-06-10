use asn1::*;
use asn1_derive::*;
use super::super::realm::*;
use super::super::principalname::*;
use super::super::encrypteddata::*;

pub struct Ticket {
    tkt_vno: i8,
    realm: Realm,
    sname: PrincipalName,
    enc_part: EncryptedData,
}

impl Ticket {

    pub fn asn1_type(&self) -> TicketAsn1 {
        return TicketAsn1::new();
    } 
}

#[derive(Asn1Sequence)]
#[seq(application_tag = 1)]
pub struct TicketAsn1 {
    #[seq_comp(context_tag = 0)]
    tkt_vno: SeqField<Integer>,
    #[seq_comp(context_tag = 1)]
    realm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 2)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 3)]
    enc_part: SeqField<EncryptedDataAsn1>
    
}

impl TicketAsn1 {

    fn new() -> TicketAsn1 {
        return Self::new_empty();
    }

    fn new_empty() -> TicketAsn1 {
        return TicketAsn1 {
            tkt_vno: SeqField::new(),
            realm: SeqField::new(),
            sname: SeqField::new(),
            enc_part: SeqField::new()
        };
    }

}


impl Asn1InstanciableObject for TicketAsn1 {

    fn new_default() -> TicketAsn1 {
        return TicketAsn1::new_empty();
    }
}