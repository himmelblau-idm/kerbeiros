use asn1::*;
use asn1_derive::*;
use super::realm::RealmAsn1;
use super::principalname::PrincipalNameAsn1;
use super::encrypteddata::EncryptedDataAsn1;
use std::ops::{Deref, DerefMut};

pub struct SeqOfTickets {
    tickets: Vec<Ticket>
}

impl Deref for SeqOfTickets {
    type Target = Vec<Ticket>;
    fn deref(&self) -> &Vec<Ticket> {
        &self.tickets
    }
}

impl DerefMut for SeqOfTickets {
    fn deref_mut(&mut self) -> &mut Vec<Ticket> {
        &mut self.tickets
    }
}

impl SeqOfTickets {

    pub fn asn1_type(&self) -> SeqOfTicketsAsn1 {
        return SeqOfTicketsAsn1::new(self);
    }

}


pub struct SeqOfTicketsAsn1 {
    subtype: SequenceOf<TicketAsn1>
}

impl SeqOfTicketsAsn1 {

    fn new(seq_of_tickets: &SeqOfTickets) -> SeqOfTicketsAsn1 {
        let mut seq_tickets_asn1 = Self::new_empty();

        seq_tickets_asn1._set_asn1_values(seq_of_tickets);
        return seq_tickets_asn1;
    }

    fn new_empty() -> Self {
        return Self {
            subtype: SequenceOf::new(),
        };
    }

    fn _set_asn1_values(&mut self, seq_of_tickets: &SeqOfTickets) {
        for ticket in seq_of_tickets.iter() {
            self.subtype.push(ticket.asn1_type());
        }
    }
}

impl Asn1Object for SeqOfTicketsAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>, Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}


impl Asn1Tagged for SeqOfTicketsAsn1 {
    fn type_tag() -> Tag {
        return SequenceOf::<TicketAsn1>::type_tag();
    }
}

impl Asn1InstanciableObject for SeqOfTicketsAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}


/*
Ticket          ::= [APPLICATION 1] SEQUENCE {
        tkt-vno         [0] INTEGER (5),
        realm           [1] Realm,
        sname           [2] PrincipalName,
        enc-part        [3] EncryptedData -- EncTicketPart
}
*/

pub struct Ticket {

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

impl<'a> TicketAsn1 {

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


impl<'a> Asn1InstanciableObject for TicketAsn1 {

    fn new_default() -> TicketAsn1 {
        return TicketAsn1::new_empty();
    }
}

pub struct TGT {
    
}