use super::ticket::*;
use red_asn1::*;
use std::ops::{Deref, DerefMut};

/// (*SEQUENCE OF Ticket*) Array of [Ticket](./struct.Ticket.html).
#[derive(Debug, PartialEq, Clone, Default)]
pub struct SeqOfTickets {
    tickets: Vec<Ticket>,
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
    #[cfg(test)]
    pub fn new(mut items: Vec<Ticket>) -> Self {
        let mut seq_of = Self::default();
        seq_of.append(&mut items);
        return seq_of;
    }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct SeqOfTicketsAsn1 {
    subtype: SequenceOf<TicketAsn1>,
}

impl SeqOfTicketsAsn1 {
    fn set_asn1_values(&mut self, seq_of_tickets: &SeqOfTickets) {
        for ticket in seq_of_tickets.iter() {
            self.subtype.push(ticket.into());
        }
    }
}

impl From<&SeqOfTickets> for SeqOfTicketsAsn1 {
    fn from(seq_of_tickets: &SeqOfTickets) -> SeqOfTicketsAsn1 {
        let mut seq_tickets_asn1 = Self::default();

        seq_tickets_asn1.set_asn1_values(seq_of_tickets);
        return seq_tickets_asn1;
    }
}

impl Asn1Object for SeqOfTicketsAsn1 {
    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_default_sequence_of_tickets_asn1() {
        assert_eq!(
            SeqOfTicketsAsn1 {
                subtype: SequenceOf::default(),
            },
            SeqOfTicketsAsn1::default()
        )
    }

    #[test]
    fn create_default_seq_of_tickets() {
        let seq_of_tickets = SeqOfTickets::default();
        assert_eq!(Vec::<Ticket>::new(), seq_of_tickets.tickets);
    }
}
