use crate::structs::*;

pub struct TicketFlagsMapper{}

impl TicketFlagsMapper {

    pub fn ticket_flags_to_tktflags(ticket_flags: &TicketFlags) -> u32 {
        return ticket_flags.get_flags();
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn ticket_flags_to_tktflags() {
        let ticket_flags = TicketFlags::new(
            ticketflags::FORWARDABLE | 
            ticketflags::PROXIABLE |
            ticketflags::RENEWABLE |
            ticketflags::INITIAL |
            ticketflags::PRE_AUTHENT
        );

        let tktflags = ticketflags::FORWARDABLE | 
        ticketflags::PROXIABLE |
        ticketflags::RENEWABLE |
        ticketflags::INITIAL |
        ticketflags::PRE_AUTHENT;

        assert_eq!(tktflags, TicketFlagsMapper::ticket_flags_to_tktflags(&ticket_flags));
    }

}