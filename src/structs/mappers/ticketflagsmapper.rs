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
            ticket_flags::FORWARDABLE | 
            ticket_flags::PROXIABLE |
            ticket_flags::RENEWABLE |
            ticket_flags::INITIAL |
            ticket_flags::PRE_AUTHENT
        );

        let tktflags = ticket_flags::FORWARDABLE | 
        ticket_flags::PROXIABLE |
        ticket_flags::RENEWABLE |
        ticket_flags::INITIAL |
        ticket_flags::PRE_AUTHENT;

        assert_eq!(tktflags, TicketFlagsMapper::ticket_flags_to_tktflags(&ticket_flags));
    }

}