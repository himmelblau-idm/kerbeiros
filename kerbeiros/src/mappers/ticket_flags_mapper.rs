use himmelblau_kerberos_asn1::TicketFlags;

pub struct TicketFlagsMapper {}

impl TicketFlagsMapper {
    pub fn ticket_flags_to_tktflags(ticket_flags: &TicketFlags) -> u32 {
        return **ticket_flags;
    }
    pub fn tktflags_to_ticket_flags(tktflags: u32) -> TicketFlags {
        return TicketFlags::from(tktflags);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use himmelblau_kerberos_constants::ticket_flags;

    #[test]
    fn ticket_flags_to_tktflags() {
        let ticket_flags = TicketFlags::from(
            ticket_flags::FORWARDABLE
                | ticket_flags::PROXIABLE
                | ticket_flags::RENEWABLE
                | ticket_flags::INITIAL
                | ticket_flags::PRE_AUTHENT,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        assert_eq!(
            tktflags,
            TicketFlagsMapper::ticket_flags_to_tktflags(&ticket_flags)
        );
    }

    #[test]
    fn test_tktflags_to_ticket_flags() {
        let ticket_flags = TicketFlags::from(
            ticket_flags::FORWARDABLE
                | ticket_flags::PROXIABLE
                | ticket_flags::RENEWABLE
                | ticket_flags::INITIAL
                | ticket_flags::PRE_AUTHENT,
        );

        let tktflags = ticket_flags::FORWARDABLE
            | ticket_flags::PROXIABLE
            | ticket_flags::RENEWABLE
            | ticket_flags::INITIAL
            | ticket_flags::PRE_AUTHENT;

        assert_eq!(
            ticket_flags,
            TicketFlagsMapper::tktflags_to_ticket_flags(tktflags)
        );
    }
}
