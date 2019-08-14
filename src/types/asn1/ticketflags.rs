use super::kerberosflags::{KerberosFlags, KerberosFlagsAsn1};

/// (*TicketFlags*) Flags for tickets.
pub type TicketFlags = KerberosFlags;
pub(crate) type TicketFlagsAsn1 = KerberosFlagsAsn1;
