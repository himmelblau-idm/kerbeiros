mod asreq;
pub use asreq::*;

use crate::structs;
pub use structs::KrbError;
pub use structs::KdcRep;
pub type AsRep = KdcRep;