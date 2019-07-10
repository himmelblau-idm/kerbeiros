mod asreq;
pub use asreq::*;

use crate::structs;
pub type KrbError = structs::KrbError;
pub type KdcRep = structs::KdcRep;
pub type AsRep = KdcRep;