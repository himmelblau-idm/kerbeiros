mod asreq;
pub use asreq::*;

use crate::structs_asn1;
pub type KrbError = structs_asn1::KrbError;
pub type KdcRep = structs_asn1::KdcRep;
pub type AsRep = KdcRep;