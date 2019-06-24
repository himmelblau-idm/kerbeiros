mod asreq;
pub use asreq::*;

mod asrep;
pub use asrep::*;

use crate::structs_asn1;
pub type KrbError = structs_asn1::KrbError;