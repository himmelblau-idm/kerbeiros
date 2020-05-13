use crate::KerberosFlags;
use red_asn1::Asn1Object;
use red_asn1_derive::Sequence;

/// (*PA-PAC-OPTIONS*) To request options of the PAC.
/// Defined in MS-KILE, section 2.2.10 and MS-SFU, section 2.2.5.
/// ```asn1
/// PA-PAC-OPTIONS ::= SEQUENCE {
///     KerberosFlags
///       --Claims (0)
///       --Branch Aware (1)
///       --Forward to Full DC (2)
///       -- resource-based constrained delegation (3)
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
pub struct PaPacOptions {
    pub kerberos_flags: KerberosFlags,
}
