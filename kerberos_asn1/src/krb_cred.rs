use crate::{Int32, Ticket, EncryptedData};
use red_asn1::{SequenceOf, Asn1Object};
use red_asn1_derive::Sequence;

/// (*KRB-CRED*) Message used to send Kerberos credentials form one principal to another.
/// Defined in RFC4120, section 5.8.1.
/// ```asn1
/// KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
///        pvno            [0] INTEGER (5),
///        msg-type        [1] INTEGER (22),
///        tickets         [2] SEQUENCE OF Ticket,
///        enc-part        [3] EncryptedData -- EncKrbCredPart
/// }
/// ```
#[derive(Sequence, Default, Debug, Clone, PartialEq)]
#[seq(application_tag = 22)]
pub struct KrbCred {
    #[seq_field(context_tag = 0)]
    pub pvno: Int32,
    #[seq_field(context_tag = 1)]
    pub msg_type: Int32,
    #[seq_field(context_tag = 2)]
    pub tickets: SequenceOf<Ticket>,
    #[seq_field(context_tag = 3)]
    pub enc_part: EncryptedData,
}
