use asn1::*;
use asn1_derive::*;
use super::ticket::*;
use super::encrypteddata::*;

/*
#[derive(Asn1Sequence)]
#[seq(application_tag = 29)]
struct KrbCredAsn1 {
    #[seq_comp(context_tag = 0)]
    ticket_info: SeqField<SeqOfKrbCredInfoAsn1>,
    #[seq_comp(context_tag = 1, optional)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 2, optional)]
    timestamp: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 3, optional)]
    usec: SeqField<MicrosecondsAsn1>,
    #[seq_comp(context_tag = 4, optional)]
    s_address: SeqField<HostAddressAsn1>,
    #[seq_comp(context_tag = 5, optional)]
    r_address: SeqField<HostAddressAsn1>,
    
}
*/