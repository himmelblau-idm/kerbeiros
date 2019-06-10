use asn1::*;
use asn1_derive::*;

use super::principalname::*;
use super::realm::*;
use super::padata::*;
use super::ticket::*;
use super::encrypteddata::*;

pub struct AsRep {
    pvno: i8,
    msg_type: i8,
    padata: Option<SeqOfPaData>,
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    enc_part: EncryptedData
}


#[derive(Asn1Sequence)]
#[seq(application_tag = 11)]
struct AsRepAsn1 {
    #[seq_comp(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_comp(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_comp(context_tag = 2, optional)]
    padata: SeqField<SeqOfPaDataAsn1>,
    #[seq_comp(context_tag = 3)]
    crealm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 4)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 5)]
    ticket: SeqField<TicketAsn1>,
    #[seq_comp(context_tag = 6)]
    enc_part: SeqField<EncryptedDataAsn1>,
}



