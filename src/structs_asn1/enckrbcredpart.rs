use asn1::*;
use asn1_derive::*;
use super::uint32::*;
use super::kerberostime::*;
use super::krbcredinfo::*;
use super::hostaddress::*;
use super::microseconds::*;


struct EncKrbCredPart {
    ticket_info: KrbCredInfo,
    nonce: Option<UInt32>,
    timestamp: Option<KerberosTime>,
    usec: Option<Microseconds>,
    s_address: Option<HostAddress>,
    r_address: Option<HostAddress>
}


impl EncKrbCredPart {

    fn new(ticket_info: KrbCredInfo) -> Self {
        return Self {
            ticket_info,
            nonce: None,
            timestamp: None,
            usec: None,
            s_address: None,
            r_address: None
        };
    }

    fn set_nonce(&mut self, nonce: UInt32) {
        self.nonce = Some(nonce);
    }

    fn set_timestamp(&mut self, timestamp: KerberosTime) {
        self.timestamp = Some(timestamp);
    }

    fn set_usec(&mut self, usec: Microseconds) {
        self.usec = Some(usec);
    }

    fn set_s_address(&mut self, s_address: HostAddress) {
        self.s_address = Some(s_address);
    }

    fn set_r_address(&mut self, r_address: HostAddress) {
        self.r_address = Some(r_address);
    }

}

/*
#[derive(Asn1Sequence)]
#[seq(application_tag = 29)]
struct EncKrbCredPartAsn1 {
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