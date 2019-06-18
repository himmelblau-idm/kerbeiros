use asn1::*;
use asn1_derive::*;
use super::encryptionkey::*;
use super::uint32::*;
use super::lastreq::*;
use super::kerberostime::*;
use super::ticketflags::*;
use super::realm::*;
use super::principalname::*;
use super::hostaddress::*;

struct EncASRepPart {

}

#[derive(Asn1Sequence)]
#[seq(application_tag = 25)]
struct EncASRepPartAsn1 {
    #[seq_comp(context_tag = 0)]
    key: SeqField<EncryptionKeyAsn1>,
    #[seq_comp(context_tag = 1)]
    last_req: SeqField<LastReqAsn1>,
    #[seq_comp(context_tag = 2)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 3, optional)]
    key_expiration: SeqField<KerberosTime>,
    #[seq_comp(context_tag = 4)]
    flags: SeqField<TicketFlags>,
    #[seq_comp(context_tag = 5)]
    authtime: SeqField<KerberosTime>,
    #[seq_comp(context_tag = 6)]
    starttime: SeqField<KerberosTime>,
    #[seq_comp(context_tag = 7)]
    endtime: SeqField<KerberosTime>,
    #[seq_comp(context_tag = 8)]
    renew_till: SeqField<KerberosTime>,
    #[seq_comp(context_tag = 9)]
    srealm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 10)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 11)]
    caddr: SeqField<HostAddressesAsn1>,

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_enc_as_rep_part() {
        let raw: Vec<u8> = vec![];

        let mut enc_as_rep_part_asn1 = EncASRepPartAsn1::new_empty();
        enc_as_rep_part_asn1.decode(&raw).unwrap();


        let encryption_key = EncryptionKey::new(
            Int32::new(0x12),
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );

        let mut last_req = LastReq::new_empty();
        last_req.push(LastReqEntry::new(
            Int32::new(0),
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        ));

        let mut ticket_flags = TicketFlags::new();
        ticket_flags.set_flags(1088421888);

        let kerb_time = KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));

        let mut sname =  PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        sname_ticket.push(KerberosString::_from("KINGDOM.HEARTS"));

        let enc_as_rep_part = EncASRepPart::new(
            encryption_key,
            last_req,
            UInt32::new(104645460),
            ticket_flags,
            kerb_time.clone(),
            kerb_time.clone(),
            Realm::_from("KINGDOM.HEARTS"),
            sname
        )

        enc_as_rep_part.set_key_expiration(
            KerberosTime::new(Utc.ymd(2037, 9, 14).and_hms(02, 48, 05))
        );

        enc_as_rep_part.set_starttime(kerb_time.clone());
        enc_as_rep_part.set_renew_till(kerb_time);
        enc_as_rep_part.set_caddr(
            HostAddresses::new(
                HostAddress::NetBios("HOLLOWBASTION".to_string())
            )
        );

        assert_eq!(enc_as_rep_part, enc_as_rep_part_asn1.no_asn1_type().unwrap());

    }

}