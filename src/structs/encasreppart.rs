use crate::structs_asn1;
use chrono::prelude::*;
use ascii::*;

#[derive(Debug, Clone, PartialEq)]
pub struct EncAsRepPart {
    nonce: u32,
    key_expiration: Option<DateTime<Utc>>,
    flags: u32,
    authtime: DateTime<Utc>,
    starttime: Option<DateTime<Utc>>,
    endtime: DateTime<Utc>,
    renew_till: Option<DateTime<Utc>>,
    realm: AsciiString,

}


#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;
    use crate::structs_asn1::*;

    #[test]
    fn test_convert_from_asn1_struct() {
        let encryption_key = EncryptionKey::new(
            Int32::new(AES256_CTS_HMAC_SHA1_96),
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

        let mut ticket_flags = TicketFlags::new_empty();
        ticket_flags.set_flags(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let kerb_time = KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));

        let mut sname =  PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        sname.push(KerberosString::_from("KINGDOM.HEARTS"));

        let mut encrypted_pa_datas = MethodData::new();
        encrypted_pa_datas.push(
            PaData::Raw(Int32::new(PA_SUPPORTED_ENCTYPES), vec![0x1f, 0x0, 0x0, 0x0])
        );

        let mut enc_as_rep_part = structs_asn1::EncAsRepPart::new(
            encryption_key,
            last_req,
            UInt32::new(104645460),
            ticket_flags,
            kerb_time.clone(),
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(16, 00, 31)),
            Realm::_from("KINGDOM.HEARTS"),
            sname
        );

        enc_as_rep_part.set_key_expiration(
            KerberosTime::new(Utc.ymd(2037, 9, 14).and_hms(02, 48, 05))
        );

        enc_as_rep_part.set_starttime(kerb_time);
        enc_as_rep_part.set_renew_till(
            KerberosTime::new(Utc.ymd(2019, 4, 25).and_hms(06, 00, 31))
        );
        enc_as_rep_part.set_caddr(
            HostAddresses::new(
                HostAddress::NetBios("HOLLOWBASTION".to_string())
            )
        );
        enc_as_rep_part.set_encrypted_pa_data(encrypted_pa_datas);




    }


}