use crate::structs::*;

pub struct KrbInfoMapper{}

impl KrbInfoMapper {

    pub fn enc_kdc_rep_part_to_krb_cred_info(enc_kdc_rep_part: &EncKdcRepPart) -> KrbCredInfo {

        let mut krb_cred_info = KrbCredInfo::new(enc_kdc_rep_part.get_key().clone());

        krb_cred_info.set_flags(enc_kdc_rep_part.get_flags().clone());
        krb_cred_info.set_authtime(enc_kdc_rep_part.get_authtime().clone());
        
        if let Some(starttime) = enc_kdc_rep_part.get_starttime() {
            krb_cred_info.set_starttime(starttime.clone());
        }
        krb_cred_info.set_endtime(enc_kdc_rep_part.get_endtime().clone());

        if let Some(renew_till) = enc_kdc_rep_part.get_renew_till() {
            krb_cred_info.set_renew_till(renew_till.clone());
        }

        krb_cred_info.set_srealm(enc_kdc_rep_part.get_srealm().clone());
        krb_cred_info.set_sname(enc_kdc_rep_part.get_sname().clone());

        if let Some(caddr) = enc_kdc_rep_part.get_caddr() {
            krb_cred_info.set_caddr(caddr.clone());
        }

        return krb_cred_info;

    }

}



#[cfg(test)]

mod test {
    use super::*;
    use crate::constants::*;
    use chrono::prelude::*;

    #[test]
    fn enc_kdc_rep_part_to_krb_info() {

        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();

        let mut sname = PrincipalName::new(
            NT_SRV_INST, 
            KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x89, 0x4d, 0x65, 0x37, 0x37, 0x12, 0xcc, 0xbd, 
                0x4e, 0x51, 0x1e, 0xe1, 0x8f, 0xef, 0x51, 0xc4, 
                0xd4, 0xa5, 0xd2, 0xef, 0x88, 0x81, 0x6d, 0xde, 
                0x85, 0x72, 0x5f, 0x70, 0xc2, 0x78, 0x47, 0x86
            ]
        );

        let auth_time = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let starttime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let endtime = Utc.ymd(2019, 4, 18).and_hms(16, 00, 31);
        let renew_till = Utc.ymd(2019, 4, 25).and_hms(06, 00, 31);

        let caddr = HostAddresses::new(HostAddress::NetBios("HOLLOWBASTION".to_string()));
        let ticket_flags = TicketFlags::new(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let nonce = 0;
        let mut enc_kdc_rep_part = EncKdcRepPart::new(
            encryption_key.clone(),
            LastReq::new_empty(),
            nonce,
            ticket_flags.clone(),
            auth_time.clone(),
            endtime.clone(),
            realm.clone(),
            sname.clone()
        );
        enc_kdc_rep_part.set_starttime(starttime.clone());
        enc_kdc_rep_part.set_renew_till(renew_till.clone());
        enc_kdc_rep_part.set_caddr(caddr.clone());

        let mut krb_cred_info = KrbCredInfo::new(encryption_key.clone());
        krb_cred_info.set_flags(ticket_flags.clone());
        krb_cred_info.set_authtime(auth_time.clone());
        krb_cred_info.set_starttime(starttime.clone());
        krb_cred_info.set_endtime(endtime.clone());
        krb_cred_info.set_renew_till(renew_till.clone());
        krb_cred_info.set_srealm(realm.clone());
        krb_cred_info.set_sname(sname.clone());
        krb_cred_info.set_caddr(caddr.clone());

        assert_eq!(krb_cred_info, KrbInfoMapper::enc_kdc_rep_part_to_krb_cred_info(&enc_kdc_rep_part));
    }

}