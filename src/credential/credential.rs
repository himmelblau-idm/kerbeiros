use crate::structs_asn1::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    client_part: EncKdcRepPart
}


impl Credential {

    pub fn new(
        crealm: Realm, cname: PrincipalName, 
        ticket: Ticket, client_part: EncKdcRepPart 
    ) -> Self {
        return Self{
            crealm,
            cname,
            ticket,
            client_part
        };
    }

    pub fn get_ticket(&self) -> &Ticket {
        return &self.ticket;
    }

    pub fn to_krb_info(&self) -> KrbCredInfo {
        let mut krb_cred_info = self.client_part.to_krb_cred_info();

        krb_cred_info.set_prealm(self.crealm.clone());
        krb_cred_info.set_pname(self.cname.clone());
        return krb_cred_info;
    }

}

#[cfg(test)]

mod test {
    use super::*;
    use crate::constants::*;
    use chrono::prelude::*;

    #[test]
    fn convert_to_krb_info() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();

        let mut sname = PrincipalName::new(
            NT_SRV_INST, 
            KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let pname = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("mickey").unwrap()
        );

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
        let key_expiration = Utc.ymd(2037, 9, 14).and_hms(02, 48, 05);

        let caddr = HostAddresses::new(HostAddress::NetBios("HOLLOWBASTION".to_string()));
        let nonce = 104645460;
        let ticket_flags = TicketFlags::new(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let mut last_req = LastReq::new_empty();
        last_req.push(LastReqEntry::new(0, Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)));

        let mut encrypted_pa_datas = MethodData::new();
        encrypted_pa_datas.push(PaData::Raw(PA_SUPPORTED_ENCTYPES, vec![0x1f, 0x0, 0x0, 0x0]));

        let mut enc_as_rep_part = EncKdcRepPart::new(
            encryption_key.clone(),
            last_req,
            nonce,
            ticket_flags.clone(),
            auth_time.clone(),
            endtime.clone(),
            realm.clone(),
            sname.clone()
        );
        enc_as_rep_part.set_key_expiration(key_expiration.clone());
        enc_as_rep_part.set_starttime(starttime.clone());
        enc_as_rep_part.set_renew_till(renew_till.clone());
        enc_as_rep_part.set_caddr(caddr.clone());
        enc_as_rep_part.set_encrypted_pa_data(encrypted_pa_datas);

        let ticket = Ticket::new(
            5, 
            realm.clone(), 
            sname.clone(), 
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x0])
        );

        let credential = Credential::new(
            realm.clone(),
            pname.clone(),
            ticket, 
            enc_as_rep_part
        );

        let mut krb_cred_info = KrbCredInfo::new(encryption_key.clone());
        krb_cred_info.set_prealm(realm.clone());
        krb_cred_info.set_pname(pname.clone());
        krb_cred_info.set_flags(ticket_flags.clone());
        krb_cred_info.set_authtime(auth_time.clone());
        krb_cred_info.set_starttime(starttime.clone());
        krb_cred_info.set_endtime(endtime.clone());
        krb_cred_info.set_renew_till(renew_till.clone());
        krb_cred_info.set_srealm(realm.clone());
        krb_cred_info.set_sname(sname.clone());
        krb_cred_info.set_caddr(caddr.clone());

        assert_eq!(krb_cred_info, credential.to_krb_info());
    }

}
