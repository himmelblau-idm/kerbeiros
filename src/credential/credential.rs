use crate::structs::*;

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

    pub fn get_crealm(&self) -> &Realm {
        return &self.crealm;
    }

    pub fn get_cname(&self) -> &PrincipalName {
        return &self.cname;
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

    pub fn to_ccache_credential(&self) -> ccache::CredentialEntry {

        let is_skey = 0;

        let time = TimesMapper::authtime_starttime_endtime_renew_till_to_times(
            self.client_part.get_authtime(),
            self.client_part.get_starttime(),
            self.client_part.get_endtime(),
            self.client_part.get_renew_till(),
        );

        let tktflags = TicketFlagsMapper::ticket_flags_to_tktflags(self.client_part.get_flags());

        let key = KeyBlockMapper::encryption_key_to_keyblock(self.client_part.get_key());

        let ticket = ccache::CountedOctetString::new(self.ticket.build());

        let client = PrincipalMapper::realm_and_principal_name_to_principal(&self.crealm, &self.cname);
        let server = PrincipalMapper::realm_and_principal_name_to_principal(
            self.client_part.get_srealm(), 
            self.client_part.get_sname(),
        );

        let ccache_credential = ccache::CredentialEntry::new(
            client, 
            server, 
            key, 
            time, 
            is_skey, 
            tktflags, 
            ticket
        );

        return ccache_credential;
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

        let caddr = HostAddresses::new(HostAddress::NetBios("HOLLOWBASTION".to_string()));
        let ticket_flags = TicketFlags::new(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let credential = create_credential(
            encryption_key.clone(), realm.clone(), pname.clone(), ticket_flags.clone(), 
            auth_time.clone(), starttime.clone(), endtime.clone(), renew_till.clone(), 
            realm.clone(), sname.clone(), caddr.clone()
        );

        let krb_cred_info = create_krb_cred_info(
            encryption_key.clone(), realm.clone(), pname.clone(), ticket_flags.clone(), 
            auth_time.clone(), starttime.clone(), endtime.clone(), renew_till.clone(), 
            realm.clone(), sname.clone(), caddr.clone()
        );

        assert_eq!(krb_cred_info, credential.to_krb_info());
    }


    fn create_krb_cred_info(
        encryption_key: EncryptionKey, prealm: Realm, pname: PrincipalName, ticket_flags: TicketFlags,
        authtime: KerberosTime, starttime: KerberosTime, endtime: KerberosTime, renew_till: KerberosTime,
        srealm: Realm, sname: PrincipalName, caddr: HostAddresses
    ) -> KrbCredInfo {
        let mut krb_cred_info = KrbCredInfo::new(encryption_key);
        krb_cred_info.set_prealm(prealm);
        krb_cred_info.set_pname(pname);
        krb_cred_info.set_flags(ticket_flags);
        krb_cred_info.set_authtime(authtime);
        krb_cred_info.set_starttime(starttime);
        krb_cred_info.set_endtime(endtime);
        krb_cred_info.set_renew_till(renew_till);
        krb_cred_info.set_srealm(srealm);
        krb_cred_info.set_sname(sname);
        krb_cred_info.set_caddr(caddr);

        return krb_cred_info;
    }

    fn create_credential(
        encryption_key: EncryptionKey, prealm: Realm, pname: PrincipalName, ticket_flags: TicketFlags,
        authtime: KerberosTime, starttime: KerberosTime, endtime: KerberosTime, renew_till: KerberosTime,
        srealm: Realm, sname: PrincipalName, caddr: HostAddresses
    ) -> Credential {
        let nonce = 0;
        let mut enc_as_rep_part = EncKdcRepPart::new(
            encryption_key,
            LastReq::new_empty(),
            nonce,
            ticket_flags,
            authtime,
            endtime,
            srealm.clone(),
            sname.clone()
        );
        enc_as_rep_part.set_starttime(starttime);
        enc_as_rep_part.set_renew_till(renew_till);
        enc_as_rep_part.set_caddr(caddr);

        let ticket = Ticket::new(
            srealm.clone(), 
            sname.clone(), 
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x0])
        );

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket, 
            enc_as_rep_part
        );

        return credential;
    }

}
