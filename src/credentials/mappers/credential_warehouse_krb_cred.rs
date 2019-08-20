use crate::types::*;
use super::*;
use super::super::*;
use crate::constants::*;

pub struct CredentialWarehouseKrbCredMapper{}


impl CredentialWarehouseKrbCredMapper {

    pub fn credential_warehouse_to_krb_cred(warehouse: &CredentialWarehouse) -> KrbCred {
        let credentials = warehouse.credentials();
        let mut seq_of_tickets = SeqOfTickets::default();
        let mut seq_of_krb_cred_info = SeqOfKrbCredInfo::default();

        for credential in credentials.iter() {
            let (krb_cred_info, ticket) = CredentialKrbInfoMapper::credential_to_krb_info_and_ticket(credential);
            seq_of_tickets.push(ticket);
            seq_of_krb_cred_info.push(krb_cred_info);
        }
        
        let enc_krb_cred_part = EncKrbCredPart::new(
            seq_of_krb_cred_info
        );

        return KrbCred::new(
            seq_of_tickets,
            EncryptedData::new(NO_ENCRYPTION, enc_krb_cred_part.build())
        )
    }


}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crate::constants::ticket_flags;

    #[test]
    fn credential_warehouse_to_krb_cred() {
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
            ticket_flags::INITIAL 
            | ticket_flags::FORWARDABLE 
            | ticket_flags::PRE_AUTHENT 
            | ticket_flags::RENEWABLE
        );

        let ticket_credential = create_ticket(realm.clone(), sname.clone());

        let credential = create_credential(
            encryption_key.clone(), realm.clone(), pname.clone(), ticket_flags.clone(), 
            auth_time.clone(), starttime.clone(), endtime.clone(), renew_till.clone(), 
            realm.clone(), sname.clone(), Some(caddr.clone()), ticket_credential
        );

        let krb_cred_info = create_krb_cred_info(
            encryption_key.clone(), realm.clone(), pname.clone(), ticket_flags.clone(), 
            auth_time.clone(), starttime.clone(), endtime.clone(), renew_till.clone(), 
            realm.clone(), sname.clone(), caddr.clone()
        );
        let seq_of_krb_cred_info = SeqOfKrbCredInfo::new(vec![krb_cred_info]);

        let ticket = create_ticket(realm.clone(), sname.clone());
        let seq_of_tickets = SeqOfTickets::new(vec![ticket]);

        let enc_krb_cred_part = EncKrbCredPart::new(seq_of_krb_cred_info);

        let krb_cred = KrbCred::new(seq_of_tickets, EncryptedData::new(NO_ENCRYPTION, enc_krb_cred_part.build()));

        let credential_warehouse = CredentialWarehouse::new(credential);

        assert_eq!(krb_cred, CredentialWarehouseKrbCredMapper::credential_warehouse_to_krb_cred(&credential_warehouse));
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
        srealm: Realm, sname: PrincipalName, caddr: Option<HostAddresses>, ticket: Ticket
    ) -> Credential {
        let nonce = 0;
        let mut enc_as_rep_part = EncKdcRepPart::new(
            encryption_key,
            LastReq::default(),
            nonce,
            ticket_flags,
            authtime,
            endtime,
            srealm.clone(),
            sname.clone()
        );
        enc_as_rep_part.set_starttime(starttime);
        enc_as_rep_part.set_renew_till(renew_till);
        if let Some(caddr) = caddr {
            enc_as_rep_part.set_caddr(caddr);
        }

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket, 
            enc_as_rep_part
        );

        return credential;
    }

    fn create_ticket(realm: Realm, pname: PrincipalName) -> Ticket {
        return Ticket::new( 
            realm,
            pname,
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x0])
        );
    }

}