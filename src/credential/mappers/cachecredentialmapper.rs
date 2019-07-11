use crate::structs::*;
use super::super::credential::*;

pub struct CredentialCCacheMapper{}


impl CredentialCCacheMapper {

     pub fn credential_to_ccache_credential(credential: &Credential) -> ccache::CredentialEntry {

        let is_skey = 0;

        let time = TimesMapper::authtime_starttime_endtime_renew_till_to_times(
            credential.get_authtime(),
            credential.get_starttime(),
            credential.get_endtime(),
            credential.get_renew_till(),
        );

        let tktflags = TicketFlagsMapper::ticket_flags_to_tktflags(credential.get_flags());
        let key = KeyBlockMapper::encryption_key_to_keyblock(credential.get_key());

        let ticket = ccache::CountedOctetString::new(credential.get_ticket().build());

        let client = PrincipalMapper::realm_and_principal_name_to_principal(credential.get_crealm(), credential.get_cname());
        let server = PrincipalMapper::realm_and_principal_name_to_principal(
            credential.get_srealm(), 
            credential.get_sname(),
        );

        let mut ccache_credential = ccache::CredentialEntry::new(
            client, 
            server, 
            key, 
            time, 
            is_skey, 
            tktflags, 
            ticket
        );

        if let Some(caddr) = credential.get_caddr() {
            ccache_credential.set_addrs(
                AddressMapper::host_addresses_to_address_vector(caddr)
            );
        }

        if let Some(encrypted_pa_data) = credential.get_encrypted_pa_data() {
            ccache_credential.set_authdata(
                AuthDataMapper::method_data_to_auth_data_vector(encrypted_pa_data)
            );
        }

        return ccache_credential;
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;
    use crate::constants::*;

    fn create_credential(
        encryption_key: EncryptionKey, prealm: Realm, pname: PrincipalName, ticket_flags: TicketFlags,
        authtime: KerberosTime, starttime: KerberosTime, endtime: KerberosTime, renew_till: KerberosTime,
        srealm: Realm, sname: PrincipalName, caddr: Option<HostAddresses>, method_data: MethodData,
        ticket: Ticket
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

        if let Some(caddr) = caddr {
            enc_as_rep_part.set_caddr(caddr);
        }

        enc_as_rep_part.set_encrypted_pa_data(method_data);

        let credential = Credential::new(
            prealm.clone(),
            pname.clone(),
            ticket, 
            enc_as_rep_part
        );

        return credential;
    }


    #[test]
    fn convert_credential_to_ccache_credential() {
        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();

        let mut sname = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("krbtgt").unwrap()
        );
        sname.push(realm.clone());

        let pname = PrincipalName::new(
            NT_PRINCIPAL, 
            KerberosString::from_ascii("mickey").unwrap()
        );

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96, 
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 
                0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 
                0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28, 
                0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2
            ]
        );

        let key = ccache::KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16, 
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 
                0xbc, 0x36, 0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 
                0xde, 0xbe, 0x82, 0xfd, 0x9d, 0x64, 0xcf, 0x28, 
                0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91, 0xd4, 0xc2
            ]
        );

        let authtime =  Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let starttime = Utc.ymd(2019, 7, 7).and_hms(14, 23, 33);
        let endtime = Utc.ymd(2019, 7, 8).and_hms(0, 23, 33);
        let renew_till = Utc.ymd(2019, 7, 8).and_hms(14, 23, 30);

        let time = ccache::Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        let tktflags = ticketflags::FORWARDABLE | 
        ticketflags::PROXIABLE |
        ticketflags::RENEWABLE |
        ticketflags::INITIAL |
        ticketflags::PRE_AUTHENT;

        let ticket_flags = TicketFlags::new(tktflags);

        let mut ticket_encrypted_data = EncryptedData::new(
            AES256_CTS_HMAC_SHA1_96, vec![0x0a]
        );
        ticket_encrypted_data.set_kvno(2);

        let ticket_credential = Ticket::new( 
            realm.clone(),
            sname.clone(),
            ticket_encrypted_data
        );

        let host_addresses = HostAddresses::new(HostAddress::NetBios("HOLLOWBASTION".to_string()));
        let mut method_data = MethodData::new_empty();
        method_data.push(PaData::PacRequest(PacRequest::new(true)));

        let credential = create_credential(
            encryption_key.clone(), realm.clone(), pname.clone(), ticket_flags.clone(), 
            authtime.clone(), starttime.clone(), endtime.clone(), renew_till.clone(), 
            realm.clone(), sname.clone(), Some(host_addresses), method_data, ticket_credential
        );

        let ticket = ccache::CountedOctetString::new(vec![
            0x61, 0x51, 0x30, 0x4f, 
                0xa0, 0x03, 0x02, 0x01, 0x05, 
                0xa1, 0x10, 0x1b, 0x0e, 
                0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                0xa2, 0x23, 0x30, 0x21,
                    0xa0, 0x03, 0x02, 0x01, 0x01, 
                    0xa1, 0x1a, 0x30,0x18, 
                        0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                        0x1b, 0x0e, 
                            0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
                0xa3, 0x11, 0x30, 0x0f, 
                    0xa0, 0x03, 0x02, 0x01, 0x12, 
                    0xa1, 0x03, 0x02, 0x01, 0x02, 
                    0xa2, 0x03, 0x04, 0x01, 0x0a
        ]);

        let realm_string = ccache::CountedOctetString::new(realm.as_bytes().to_vec());

        let client_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32, 
            realm_string.clone(),
            vec![ccache::CountedOctetString::new("mickey".as_bytes().to_vec())]
        );
        let server_principal = ccache::Principal::new(
            NT_PRINCIPAL as u32, 
            realm_string.clone(),
            vec![
                ccache::CountedOctetString::new("krbtgt".as_bytes().to_vec()),
                realm_string.clone()
            ]
        );

        let is_skey = 0;

        let mut ccache_credential = ccache::CredentialEntry::new(
            client_principal.clone(),
            server_principal,
            key,
            time,
            is_skey,
            tktflags,
            ticket
        );

        let mut addresses = Vec::new();
        addresses.push(
            Address::new(
                NETBIOS_ADDRESS as u16,
                CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec())
            )
        );
        ccache_credential.set_addrs(addresses);

        let mut auth_datas = Vec::new();
        auth_datas.push(
            AuthData::new(
                PA_PAC_REQUEST as u16,
                CountedOctetString::new(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff])
            )
        );

        ccache_credential.set_authdata(auth_datas);

        assert_eq!(ccache_credential, CredentialCCacheMapper::credential_to_ccache_credential(&credential));
    }

}

