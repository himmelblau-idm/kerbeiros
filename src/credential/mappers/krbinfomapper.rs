use crate::structs::*;
use super::super::credential::*;
use crate::crypter::*;
use crate::constants::*;

pub struct CredentialKrbInfoMapper{}

impl CredentialKrbInfoMapper {


    pub fn credential_to_krb_info_and_ticket(credential: &Credential) -> (KrbCredInfo,Ticket) {

        let mut krb_cred_info = KrbCredInfo::new(credential.get_key().clone());

        krb_cred_info.set_flags(credential.get_flags().clone());
        krb_cred_info.set_authtime(credential.get_authtime().clone());
        
        if let Some(starttime) = credential.get_starttime() {
            krb_cred_info.set_starttime(starttime.clone());
        }
        krb_cred_info.set_endtime(credential.get_endtime().clone());

        if let Some(renew_till) = credential.get_renew_till() {
            krb_cred_info.set_renew_till(renew_till.clone());
        }

        krb_cred_info.set_srealm(credential.get_srealm().clone());
        krb_cred_info.set_sname(credential.get_sname().clone());

        if let Some(caddr) = credential.get_caddr() {
            krb_cred_info.set_caddr(caddr.clone());
        }

        krb_cred_info.set_prealm(credential.get_crealm().clone());
        krb_cred_info.set_pname(credential.get_cname().clone());
        return (krb_cred_info, credential.get_ticket().clone());
    }

    pub fn kdc_rep_to_credential(password: &str, kdc_rep: &KdcRep) -> KerberosResult<Credential> {
        let crypter = new_kerberos_crypter(kdc_rep.get_enc_part_etype())?;
        let plaintext = crypter.generate_key_from_password_and_decrypt(
            password, 
            &kdc_rep.get_encryption_salt(),
            KEY_USAGE_AS_REP_ENC_PART, 
            kdc_rep.get_enc_part_cipher()
        )?;

        let enc_kdc_rep_part = EncKdcRepPart::parse(&plaintext)?;

        return Ok(Credential::new(
            kdc_rep.get_crealm().clone(),
            kdc_rep.get_cname().clone(),
            kdc_rep.get_ticket().clone(),
            enc_kdc_rep_part
        ));
    }

}

#[cfg(test)]

mod test {
    use super::*;
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

        let ticket = Ticket::new(
            realm.clone(), 
            sname.clone(), 
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x0])
        );

        assert_eq!((krb_cred_info, ticket), CredentialKrbInfoMapper::credential_to_krb_info_and_ticket(&credential));
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

    #[test]
    fn decode_and_decrypt_enc_part_aes256() {

        let ticket = Ticket::new(
            Realm::from_ascii("fake").unwrap(),
            PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("fake").unwrap()),
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x9])
        );

        let encrypted_data = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![
            0xe2, 0xbb, 0xa9, 0x28, 0x8e, 0x2e, 0x2e, 0x3e, 0xf5, 0xfa, 0xee, 0x6d, 0x9e, 0xde, 0x0e, 0x77,
            0x38, 0x70, 0x9b, 0xca, 0xc4, 0x74, 0x6f, 0x7f, 0x00, 0xbf, 0xc7, 0x92, 0x30, 0x30, 0x98, 0xd5,
            0x29, 0x76, 0x49, 0xab, 0x92, 0x31, 0x7f, 0x7b, 0xbe, 0x49, 0x4b, 0x37, 0xe7, 0xf9, 0x33, 0x0f,
            0x14, 0x88, 0x8e, 0x4c, 0xda, 0xb8, 0x80, 0xfb, 0x84, 0xde, 0x97, 0xd9, 0x02, 0xb7, 0x44, 0x4d,
            0x66, 0x73, 0x5a, 0x62, 0xcf, 0x47, 0xc4, 0x42, 0x69, 0xba, 0xdb, 0x64, 0x8b, 0x61, 0x61, 0x71,
            0xeb, 0xc1, 0xf6, 0x10, 0x01, 0x26, 0x65, 0xa0, 0xab, 0x8d, 0x30, 0xad, 0xa9, 0x13, 0x30, 0xda,
            0x74, 0x6a, 0xd7, 0x00, 0xa7, 0x24, 0x16, 0x1d, 0x99, 0xe0, 0x7c, 0xb9, 0x77, 0x98, 0x3e, 0x04,
            0x3d, 0xa7, 0x21, 0x6b, 0xee, 0xec, 0x1a, 0xb1, 0x68, 0xb9, 0x93, 0xf9, 0x06, 0xdb, 0xce, 0x2e,
            0x51, 0x77, 0x56, 0xd7, 0x8f, 0xe1, 0x36, 0xc8, 0x6a, 0xca, 0xb1, 0x3d, 0x71, 0xdf, 0x8d, 0x0c,
            0x83, 0x68, 0x9b, 0x9b, 0xe8, 0xc9, 0xe7, 0x0f, 0xf3, 0x5e, 0xd2, 0xc6, 0x8c, 0xad, 0xf0, 0x93,
            0x4e, 0xe8, 0xac, 0x9a, 0xe5, 0x84, 0x25, 0x5d, 0xde, 0x5f, 0xb9, 0x48, 0xbe, 0xd5, 0x93, 0xc7,
            0x53, 0xd7, 0xe8, 0x86, 0xd4, 0xc5, 0x5a, 0xfd, 0xab, 0xe0, 0x5d, 0x75, 0x87, 0x8b, 0x5b, 0x06,
            0x09, 0x4d, 0xd7, 0x0a, 0x35, 0x91, 0xee, 0x68, 0x8b, 0x91, 0x34, 0x38, 0x43, 0x75, 0x9a, 0xaf,
            0x20, 0xf7, 0x32, 0x61, 0xe6, 0xea, 0xcb, 0x8d, 0x7c, 0x34, 0x55, 0x8a, 0x08, 0x26, 0x96, 0x79,
            0xff, 0xbd, 0x74, 0x0c, 0x8a, 0x7c, 0xb2, 0xfb, 0x06, 0x90, 0xc3, 0xf5, 0x77, 0xba, 0x3a, 0x53,
            0x0c, 0x6f, 0x41, 0x4d, 0x35, 0xe8, 0x0c, 0x75, 0x4e, 0x14, 0x90, 0xdc, 0xf1, 0xa7, 0x70, 0x5f,
            0xe1, 0x90, 0xa4, 0x54, 0xdc, 0x5f, 0xb8, 0x18, 0x41, 0x5f, 0xfc, 0xc1, 0xe6, 0x5f, 0xf9, 0x54,
            0x77, 0xf5, 0x5c, 0x7b, 0x31, 0xf0, 0xd2, 0xcf, 0x05, 0x35, 0x12, 0xea, 0xdb, 0xfc, 0x80, 0x71,
            0xf8, 0xcc, 0x4a, 0x2d, 0x3b, 0x54, 0xf2, 0xde, 0xe2, 0x20, 0x32, 0x7e, 0xf1, 0xa7, 0x14, 0x25,
            0x1b, 0x88, 0x38, 0x0e, 0x24, 0x46, 0x04, 0x09, 0x87, 0xf9, 0xd6, 0xe1, 0xce, 0x3b, 0xe8, 0x42,
            0x95, 0xb7, 0x6c, 0x75, 0xc0, 0x7d, 0x13, 0xa0, 0x7b
        ]);

        let mut padata = SeqOfPaData::new();
        let mut entry1 = EtypeInfo2Entry::_new(AES256_CTS_HMAC_SHA1_96);
        entry1._set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::_new();
        info2.push(entry1);
        padata.push(PaData::EtypeInfo2(info2));

        let mut as_rep = KdcRep::new(
            Realm::from_ascii("fake").unwrap(),
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("fake").unwrap()),
            ticket.clone(),
            encrypted_data
        );

        as_rep.set_padata(padata);

        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );

        let mut last_req = LastReq::new_empty();
        last_req.push(LastReqEntry::new(
            0,
            Utc.ymd(2019, 4, 18).and_hms(06, 00, 31)
        ));

        let mut ticket_flags = TicketFlags::new_empty();
        ticket_flags.set_flags(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let kerb_time = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);

        let mut sname =  PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut encrypted_pa_datas = MethodData::new();
        encrypted_pa_datas.push(
            PaData::Raw(PA_SUPPORTED_ENCTYPES, vec![0x1f, 0x0, 0x0, 0x0])
        );

        let mut enc_as_rep_part = EncKdcRepPart::new(
            encryption_key,
            last_req,
            104645460,
            ticket_flags,
            kerb_time.clone(),
            Utc.ymd(2019, 4, 18).and_hms(16, 00, 31),
            Realm::from_ascii("KINGDOM.HEARTS").unwrap(),
            sname
        );

        enc_as_rep_part.set_key_expiration(
            Utc.ymd(2037, 9, 14).and_hms(02, 48, 05)
        );

        enc_as_rep_part.set_starttime(kerb_time);
        enc_as_rep_part.set_renew_till(
            Utc.ymd(2019, 4, 25).and_hms(06, 00, 31)
        );
        enc_as_rep_part.set_caddr(
            HostAddresses::new(
                HostAddress::NetBios("HOLLOWBASTION".to_string())
            )
        );
        enc_as_rep_part.set_encrypted_pa_data(encrypted_pa_datas);

        let credential = Credential::new(
            Realm::from_ascii("fake").unwrap(),
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("fake").unwrap()),
            ticket,
            enc_as_rep_part
        );

        assert_eq!(
            credential, 
            CredentialKrbInfoMapper::kdc_rep_to_credential("Minnie1234", &as_rep).unwrap()
        );

    }

}
