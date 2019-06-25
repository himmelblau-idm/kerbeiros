use crate::structs_asn1::*;
use crate::error::*;
use crate::constants::*;
use crate::crypter::*;
use crate::structs_asn1;
use std::convert::From;

#[derive(Debug, Clone, PartialEq)]
enum AsRepEncPart{
    EncryptedData(EncryptedData),
    EncAsRepPart(EncAsRepPart)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsRep {
    pvno: i8,
    msg_type: i8,
    padata: Option<SeqOfPaData>,
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    enc_part: AsRepEncPart,
    encryption_salt: Vec<u8>
}


impl AsRep {

    fn new(
        crealm: Realm, cname: PrincipalName, ticket: Ticket, 
        enc_part: AsRepEncPart
    ) -> Self {
        return Self {
            pvno: 5,
            msg_type: 11,
            padata: None,
            crealm,
            cname,
            ticket,
            enc_part,
            encryption_salt: Vec::new()
        };
    }

    fn set_salt(&mut self, salt: Vec<u8>) {
        self.encryption_salt = salt;
    }
    
    fn set_padata(&mut self, padata: SeqOfPaData) {
        self.padata = Some(padata);
    }
    
    
    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let as_rep_asn1 = structs_asn1::AsRep::parse(raw)?;
        return Ok(Self::from(&as_rep_asn1));
    }

    pub fn decrypt_encrypted_data_with_password(&mut self, password: &str) -> KerberosResult<()> {
        match self.enc_part.clone() {
            AsRepEncPart::EncryptedData(enc_data) => {
                return self._decrypt_enc_part_with_password(&enc_data, password);
            }
            AsRepEncPart::EncAsRepPart(_) => {
                return Ok(());
            }
        }
    }

    fn _decrypt_enc_part_with_password(&mut self, enc_part: &EncryptedData, password: &str) -> KerberosResult<()> {
        match enc_part.get_etype() {
            AES256_CTS_HMAC_SHA1_96 => {
                println!("{:?}", password);
                println!("{:?}", &self.encryption_salt);
                let key = generate_aes_256_key(password.as_bytes(), &self.encryption_salt);
                println!("{:?}", key);
                let plaintext = aes_256_hmac_sh1_decrypt(&key, enc_part.get_cipher())?;
                self.enc_part = AsRepEncPart::EncAsRepPart(
                    EncAsRepPart::from(structs_asn1::EncAsRepPart::parse(&plaintext)?)
                );
            },
            AES128_CTS_HMAC_SHA1_96 => {
                let _key = generate_aes_128_key(password.as_bytes(), &self.encryption_salt);
                unimplemented!()
            },
            RC4_HMAC => {
                let _key = ntlm_hash(password);
                unimplemented!()
            }
            etype => {
                return Err(KerberosErrorKind::UnsupportedCipherAlgorithm(etype))?;
            }
        }

        return Ok(());
    }

}

impl From<&structs_asn1::AsRep> for AsRep {
    fn from(as_rep_asn1: &structs_asn1::AsRep) -> Self {
        let mut as_rep = Self::new(
            as_rep_asn1.get_crealm().clone(),
            as_rep_asn1.get_cname().clone(),
            as_rep_asn1.get_ticket().clone(),
            AsRepEncPart::EncryptedData(as_rep_asn1.get_enc_part().clone())
        );

        as_rep.set_salt(as_rep_asn1.get_salt());

        if let Some(padata) = as_rep_asn1.get_padata() {
            as_rep.set_padata(padata.clone());
        }

        return as_rep;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn test_decode_and_decrypt_enc_part_AES256() {

        let ticket = Ticket::new(5, 
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

        let mut as_rep_asn1 = structs_asn1::AsRep::new(
            Realm::from_ascii("fake").unwrap(),
            PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("fake").unwrap()),
            ticket,
            encrypted_data
        );

        as_rep_asn1.set_padata(padata);

        let mut as_rep = AsRep::from(&as_rep_asn1);




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

        let mut enc_as_rep_part = EncAsRepPart::new(
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

        as_rep.decrypt_encrypted_data_with_password("Minnie1234").unwrap();

        match as_rep.enc_part {
            AsRepEncPart::EncryptedData(_) => {
                unreachable!()
            }
            AsRepEncPart::EncAsRepPart(enc_data_decrypted) => {
                assert_eq!(enc_as_rep_part, enc_data_decrypted);
            }
        }

    }

}