use asn1::*;
use asn1_derive::*;

use super::principalname::*;
use super::realm::*;
use super::padata::*;
use super::ticket::*;
use super::encrypteddata::*;
use super::super::error::*;

#[derive(Debug, Clone, PartialEq)]
pub struct KdcRep {
    pvno: i8,
    msg_type: i8,
    padata: Option<SeqOfPaData>,
    crealm: Realm,
    cname: PrincipalName,
    ticket: Ticket,
    enc_part: EncryptedData
}


impl KdcRep {

    pub fn new(crealm: Realm, cname: PrincipalName, ticket: Ticket, enc_part: EncryptedData) -> Self {
        return KdcRep {
            pvno: 5,
            msg_type: 11,
            padata: None,
            crealm,
            cname,
            ticket,
            enc_part,
        };
    }

    fn set_pvno(&mut self, pvno: i8) {
        self.pvno = pvno;
    }

    fn set_msg_type(&mut self, msg_type: i8) {
        self.msg_type = msg_type;
    }

    pub fn set_padata(&mut self, padata: SeqOfPaData) {
        self.padata = Some(padata);
    }

    pub fn get_padata(&self) -> &Option<SeqOfPaData> {
        return &self.padata;
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

    pub fn get_enc_part_etype(&self) -> i32 {
        return self.enc_part.get_etype();
    }

    pub fn get_enc_part_cipher(&self) -> &Vec<u8> {
        return self.enc_part.get_cipher();
    }

    pub fn get_encryption_salt(&self) -> Vec<u8> {
        if let Some(padata) = &self.padata {
            for entry_data in padata.iter() {
                if let PaData::EtypeInfo2(etype_info2) = entry_data {
                    for info2_entry in etype_info2.iter() {
                        return info2_entry.get_salt_bytes();
                    }
                }
            }
        }
        
        return Vec::new();
    }


    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let mut as_rep_asn1 = AsRepAsn1::new_empty();
        as_rep_asn1.decode(raw)?;
        return Ok(as_rep_asn1.no_asn1_type().unwrap());
    }

}

#[derive(Asn1Sequence)]
#[seq(application_tag = 11)]
struct AsRepAsn1 {
    #[seq_comp(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_comp(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_comp(context_tag = 2, optional)]
    padata: SeqField<SeqOfPaDataAsn1>,
    #[seq_comp(context_tag = 3)]
    crealm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 4)]
    cname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 5)]
    ticket: SeqField<TicketAsn1>,
    #[seq_comp(context_tag = 6)]
    enc_part: SeqField<EncryptedDataAsn1>,
}

impl AsRepAsn1 {

    fn new_empty() -> Self {
        return Self {
            pvno: SeqField::new(),
            msg_type: SeqField::new(),
            padata: SeqField::new(),
            crealm: SeqField::new(),
            cname: SeqField::new(),
            ticket: SeqField::new(),
            enc_part: SeqField::new(),
        };
    }

    fn no_asn1_type(&self) -> KerberosResult<KdcRep> {
        let pvno = self.get_pvno().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::pvno".to_string())
        )?;
        let pvno_value = pvno.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::pvno".to_string())
        )?;
        
        let msg_type = self.get_msg_type().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::msg_type".to_string())
        )?;
        let msg_type_value = msg_type.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::msg_type".to_string())
        )?;
        
        let crealm = self.get_crealm().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::crealm".to_string())
        )?;
        let cname = self.get_cname().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::cname".to_string())
        )?;
        let ticket = self.get_ticket().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::ticket".to_string())
        )?;
        let enc_part = self.get_enc_part().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("AsRep::enc_part".to_string())
        )?;
        
        let mut as_rep = KdcRep::new(
            crealm.no_asn1_type()?,
            cname.no_asn1_type()?,
            ticket.no_asn1_type()?,
            enc_part.no_asn1_type()?
        );

        as_rep.set_pvno(*pvno_value as i8);
        as_rep.set_msg_type(*msg_type_value as i8);

        if let Some(padata) = self.get_padata() {
            as_rep.set_padata(padata.no_asn1_type()?);
        }

        return Ok(as_rep);
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::constants::*;

    #[test]
    fn decode_as_rep() {
        
        let encoded_as_rep = [
            0x6b, 0x81, 0xcc, 0x30, 0x81, 0xc9, 
            0xa0, 0x03, 0x02, 0x01, 0x05, 
            0xa1, 0x03, 0x02, 0x01, 0x0b, 
            0xa2, 0x2e, 0x30, 0x2c, 
                0x30, 0x2a, 
                    0xa1, 0x03, 0x02, 0x01, 0x13, 
                    0xa2, 0x23, 0x04, 0x21, 0x30, 0x1f, 0x30,
                    0x1d, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x16, 0x1b, 0x14, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f,
                    0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79, 
            0xa3, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
            0xa4, 0x13, 0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0a, 0x30, 0x08, 0x1b, 0x06, 0x6d,
            0x69, 0x63, 0x6b, 0x65, 0x79, 
            0xa5, 0x53, 0x61, 0x51, 0x30, 0x4f, 
                    0xa0, 0x03, 0x02, 0x01, 0x05, 
                    0xa1, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                    0xa2, 0x23, 0x30, 0x21, 
                        0xa0, 0x03, 0x02, 0x01, 0x02, 
                        0xa1, 0x1a, 0x30, 0x18, 
                            0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 
                            0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                    0xa3, 0x11, 0x30, 0x0f, 
                        0xa0, 0x03, 0x02, 0x01, 0x12, 
                        0xa1, 0x03, 0x02, 0x01, 0x02, 
                        0xa2, 0x03, 0x04, 0x01, 
                            0x9,
            0xa6, 0x11, 0x30, 0x0f, 
                0xa0, 0x03, 0x02, 0x01, 0x12, 
                0xa1, 0x03, 0x02, 0x01, 0x02, 
                0xa2, 0x03, 0x04, 0x01, 
                    0x9
        ];

        let as_rep_decoded = KdcRep::parse(&encoded_as_rep).unwrap();

        let realm = Realm::from_ascii("KINGDOM.HEARTS").unwrap();
        let cname = PrincipalName::new(NT_PRINCIPAL, KerberosString::from_ascii("mickey").unwrap());

        let mut sname_ticket =  PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        sname_ticket.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut encrypted_data_ticket = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x9]);
        encrypted_data_ticket.set_kvno(2);

        let ticket = Ticket::new(
            Realm::from_ascii("KINGDOM.HEARTS").unwrap(),
            sname_ticket,
            encrypted_data_ticket
        );

        let mut encrypted_data = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x9]);
        encrypted_data.set_kvno(2);

        let mut padata = SeqOfPaData::new();
        let mut entry1 = EtypeInfo2Entry::_new(AES256_CTS_HMAC_SHA1_96);
        entry1._set_salt(KerberosString::from_ascii("KINGDOM.HEARTSmickey").unwrap());

        let mut info2 = EtypeInfo2::_new();
        info2.push(entry1);
        padata.push(PaData::EtypeInfo2(info2));

        let mut as_rep = KdcRep::new(
            realm,
            cname,
            ticket,
            encrypted_data
        );

        as_rep.set_padata(padata);

        assert_eq!(as_rep, as_rep_decoded);
    }

}
