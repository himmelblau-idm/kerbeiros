use red_asn1::*;
use crate::error::*;
use super::super::realm::*;
use super::super::principalname::*;
use super::super::encrypteddata::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    tkt_vno: i8,
    realm: Realm,
    sname: PrincipalName,
    enc_part: EncryptedData,
}

impl Ticket {

    pub fn new(realm: Realm, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        return Self {
            tkt_vno: 5,
            realm,
            sname,
            enc_part,
        };
    }

    pub fn set_tkt_vno(&mut self, tkt_vno: i8) {
        self.tkt_vno = tkt_vno;
    }

    pub fn get_realm_ascii_string(&self) -> AsciiString {
        return self.realm.to_ascii_string();
    }

    pub fn get_sname_ascii_string(&self) -> AsciiString {
        return self.sname.to_ascii_string();
    }

    pub fn get_encrypted_data(&self) -> &EncryptedData {
        return &self.enc_part;
    }

    pub fn asn1_type(&self) -> TicketAsn1 {
        return TicketAsn1::new(self);
    }

    pub fn build(&self) -> Vec<u8> {
        return self.asn1_type().encode().unwrap();
    }

}

#[derive(Sequence, Default, Debug, PartialEq)]
#[seq(application_tag = 1)]
pub struct TicketAsn1 {
    #[seq_field(context_tag = 0)]
    tkt_vno: SeqField<Integer>,
    #[seq_field(context_tag = 1)]
    realm: SeqField<RealmAsn1>,
    #[seq_field(context_tag = 2)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_field(context_tag = 3)]
    enc_part: SeqField<EncryptedDataAsn1>
    
}

impl TicketAsn1 {

    fn new(ticket: &Ticket) -> TicketAsn1 {
        let mut ticket_asn1 = Self::default();

        ticket_asn1.set_tkt_vno(Integer::from(ticket.tkt_vno as i64));
        ticket_asn1.set_realm(RealmAsn1::new(ticket.realm.clone()));
        ticket_asn1.set_sname(ticket.sname.asn1_type());
        ticket_asn1.set_enc_part(ticket.enc_part.asn1_type());

        return ticket_asn1;
    }

    pub fn no_asn1_type(&self) -> KerberosResult<Ticket> {
        let tkt_vno = self.get_tkt_vno().ok_or_else(||
            KerberosErrorKind::NotAvailableData("Ticket::tkt_vno".to_string())
        )?;
        let tkt_vno_value = tkt_vno.value().ok_or_else(||
            KerberosErrorKind::NotAvailableData("Ticket::tkt_vno".to_string())
        )?;

        let realm = self.get_realm().ok_or_else(||
            KerberosErrorKind::NotAvailableData("Ticket::realm".to_string())
        )?;
        let sname = self.get_sname().ok_or_else(||
            KerberosErrorKind::NotAvailableData("Ticket::sname".to_string())
        )?;
        let enc_part = self.get_enc_part().ok_or_else(||
            KerberosErrorKind::NotAvailableData("Ticket::enc_part".to_string())
        )?;

        let mut ticket = Ticket::new(
            realm.no_asn1_type()?,
            sname.no_asn1_type()?,
            enc_part.no_asn1_type()?
        );
        ticket.set_tkt_vno(tkt_vno_value as i8);


        return Ok(ticket);

    }

}

#[cfg(test)]

mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn create_default_ticket_asn1() {
        assert_eq!(
            TicketAsn1 {
                tkt_vno: SeqField::default(),
                realm: SeqField::default(),
                sname: SeqField::default(),
                enc_part: SeqField::default()
            },
            TicketAsn1::default()
        )
    }

    #[test]
    fn decode_ticket() {
        let mut ticket_asn1 = TicketAsn1::default();

        ticket_asn1.decode(&[
            0x61, 0x82, 0x04, 0x13, 0x30, 0x82, 0x04, 0x0f,
                0xa0, 0x03, 0x02, 0x01, 0x05,
                0xa1, 0x10, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
                0xa2, 0x23, 0x30, 0x21,
                    0xa0, 0x03, 0x02, 0x01, 0x02,
                    0xa1, 0x1a, 0x30, 0x18,
                        0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74,
                        0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53,
                0xa3, 0x82, 0x03, 0xcf, 0x30, 0x82, 0x03, 0xcb,
                0xa0, 0x03, 0x02, 0x01, 0x12,
                0xa1, 0x03, 0x02, 0x01, 0x02,
                0xa2, 0x82, 0x03, 0xbd, 0x04, 0x82, 0x03, 0xb9, 0x4e, 0xc1, 0x75, 0x6d, 0x5e, 0xf6,
                    0x84, 0x18, 0x5f, 0x33, 0x21, 0x24, 0x54, 0x02, 0x40, 0x79, 0x23, 0x48, 0x2f, 0x39, 0xdd, 0x5a,
                    0xa1, 0x68, 0x79, 0x3f, 0x1a, 0x33, 0x0f, 0xcd, 0xe3, 0xe6, 0x3d, 0x0a, 0x3b, 0x39, 0x22, 0xd3,
                    0x6c, 0xb5, 0x89, 0xd3, 0x8f, 0xcb, 0x4a, 0xbe, 0x8f, 0xcb, 0xae, 0x72, 0x96, 0x7f, 0x98, 0x7c,
                    0x4d, 0x52, 0xbd, 0xa9, 0xae, 0xe6, 0xd1, 0x1c, 0x21, 0x9c, 0x2b, 0x7f, 0x2b, 0xd8, 0x29, 0xd6,
                    0x6a, 0x82, 0x5d, 0xaf, 0x0a, 0x51, 0x94, 0xd5, 0x00, 0xfa, 0x4d, 0xf1, 0x78, 0x88, 0x6d, 0xbf,
                    0x5f, 0x5e, 0x7c, 0x5a, 0xd0, 0xf6, 0x74, 0xac, 0x14, 0x58, 0xbf, 0x6c, 0xeb, 0xa1, 0x1a, 0xaa,
                    0x5b, 0x65, 0x4c, 0x16, 0x9c, 0xcc, 0xa5, 0xb1, 0x2c, 0x43, 0x1d, 0x05, 0x71, 0xa9, 0x05, 0xd7,
                    0x9e, 0x86, 0x50, 0x44, 0xeb, 0x9e, 0x33, 0x2d, 0xad, 0x21, 0xc9, 0x2e, 0x37, 0x67, 0x46, 0x13,
                    0xa5, 0x96, 0x30, 0xbf, 0x9e, 0xfa, 0x55, 0x80, 0x7f, 0x9b, 0x8d, 0x53, 0xe3, 0x08, 0xf0, 0xa9,
                    0xfe, 0x88, 0xd8, 0xa9, 0x16, 0xcb, 0x02, 0xa6, 0x63, 0x1e, 0x89, 0xa2, 0xf2, 0xe1, 0x86, 0x8f,
                    0x50, 0x89, 0x34, 0xa2, 0x9f, 0x64, 0xd6, 0xe5, 0x9c, 0x67, 0xf0, 0x56, 0xbb, 0x0d, 0xbb, 0xaf,
                    0x1d, 0xd8, 0xf3, 0xc5, 0xc7, 0xb9, 0xa0, 0x24, 0xeb, 0x0b, 0x87, 0x0f, 0x40, 0x7e, 0xdd, 0xe7,
                    0x88, 0xeb, 0xd2, 0x7e, 0xa3, 0x93, 0xc9, 0xc4, 0x1b, 0x5a, 0xf1, 0xf5, 0x54, 0x09, 0xc6, 0x38,
                    0x9f, 0xd2, 0x02, 0xaa, 0x5c, 0xf3, 0x17, 0x4e, 0x29, 0x97, 0xaf, 0xc2, 0xf2, 0xe3, 0x00, 0xb1,
                    0x49, 0x7d, 0x97, 0x3f, 0x49, 0xe3, 0xf7, 0x0b, 0x5b, 0x76, 0xc8, 0x89, 0x3c, 0xff, 0x27, 0x4a,
                    0x7a, 0x80, 0xe1, 0x67, 0x6e, 0xb0, 0xc2, 0x35, 0xf9, 0xaa, 0xb7, 0x65, 0x3e, 0x8c, 0x8d, 0x2a,
                    0x69, 0x9a, 0xdc, 0xeb, 0x53, 0x7d, 0xd9, 0xc8, 0x5d, 0xa5, 0x1c, 0x5f, 0xab, 0x52, 0xf5, 0x35,
                    0xd9, 0x76, 0x5f, 0x7b, 0x63, 0xd7, 0x35, 0x30, 0x52, 0x94, 0x2c, 0x37, 0x99, 0x9b, 0x5a, 0x83,
                    0x37, 0x5d, 0x52, 0x85, 0xc0, 0x8b, 0xa1, 0xac, 0xe6, 0xcc, 0x64, 0x51, 0x23, 0x7f, 0x21, 0x47,
                    0x95, 0x6d, 0xb7, 0xcb, 0x45, 0x78, 0xf4, 0xbf, 0xd9, 0x26, 0x3c, 0x82, 0xc5, 0x64, 0x75, 0x7a,
                    0x8f, 0x3f, 0xa1, 0x46, 0x3d, 0x4e, 0x4d, 0x11, 0xee, 0xf1, 0xae, 0xc4, 0x3a, 0x09, 0xa8, 0xfc,
                    0x89, 0x1f, 0x37, 0xe0, 0xe4, 0xf5, 0x44, 0x33, 0xa5, 0xec, 0xbb, 0xf5, 0x0e, 0xc0, 0x1d, 0x54,
                    0x52, 0x41, 0xc4, 0xf8, 0x65, 0xc7, 0x3d, 0x10, 0xab, 0x4b, 0x90, 0x28, 0xb1, 0x62, 0x85, 0x5d,
                    0xf1, 0xd7, 0xe0, 0xd2, 0x0f, 0x12, 0x51, 0x2f, 0x0d, 0xc5, 0x9f, 0xab, 0x8b, 0x93, 0x2f, 0x72,
                    0xb4, 0x74, 0xdd, 0xdd, 0x29, 0x0a, 0x6f, 0xa7, 0x2a, 0xc1, 0x82, 0x5e, 0xfc, 0xb2, 0x27, 0x3f,
                    0xa0, 0x7d, 0xce, 0xd2, 0x40, 0x13, 0xcb, 0x0a, 0xde, 0x0d, 0xc5, 0xc4, 0x45, 0x1f, 0x62, 0xfb,
                    0x5a, 0xd6, 0x3d, 0x91, 0x44, 0x85, 0x0c, 0x11, 0x76, 0x6a, 0x6f, 0x65, 0x3b, 0xc8, 0x67, 0x06,
                    0x36, 0x6d, 0x01, 0x3d, 0xdb, 0x22, 0x03, 0x75, 0xc5, 0xb2, 0x56, 0xf3, 0xed, 0x6c, 0x25, 0x2d,
                    0x7d, 0x21, 0xc1, 0xa5, 0xb6, 0xe6, 0x3c, 0xbd, 0xb8, 0x16, 0x0a, 0x36, 0x6e, 0x60, 0x9c, 0xd6,
                    0x23, 0x53, 0x2b, 0xbc, 0x14, 0xbe, 0xfd, 0x1b, 0x57, 0xbb, 0x0b, 0xfd, 0x7e, 0x65, 0xe3, 0xc7,
                    0x00, 0x56, 0x6a, 0x9f, 0xf4, 0xf3, 0x83, 0xae, 0x2f, 0x4c, 0xe6, 0x68, 0x80, 0x8d, 0x55, 0x0f,
                    0xfa, 0x87, 0xbf, 0xcc, 0x62, 0xe4, 0xa8, 0x37, 0xe2, 0x04, 0x1f, 0xc3, 0x4b, 0x39, 0xb2, 0x70,
                    0x88, 0x2e, 0x4c, 0x89, 0xfb, 0x3d, 0x74, 0xae, 0x82, 0xf8, 0xea, 0x9c, 0x7d, 0xf1, 0x78, 0x22,
                    0xac, 0x2f, 0x96, 0x52, 0x13, 0x1b, 0x8b, 0xcc, 0x01, 0x17, 0x9d, 0xff, 0x4f, 0x1f, 0xeb, 0x3d,
                    0x97, 0xea, 0x2a, 0x0c, 0xd6, 0x0c, 0x5c, 0x7a, 0x41, 0x1f, 0x6e, 0x5b, 0x9b, 0x5d, 0x16, 0xb8,
                    0x0c, 0x08, 0x93, 0x51, 0xa4, 0xb9, 0x4a, 0xe9, 0x4c, 0x3a, 0x60, 0x88, 0x74, 0xf0, 0xa8, 0xb5,
                    0x2a, 0x9f, 0x34, 0x6f, 0xad, 0x8a, 0xed, 0xc2, 0x9e, 0x38, 0xdc, 0x74, 0x33, 0x62, 0x6b, 0x4e,
                    0x1d, 0x82, 0x92, 0xa8, 0xd2, 0xda, 0x86, 0x9d, 0x90, 0xcb, 0x6b, 0x19, 0x07, 0x56, 0xa3, 0x59,
                    0x10, 0x57, 0x89, 0xd1, 0x00, 0xcc, 0x94, 0x7c, 0xcd, 0x0c, 0xdc, 0x74, 0xfb, 0x5f, 0xe4, 0x6f,
                    0x73, 0x1e, 0xa8, 0x8e, 0xad, 0x31, 0x0d, 0x07, 0xe7, 0x8d, 0x23, 0xf9, 0x8f, 0xed, 0x04, 0x2b,
                    0x47, 0x3f, 0x54, 0xcb, 0xbb, 0x0b, 0xf8, 0xc6, 0x32, 0xd5, 0x7d, 0x20, 0x92, 0xfd, 0xa6, 0xba,
                    0x75, 0x02, 0x42, 0x5a, 0x72, 0xa4, 0xdf, 0xd0, 0x0a, 0xb0, 0x33, 0x80, 0xf1, 0xea, 0x15, 0x3d,
                    0x5f, 0xae, 0xcf, 0x1f, 0xcc, 0x44, 0xb5, 0x5f, 0x69, 0x9f, 0x90, 0x40, 0xf0, 0x6e, 0xc9, 0x9a,
                    0x63, 0x52, 0x97, 0x1e, 0xed, 0xc8, 0x05, 0x12, 0xb2, 0xfb, 0xad, 0xe1, 0x13, 0xa5, 0x39, 0x53,
                    0x88, 0xaf, 0xcf, 0xbe, 0x01, 0x4a, 0x65, 0x62, 0xf0, 0x35, 0x2f, 0x76, 0x9a, 0x8b, 0xc3, 0xbc,
                    0x43, 0x5b, 0xc4, 0x91, 0xcc, 0x04, 0xfe, 0xcc, 0xc4, 0xf5, 0xa3, 0x27, 0x88, 0x97, 0x49, 0xca,
                    0xe2, 0x33, 0x1d, 0xff, 0x96, 0x33, 0x4b, 0x50, 0x49, 0x86, 0xdc, 0x65, 0x9f, 0x55, 0xc1, 0xb6,
                    0x85, 0xe5, 0x9f, 0x3d, 0xd1, 0x87, 0x84, 0xd8, 0x08, 0x9f, 0x03, 0x4c, 0xc7, 0xa8, 0x8b, 0x59,
                    0xb7, 0x58, 0xd2, 0x10, 0x1c, 0x3f, 0xf9, 0x2d, 0x5f, 0x37, 0x5c, 0x70, 0x90, 0x84, 0xea, 0x4b,
                    0x37, 0x55, 0x9c, 0x12, 0x2d, 0xa4, 0xb2, 0x75, 0x5d, 0x37, 0xfc, 0x7c, 0xa7, 0x19, 0xb4, 0x88,
                    0xba, 0xf3, 0xea, 0xe2, 0xf1, 0xa2, 0xe3, 0x23, 0xd6, 0x5e, 0x6e, 0xf8, 0x37, 0x61, 0xf2, 0xec,
                    0xd8, 0x17, 0x19, 0xa3, 0x69, 0xbd, 0xd8, 0x51, 0x17, 0x37, 0xa3, 0xc6, 0x8f, 0x26, 0xf1, 0x19,
                    0x6f, 0xf4, 0xf9, 0xdb, 0x09, 0xef, 0x70, 0x88, 0x81, 0x78, 0xfd, 0x2e, 0x60, 0xdb, 0xdf, 0x6e,
                    0xe9, 0xf6, 0xef, 0xb0, 0x7e, 0x75, 0xc5, 0x18, 0x39, 0xdc, 0x4b, 0x33, 0xda, 0x51, 0xad, 0xe4,
                    0x7b, 0x7d, 0x46, 0xd2, 0x39, 0x62, 0xf1, 0x71, 0x4c, 0xda, 0x49, 0xa0, 0x7b, 0xc7, 0x67, 0xe8,
                    0x47, 0x6e, 0x3a, 0x43, 0x4e, 0x31, 0x0e, 0x30, 0x3b, 0x60, 0x7d, 0xc1, 0x0c, 0x4e, 0x82, 0x7e,
                    0xf6, 0x02, 0xcf, 0xd4, 0xfe, 0x8f, 0x39, 0x8e, 0xce, 0xe6, 0x7b, 0x3a, 0xc7, 0xae, 0xde, 0xf1,
                    0x2b, 0xae, 0x4e, 0xd8, 0x60, 0x7e, 0x8a, 0x10, 0xdf, 0xdf, 0xb8, 0x57, 0x5b, 0x7c, 0xb3, 0x80,
                    0x55, 0x16, 0x4c, 0xab, 0x62, 0x39, 0xb7, 0xa4, 0x4c, 0xd3, 0xaa, 0xca, 0x5b, 0xd1, 0xb5, 0xcb,
                    0xf4, 0x46, 0xfc]
        ).unwrap();
        

        let mut principal_name =  PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let mut encrypted_data = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![
            0x4e, 0xc1, 0x75, 0x6d, 0x5e, 0xf6, 0x84, 0x18, 0x5f, 0x33, 0x21, 0x24, 0x54, 0x02, 0x40, 0x79,
            0x23, 0x48, 0x2f, 0x39, 0xdd, 0x5a, 0xa1, 0x68, 0x79, 0x3f, 0x1a, 0x33, 0x0f, 0xcd, 0xe3, 0xe6,
            0x3d, 0x0a, 0x3b, 0x39, 0x22, 0xd3, 0x6c, 0xb5, 0x89, 0xd3, 0x8f, 0xcb, 0x4a, 0xbe, 0x8f, 0xcb,
            0xae, 0x72, 0x96, 0x7f, 0x98, 0x7c, 0x4d, 0x52, 0xbd, 0xa9, 0xae, 0xe6, 0xd1, 0x1c, 0x21, 0x9c,
            0x2b, 0x7f, 0x2b, 0xd8, 0x29, 0xd6, 0x6a, 0x82, 0x5d, 0xaf, 0x0a, 0x51, 0x94, 0xd5, 0x00, 0xfa,
            0x4d, 0xf1, 0x78, 0x88, 0x6d, 0xbf, 0x5f, 0x5e, 0x7c, 0x5a, 0xd0, 0xf6, 0x74, 0xac, 0x14, 0x58,
            0xbf, 0x6c, 0xeb, 0xa1, 0x1a, 0xaa, 0x5b, 0x65, 0x4c, 0x16, 0x9c, 0xcc, 0xa5, 0xb1, 0x2c, 0x43,
            0x1d, 0x05, 0x71, 0xa9, 0x05, 0xd7, 0x9e, 0x86, 0x50, 0x44, 0xeb, 0x9e, 0x33, 0x2d, 0xad, 0x21,
            0xc9, 0x2e, 0x37, 0x67, 0x46, 0x13, 0xa5, 0x96, 0x30, 0xbf, 0x9e, 0xfa, 0x55, 0x80, 0x7f, 0x9b,
            0x8d, 0x53, 0xe3, 0x08, 0xf0, 0xa9, 0xfe, 0x88, 0xd8, 0xa9, 0x16, 0xcb, 0x02, 0xa6, 0x63, 0x1e,
            0x89, 0xa2, 0xf2, 0xe1, 0x86, 0x8f, 0x50, 0x89, 0x34, 0xa2, 0x9f, 0x64, 0xd6, 0xe5, 0x9c, 0x67,
            0xf0, 0x56, 0xbb, 0x0d, 0xbb, 0xaf, 0x1d, 0xd8, 0xf3, 0xc5, 0xc7, 0xb9, 0xa0, 0x24, 0xeb, 0x0b,
            0x87, 0x0f, 0x40, 0x7e, 0xdd, 0xe7, 0x88, 0xeb, 0xd2, 0x7e, 0xa3, 0x93, 0xc9, 0xc4, 0x1b, 0x5a,
            0xf1, 0xf5, 0x54, 0x09, 0xc6, 0x38, 0x9f, 0xd2, 0x02, 0xaa, 0x5c, 0xf3, 0x17, 0x4e, 0x29, 0x97,
            0xaf, 0xc2, 0xf2, 0xe3, 0x00, 0xb1, 0x49, 0x7d, 0x97, 0x3f, 0x49, 0xe3, 0xf7, 0x0b, 0x5b, 0x76,
            0xc8, 0x89, 0x3c, 0xff, 0x27, 0x4a, 0x7a, 0x80, 0xe1, 0x67, 0x6e, 0xb0, 0xc2, 0x35, 0xf9, 0xaa,
            0xb7, 0x65, 0x3e, 0x8c, 0x8d, 0x2a, 0x69, 0x9a, 0xdc, 0xeb, 0x53, 0x7d, 0xd9, 0xc8, 0x5d, 0xa5,
            0x1c, 0x5f, 0xab, 0x52, 0xf5, 0x35, 0xd9, 0x76, 0x5f, 0x7b, 0x63, 0xd7, 0x35, 0x30, 0x52, 0x94,
            0x2c, 0x37, 0x99, 0x9b, 0x5a, 0x83, 0x37, 0x5d, 0x52, 0x85, 0xc0, 0x8b, 0xa1, 0xac, 0xe6, 0xcc,
            0x64, 0x51, 0x23, 0x7f, 0x21, 0x47, 0x95, 0x6d, 0xb7, 0xcb, 0x45, 0x78, 0xf4, 0xbf, 0xd9, 0x26,
            0x3c, 0x82, 0xc5, 0x64, 0x75, 0x7a, 0x8f, 0x3f, 0xa1, 0x46, 0x3d, 0x4e, 0x4d, 0x11, 0xee, 0xf1,
            0xae, 0xc4, 0x3a, 0x09, 0xa8, 0xfc, 0x89, 0x1f, 0x37, 0xe0, 0xe4, 0xf5, 0x44, 0x33, 0xa5, 0xec,
            0xbb, 0xf5, 0x0e, 0xc0, 0x1d, 0x54, 0x52, 0x41, 0xc4, 0xf8, 0x65, 0xc7, 0x3d, 0x10, 0xab, 0x4b,
            0x90, 0x28, 0xb1, 0x62, 0x85, 0x5d, 0xf1, 0xd7, 0xe0, 0xd2, 0x0f, 0x12, 0x51, 0x2f, 0x0d, 0xc5,
            0x9f, 0xab, 0x8b, 0x93, 0x2f, 0x72, 0xb4, 0x74, 0xdd, 0xdd, 0x29, 0x0a, 0x6f, 0xa7, 0x2a, 0xc1,
            0x82, 0x5e, 0xfc, 0xb2, 0x27, 0x3f, 0xa0, 0x7d, 0xce, 0xd2, 0x40, 0x13, 0xcb, 0x0a, 0xde, 0x0d,
            0xc5, 0xc4, 0x45, 0x1f, 0x62, 0xfb, 0x5a, 0xd6, 0x3d, 0x91, 0x44, 0x85, 0x0c, 0x11, 0x76, 0x6a,
            0x6f, 0x65, 0x3b, 0xc8, 0x67, 0x06, 0x36, 0x6d, 0x01, 0x3d, 0xdb, 0x22, 0x03, 0x75, 0xc5, 0xb2,
            0x56, 0xf3, 0xed, 0x6c, 0x25, 0x2d, 0x7d, 0x21, 0xc1, 0xa5, 0xb6, 0xe6, 0x3c, 0xbd, 0xb8, 0x16,
            0x0a, 0x36, 0x6e, 0x60, 0x9c, 0xd6, 0x23, 0x53, 0x2b, 0xbc, 0x14, 0xbe, 0xfd, 0x1b, 0x57, 0xbb,
            0x0b, 0xfd, 0x7e, 0x65, 0xe3, 0xc7, 0x00, 0x56, 0x6a, 0x9f, 0xf4, 0xf3, 0x83, 0xae, 0x2f, 0x4c,
            0xe6, 0x68, 0x80, 0x8d, 0x55, 0x0f, 0xfa, 0x87, 0xbf, 0xcc, 0x62, 0xe4, 0xa8, 0x37, 0xe2, 0x04,
            0x1f, 0xc3, 0x4b, 0x39, 0xb2, 0x70, 0x88, 0x2e, 0x4c, 0x89, 0xfb, 0x3d, 0x74, 0xae, 0x82, 0xf8,
            0xea, 0x9c, 0x7d, 0xf1, 0x78, 0x22, 0xac, 0x2f, 0x96, 0x52, 0x13, 0x1b, 0x8b, 0xcc, 0x01, 0x17,
            0x9d, 0xff, 0x4f, 0x1f, 0xeb, 0x3d, 0x97, 0xea, 0x2a, 0x0c, 0xd6, 0x0c, 0x5c, 0x7a, 0x41, 0x1f,
            0x6e, 0x5b, 0x9b, 0x5d, 0x16, 0xb8, 0x0c, 0x08, 0x93, 0x51, 0xa4, 0xb9, 0x4a, 0xe9, 0x4c, 0x3a,
            0x60, 0x88, 0x74, 0xf0, 0xa8, 0xb5, 0x2a, 0x9f, 0x34, 0x6f, 0xad, 0x8a, 0xed, 0xc2, 0x9e, 0x38,
            0xdc, 0x74, 0x33, 0x62, 0x6b, 0x4e, 0x1d, 0x82, 0x92, 0xa8, 0xd2, 0xda, 0x86, 0x9d, 0x90, 0xcb,
            0x6b, 0x19, 0x07, 0x56, 0xa3, 0x59, 0x10, 0x57, 0x89, 0xd1, 0x00, 0xcc, 0x94, 0x7c, 0xcd, 0x0c,
            0xdc, 0x74, 0xfb, 0x5f, 0xe4, 0x6f, 0x73, 0x1e, 0xa8, 0x8e, 0xad, 0x31, 0x0d, 0x07, 0xe7, 0x8d,
            0x23, 0xf9, 0x8f, 0xed, 0x04, 0x2b, 0x47, 0x3f, 0x54, 0xcb, 0xbb, 0x0b, 0xf8, 0xc6, 0x32, 0xd5,
            0x7d, 0x20, 0x92, 0xfd, 0xa6, 0xba, 0x75, 0x02, 0x42, 0x5a, 0x72, 0xa4, 0xdf, 0xd0, 0x0a, 0xb0,
            0x33, 0x80, 0xf1, 0xea, 0x15, 0x3d, 0x5f, 0xae, 0xcf, 0x1f, 0xcc, 0x44, 0xb5, 0x5f, 0x69, 0x9f,
            0x90, 0x40, 0xf0, 0x6e, 0xc9, 0x9a, 0x63, 0x52, 0x97, 0x1e, 0xed, 0xc8, 0x05, 0x12, 0xb2, 0xfb,
            0xad, 0xe1, 0x13, 0xa5, 0x39, 0x53, 0x88, 0xaf, 0xcf, 0xbe, 0x01, 0x4a, 0x65, 0x62, 0xf0, 0x35,
            0x2f, 0x76, 0x9a, 0x8b, 0xc3, 0xbc, 0x43, 0x5b, 0xc4, 0x91, 0xcc, 0x04, 0xfe, 0xcc, 0xc4, 0xf5,
            0xa3, 0x27, 0x88, 0x97, 0x49, 0xca, 0xe2, 0x33, 0x1d, 0xff, 0x96, 0x33, 0x4b, 0x50, 0x49, 0x86,
            0xdc, 0x65, 0x9f, 0x55, 0xc1, 0xb6, 0x85, 0xe5, 0x9f, 0x3d, 0xd1, 0x87, 0x84, 0xd8, 0x08, 0x9f,
            0x03, 0x4c, 0xc7, 0xa8, 0x8b, 0x59, 0xb7, 0x58, 0xd2, 0x10, 0x1c, 0x3f, 0xf9, 0x2d, 0x5f, 0x37,
            0x5c, 0x70, 0x90, 0x84, 0xea, 0x4b, 0x37, 0x55, 0x9c, 0x12, 0x2d, 0xa4, 0xb2, 0x75, 0x5d, 0x37,
            0xfc, 0x7c, 0xa7, 0x19, 0xb4, 0x88, 0xba, 0xf3, 0xea, 0xe2, 0xf1, 0xa2, 0xe3, 0x23, 0xd6, 0x5e,
            0x6e, 0xf8, 0x37, 0x61, 0xf2, 0xec, 0xd8, 0x17, 0x19, 0xa3, 0x69, 0xbd, 0xd8, 0x51, 0x17, 0x37,
            0xa3, 0xc6, 0x8f, 0x26, 0xf1, 0x19, 0x6f, 0xf4, 0xf9, 0xdb, 0x09, 0xef, 0x70, 0x88, 0x81, 0x78,
            0xfd, 0x2e, 0x60, 0xdb, 0xdf, 0x6e, 0xe9, 0xf6, 0xef, 0xb0, 0x7e, 0x75, 0xc5, 0x18, 0x39, 0xdc,
            0x4b, 0x33, 0xda, 0x51, 0xad, 0xe4, 0x7b, 0x7d, 0x46, 0xd2, 0x39, 0x62, 0xf1, 0x71, 0x4c, 0xda,
            0x49, 0xa0, 0x7b, 0xc7, 0x67, 0xe8, 0x47, 0x6e, 0x3a, 0x43, 0x4e, 0x31, 0x0e, 0x30, 0x3b, 0x60,
            0x7d, 0xc1, 0x0c, 0x4e, 0x82, 0x7e, 0xf6, 0x02, 0xcf, 0xd4, 0xfe, 0x8f, 0x39, 0x8e, 0xce, 0xe6,
            0x7b, 0x3a, 0xc7, 0xae, 0xde, 0xf1, 0x2b, 0xae, 0x4e, 0xd8, 0x60, 0x7e, 0x8a, 0x10, 0xdf, 0xdf,
            0xb8, 0x57, 0x5b, 0x7c, 0xb3, 0x80, 0x55, 0x16, 0x4c, 0xab, 0x62, 0x39, 0xb7, 0xa4, 0x4c, 0xd3,
            0xaa, 0xca, 0x5b, 0xd1, 0xb5, 0xcb, 0xf4, 0x46, 0xfc]
        );

        encrypted_data.set_kvno(2);

        let ticket = Ticket::new(
            Realm::from_ascii("KINGDOM.HEARTS").unwrap(),
            principal_name,
            encrypted_data
        );

        assert_eq!(ticket, ticket_asn1.no_asn1_type().unwrap());
    }

}