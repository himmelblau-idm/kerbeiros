use red_asn1::*;
use super::ticket::*;
use super::encrypteddata::*;

#[derive(Debug,PartialEq,Clone)]
pub struct KrbCred {
    pvno: i8,
    msg_type: i8,
    tickets: SeqOfTickets,
    enc_part: EncryptedData
}

impl KrbCred {

    pub fn new(tickets: SeqOfTickets, enc_part: EncryptedData) -> Self {
        return Self {
            pvno: 5,
            msg_type: 22,
            tickets,
            enc_part
        };
    }

    pub fn get_pvno(&self) -> i8 {
        return self.pvno;
    }

    pub fn get_msg_type(&self) -> i8 {
        return self.msg_type;
    }

    pub fn get_tickets(&self) -> &SeqOfTickets {
        return &self.tickets;
    }

    pub fn get_enc_part(&self) -> &EncryptedData {
        return &self.enc_part;
    }

    pub fn build(&self) -> Vec<u8> {
        return KrbCredAsn1::from(self).encode().unwrap();
    }

}

#[derive(Sequence, Default, Debug, PartialEq)]
#[seq(application_tag = 22)]
pub(crate) struct KrbCredAsn1 {
    #[seq_field(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_field(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_field(context_tag = 2)]
    tickets: SeqField<SeqOfTicketsAsn1>,
    #[seq_field(context_tag = 3)]
    enc_part: SeqField<EncryptedDataAsn1>,
}

impl From<&KrbCred> for KrbCredAsn1 {

    fn from(krb_cred: &KrbCred) -> Self {
        let mut krb_cred_asn1 = Self::default();

        krb_cred_asn1.set_pvno(Integer::from(krb_cred.get_pvno() as i64));
        krb_cred_asn1.set_msg_type(Integer::from(krb_cred.get_msg_type() as i64));
        krb_cred_asn1.set_tickets(krb_cred.get_tickets().into());
        krb_cred_asn1.set_enc_part(krb_cred.get_enc_part().into());

        return krb_cred_asn1;
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::principalname::*;
    use super::super::kerberosstring::*;
    use super::super::realm::*;
    use crate::constants::*;

    #[test]
    fn create_default_krb_cred_asn1() {
        assert_eq!(
            KrbCredAsn1 {
                pvno: SeqField::default(),
                msg_type: SeqField::default(),
                tickets: SeqField::default(),
                enc_part: SeqField::default()
            },
            KrbCredAsn1::default()
        )
    }

    #[test]
    fn test_encode_krb_cred() {
        
        let mut encrypted_data = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x4e]);
        encrypted_data.set_kvno(2);

        let mut principal_name =  PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let ticket = Ticket::new(
            Realm::from_ascii("KINGDOM.HEARTS").unwrap(),
            principal_name,
            encrypted_data
        );

        let mut seq_of_tickets = SeqOfTickets::default();
        seq_of_tickets.push(ticket);


        let krb_cred = KrbCred::new(
            seq_of_tickets,
            EncryptedData::new(NO_ENCRYPTION, vec![0x4e])
        );

        let raw: Vec<u8> = vec![
            0x76, 0x71, 0x30, 0x6f, 
                0xa0, 0x3, 0x2, 0x1, 0x5, 
                0xa1, 0x3, 0x2, 0x1, 0x16, 
                0xa2, 0x55, 0x30, 0x53, 
                        0x61, 0x51, 0x30, 0x4f, 
                            0xa0, 0x3, 0x2, 0x1, 0x5, 
                            0xa1, 0x10, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                            0xa2, 0x23, 0x30, 0x21, 
                                0xa0, 0x3, 0x2, 0x1, 0x2, 
                                0xa1, 0x1a, 0x30, 0x18, 0x1b, 0x6, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0xe, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 
                            0xa3, 0x11, 0x30, 0xf, 
                                0xa0, 0x3, 0x2, 0x1, 0x12, 
                                0xa1, 0x3, 0x2, 0x1, 0x2, 
                                0xa2, 0x3, 0x4, 0x1, 
                                    0x4e,                  
                0xa3, 0xc, 0x30, 0xa, 
                    0xa0, 0x3, 0x2, 0x1, 0x0, 
                    0xa2, 0x3, 0x4, 0x1, 
                        0x4e
        ];

        assert_eq!(raw, krb_cred.build());

    }

}
