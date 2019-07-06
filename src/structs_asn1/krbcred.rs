use asn1::*;
use asn1_derive::*;
use super::ticket::*;
use super::encrypteddata::*;


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

    fn asn1_type(&self) -> KrbCredAsn1 {
        return KrbCredAsn1::new(self);
    }

    pub fn build(&self) -> Vec<u8> {
        return self.asn1_type().encode().unwrap();
    }

}

#[derive(Asn1Sequence)]
#[seq(application_tag = 22)]
struct KrbCredAsn1 {
    #[seq_comp(context_tag = 0)]
    pvno: SeqField<Integer>,
    #[seq_comp(context_tag = 1)]
    msg_type: SeqField<Integer>,
    #[seq_comp(context_tag = 2)]
    tickets: SeqField<SeqOfTicketsAsn1>,
    #[seq_comp(context_tag = 3)]
    enc_part: SeqField<EncryptedDataAsn1>,
}

impl KrbCredAsn1 {

    fn new(krb_cred: &KrbCred) -> Self {
        let mut krb_cred_asn1 = Self::new_empty();

        krb_cred_asn1.set_pvno(Integer::new(krb_cred.pvno as i64));
        krb_cred_asn1.set_msg_type(Integer::new(krb_cred.msg_type as i64));
        krb_cred_asn1.set_tickets(krb_cred.tickets.asn1_type());
        krb_cred_asn1.set_enc_part(krb_cred.enc_part.asn1_type());

        return krb_cred_asn1;
    }

    fn new_empty() -> Self {
        return Self {
            pvno: SeqField::new(),
            msg_type: SeqField::new(),
            tickets: SeqField::new(),
            enc_part: SeqField::new()
        };
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
    fn test_encode_krb_cred() {
        
        let mut encrypted_data = EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![0x4e]);
        encrypted_data.set_kvno(2);

        let mut principal_name =  PrincipalName::new(NT_SRV_INST, KerberosString::from_ascii("krbtgt").unwrap());
        principal_name.push(KerberosString::from_ascii("KINGDOM.HEARTS").unwrap());

        let ticket = Ticket::new(5, 
            Realm::from_ascii("KINGDOM.HEARTS").unwrap(),
            principal_name,
            encrypted_data
        );

        let mut seq_of_tickets = SeqOfTickets::new_empty();
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

        assert_eq!(raw, krb_cred.asn1_type().encode().unwrap());

    }

}
