use ascii::AsciiString;
pub use super::structs::EncryptedData;
use super::structs_asn1;
use std::convert::From;

pub type TGT = Ticket;

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    realm: AsciiString,
    sname: AsciiString,
    enc_part: EncryptedData
}

impl Ticket {

    pub fn new(realm: AsciiString, sname: AsciiString, enc_part: EncryptedData) -> Self {
        return Self {
            realm,
            sname,
            enc_part
        };
    }
}


impl From<&structs_asn1::Ticket> for Ticket {
    fn from(ticket_asn1: &structs_asn1::Ticket) -> Self {
        return Self::new(
            ticket_asn1.get_realm_ascii_string(), 
            ticket_asn1.get_sname_ascii_string(),
            EncryptedData::from(ticket_asn1.get_encrypted_data())
        );
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::constants::*;

    #[test]
    fn test_from_ticket_asn1() {
        let enc_data_asn1 = structs_asn1::EncryptedData::new(5, vec![1,2,3,4]);
        let mut sname = structs_asn1::PrincipalName::new(
                NT_SRV_INST, 
                structs_asn1::KerberosString::new(AsciiString::from_ascii("krbtgt").unwrap())
                );
        sname.push(structs_asn1::KerberosString::new(AsciiString::from_ascii("KINGDOM.HEARTS").unwrap()));
        
        let ticket_asn1 = structs_asn1::Ticket::new(
            5,
            structs_asn1::Realm::new(AsciiString::from_ascii("KINGDOM.HEARTS").unwrap()),
            sname, 
            enc_data_asn1
        );

        let ticket = Ticket::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("krbtgt/KINGDOM.HEARTS").unwrap(),
            EncryptedData::new(5, vec![1,2,3,4])
        );

        assert_eq!(ticket, Ticket::from(&ticket_asn1));
    }

}