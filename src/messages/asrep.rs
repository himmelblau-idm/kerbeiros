use super::super::structs_asn1;
use super::super::tickets::*;
use super::super::error::*;
use ascii::AsciiString;

#[derive(Debug, Clone, PartialEq)]
pub struct AsRep {
    client_realm: AsciiString,
    client_name: AsciiString,
    ticket: Ticket,
    enc_part: EncryptedData
}


impl AsRep {

    fn new(client_realm: AsciiString, client_name: AsciiString, 
        ticket: Ticket, enc_part: EncryptedData) -> Self {
        return Self {
            client_realm,
            client_name,
            ticket,
            enc_part
        };
    }
    
    
    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let as_rep = structs_asn1::AsRep::parse(raw)?;

        return Ok(Self::new(
            as_rep.get_crealm_ascii_string(),
            as_rep.get_cname_ascii_string(),
            Ticket::from(as_rep.get_ticket()),
            EncryptedData::from(as_rep.get_enc_part())
        ));
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::constants::*;

    #[test]
    fn test_parse_as_rep() {
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

        let as_rep_parsed = AsRep::parse(&encoded_as_rep).unwrap();

        let ticket = Ticket::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(),
            AsciiString::from_ascii("krbtgt/KINGDOM.HEARTS").unwrap(),
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![9])
        );

        let as_rep = AsRep::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(), 
            AsciiString::from_ascii("mickey").unwrap(),
            ticket,
            EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![9])
        );

        assert_eq!(as_rep, as_rep_parsed);
    }

}