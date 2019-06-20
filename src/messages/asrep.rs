use super::super::structs_asn1;
use super::super::tickets::*;
use super::super::error::*;
use ascii::AsciiString;
use super::super::constants::*;
use super::super::crypter::*;

#[derive(Debug, Clone, PartialEq)]
enum AsRepEncPart{
    EncryptedData(EncryptedData),
    EncAsRepPart(EncAsRepPart)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsRep {
    client_realm: AsciiString,
    client_name: AsciiString,
    ticket: Ticket,
    enc_part: AsRepEncPart,
    encryption_salt: Vec<u8>
}


impl AsRep {

    fn new(client_realm: AsciiString, client_name: AsciiString, 
        ticket: Ticket, enc_part: AsRepEncPart) -> Self {
        return Self {
            client_realm,
            client_name,
            ticket,
            enc_part,
            encryption_salt: Vec::new()
        };
    }

    fn set_salt(&mut self, salt: Vec<u8>) {
        self.encryption_salt = salt;
    }
    
    
    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let as_rep_asn1 = structs_asn1::AsRep::parse(raw)?;

        let mut as_rep = Self::new(
            as_rep_asn1.get_crealm_ascii_string(),
            as_rep_asn1.get_cname_ascii_string(),
            Ticket::from(as_rep_asn1.get_ticket()),
            AsRepEncPart::EncryptedData(EncryptedData::from(as_rep_asn1.get_enc_part()))
        );

        if let Some(salt) = as_rep_asn1.get_salt() {
            as_rep.set_salt(salt);
        }

        return Ok(as_rep);
    }

    pub fn decrypt_encrypted_data_with_password(&mut self, password: &str) -> KerberosResult<()> {
        match self.enc_part {
            AsRepEncPart::EncryptedData(enc_data) => {
                return self._decrypt_enc_part_with_password(enc_data, password);
            }
            AsRepEncPart::EncAsRepPart(_) => {
                return Ok(());
            }
        }
    }

    fn _decrypt_enc_part_with_password(&mut self, enc_part: EncryptedData, password: &str) -> KerberosResult<()> {
        match *enc_part.get_etype() {
            AES256_CTS_HMAC_SHA1_96 => {
                let key = generate_aes_256_key(password.as_bytes(), &self.encryption_salt);
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

#[cfg(test)]
mod test {
    use super::*;

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

        let mut as_rep = AsRep::new(
            AsciiString::from_ascii("KINGDOM.HEARTS").unwrap(), 
            AsciiString::from_ascii("mickey").unwrap(),
            ticket,
            AsRepEncPart::EncryptedData(EncryptedData::new(AES256_CTS_HMAC_SHA1_96, vec![9]))
        );

        as_rep.set_salt("KINGDOM.HEARTSmickey".as_bytes().to_vec());

        assert_eq!(as_rep, as_rep_parsed);
    }

}