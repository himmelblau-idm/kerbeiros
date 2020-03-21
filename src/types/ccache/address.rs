use super::counted_octet_string::*;

/// Represent addresses of Kerberos actors.
#[derive(Debug, PartialEq, Clone)]
pub struct Address {
    addrtype: u16,
    addrdata: CountedOctetString,
}

impl Address {
    pub fn new(addrtype: u16, addrdata: CountedOctetString) -> Self {
        return Self { addrtype, addrdata };
    }

    pub fn addrtype(&self) -> u16 {
        return self.addrtype;
    }

    pub fn addrdata(&self) -> &CountedOctetString {
        return &self.addrdata;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.addrtype.to_be_bytes().to_vec();
        bytes.append(&mut self.addrdata.to_bytes());
        return bytes;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn address_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e,
                0x48, 0x45, 0x41, 0x52, 0x54, 0x53
            ],
            Address::new(
                address_type::NETBIOS as u16,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec())
            )
            .to_bytes()
        )
    }
}
