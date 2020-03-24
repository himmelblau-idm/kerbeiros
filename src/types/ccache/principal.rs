use super::counted_octet_string::CountedOctetString;
use getset::Getters;
use nom::multi::many_m_n;
use nom::number::complete::be_u32;
use nom::IResult;

/// Name of some Kerberos entity.
#[derive(Debug, Clone, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Principal {
    name_type: u32,
    realm: CountedOctetString,
    components: Vec<CountedOctetString>,
}

impl Principal {
    pub fn new(
        name_type: u32,
        realm: CountedOctetString,
        components: Vec<CountedOctetString>,
    ) -> Self {
        return Self {
            name_type,
            realm,
            components,
        };
    }

    pub fn build(&self) -> Vec<u8> {
        let mut bytes = self.name_type.to_be_bytes().to_vec();
        let components_len = self.components.len() as u32;

        bytes.append(&mut components_len.to_be_bytes().to_vec());
        bytes.append(&mut self.realm.build());

        for component in self.components.iter() {
            bytes.append(&mut component.build());
        }

        return bytes;
    }

    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (rest, name_type) = be_u32(raw)?;
        let (rest, components_len) = be_u32(rest)?;
        let (rest, realm) = CountedOctetString::parse(rest)?;
        let (rest, components) = many_m_n(
            components_len as usize,
            components_len as usize,
            CountedOctetString::parse,
        )(rest)?;

        return Ok((rest, Self::new(name_type, realm, components)));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn principal_to_bytes() {
        assert_eq!(
            vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49,
                0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x00, 0x00,
                0x00, 0x06, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79
            ],
            Principal::new(
                NT_PRINCIPAL as u32,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
                vec![CountedOctetString::new("mickey".as_bytes().to_vec())]
            )
            .build()
        );
    }

    #[test]
    fn test_parse_principal_from_bytes() {
        assert_eq!(
            Principal::new(
                NT_PRINCIPAL as u32,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
                vec![CountedOctetString::new("mickey".as_bytes().to_vec())]
            ),
            Principal::parse(&[
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x4b, 0x49,
                0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52, 0x54, 0x53, 0x00, 0x00,
                0x00, 0x06, 0x6d, 0x69, 0x63, 0x6b, 0x65, 0x79
            ])
            .unwrap()
            .1,
        );
    }

    #[test]
    #[should_panic(expected = "[0], Eof")]
    fn test_parse_principal_from_bytes_panic() {
        Principal::parse(&[0x00]).unwrap();
    }
}
