use red_asn1::*;
use super::hostaddress::*;
use crate::error::Result;
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Clone)]
pub struct HostAddresses {
    addresses: Vec<HostAddress>
}

impl HostAddresses {

    fn default() -> Self {
        return Self {
            addresses: Vec::new()
        };
    }

    pub fn new(address: HostAddress) -> HostAddresses {
        return HostAddresses{
            addresses: vec![address]
        };
    }

}

impl Deref for HostAddresses {
    type Target = Vec<HostAddress>;
    fn deref(&self) -> &Vec<HostAddress> {
        &self.addresses
    }
}

impl DerefMut for HostAddresses {
    fn deref_mut(&mut self) -> &mut Vec<HostAddress> {
        &mut self.addresses
    }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct HostAddressesAsn1 {
    subtype: SequenceOf<HostAddressAsn1>
}

impl HostAddressesAsn1 {

    fn seq_of_host_address(host_addresses: &HostAddresses) -> SequenceOf<HostAddressAsn1> {
        let mut seq_of_host_addresses: SequenceOf<HostAddressAsn1> = SequenceOf::default();

        for host_address in host_addresses.addresses.iter() {
            seq_of_host_addresses.push(host_address.into());
        }

        return seq_of_host_addresses;
    }

    pub fn no_asn1_type(&self) -> Result<HostAddresses> {
        let mut host_addresses = HostAddresses::default();
        for host_address_asn1 in self.subtype.iter() {
            host_addresses.push(host_address_asn1.no_asn1_type()?);
        }

        return Ok(host_addresses);
    }
}

impl From<&HostAddresses> for HostAddressesAsn1 {
    fn from(host_addresses: &HostAddresses) -> HostAddressesAsn1 {
        return HostAddressesAsn1 {
            subtype: HostAddressesAsn1::seq_of_host_address(host_addresses)
        }
    }
}

impl Asn1Object for HostAddressesAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> red_asn1::Result<Vec<u8>> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_netbios_host_addresses() {
        let netbios_address = HostAddress::NetBios("HOLLOWBASTION".to_string());
        let addresses = HostAddresses::new(netbios_address);
        assert_eq!(vec![0x30, 0x1b, 
                        0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 
                        0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 
                        0x42, 0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20],
                   HostAddressesAsn1::from(&addresses).encode().unwrap());
    }

    #[test]
    fn test_decode_netbios_host_addresses() {
        let mut host_addresses_asn1 = HostAddressesAsn1::default();

        host_addresses_asn1.decode(&[
            0x30, 0x1b, 
            0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 
            0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 
            0x42, 0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20]
        ).unwrap();

        let netbios_address = HostAddress::NetBios("HOLLOWBASTION".to_string());
        let addresses = HostAddresses::new(netbios_address);
        assert_eq!(addresses, host_addresses_asn1.no_asn1_type().unwrap());
    }
}