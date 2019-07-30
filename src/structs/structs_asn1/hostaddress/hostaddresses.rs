use red_asn1::*;
use super::hostaddress::*;
use crate::error::*;
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Clone)]
pub struct HostAddresses {
    addresses: Vec<HostAddress>
}

impl HostAddresses {

    fn new_empty() -> Self {
        return Self {
            addresses: Vec::new()
        };
    }

    pub fn new(address: HostAddress) -> HostAddresses {
        return HostAddresses{
            addresses: vec![address]
        };
    }

    pub fn asn1_type(&self) -> HostAddressesAsn1 {
        return HostAddressesAsn1::new(self);
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

pub struct HostAddressesAsn1 {
    subtype: SequenceOf<HostAddressAsn1>
}

impl HostAddressesAsn1 {
    fn new(host_addresses: &HostAddresses) -> HostAddressesAsn1 {
        return HostAddressesAsn1 {
            subtype: HostAddressesAsn1::_seq_of_host_address(host_addresses)
        }
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _seq_of_host_address(host_addresses: &HostAddresses) -> SequenceOf<HostAddressAsn1> {
        let mut seq_of_host_addresses: SequenceOf<HostAddressAsn1> = SequenceOf::new();

        for host_address in host_addresses.addresses.iter() {
            seq_of_host_addresses.push(host_address.asn1_type());
        }

        return seq_of_host_addresses;
    }

    pub fn no_asn1_type(&self) -> KerberosResult<HostAddresses> {
        let mut host_addresses = HostAddresses::new_empty();
        for host_address_asn1 in self.subtype.iter() {
            host_addresses.push(host_address_asn1.no_asn1_type()?);
        }

        return Ok(host_addresses);
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

impl Asn1InstanciableObject for HostAddressesAsn1 {
    fn new_default() -> Self {
        return Self::new_empty();
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
                   addresses.asn1_type().encode().unwrap());
    }

    #[test]
    fn test_decode_netbios_host_addresses() {
        let mut host_addresses_asn1 = HostAddressesAsn1::new_empty();

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