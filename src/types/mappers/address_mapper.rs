use crate::constants::address_type;
use crate::error::Result;
use crate::types::{Address, CountedOctetString, HostAddress, HostAddresses};
use std::convert::TryInto;

pub struct AddressMapper {}

impl AddressMapper {
    pub fn host_address_to_address(host_address: &HostAddress) -> Address {
        return Address::new(
            host_address.addr_type() as u16,
            CountedOctetString::new(host_address.address_without_modifications()),
        );
    }

    pub fn host_addresses_to_address_vector(host_addresses: &HostAddresses) -> Vec<Address> {
        let mut addresses = Vec::new();
        for host_address in host_addresses.iter() {
            addresses.push(Self::host_address_to_address(host_address));
        }
        return addresses;
    }

    pub fn address_to_host_address(address: &Address) -> Result<HostAddress> {
        let address_type = address.addrtype() as i32;
        match address_type {
            address_type::NETBIOS => {
                return Ok(HostAddress::NetBios(address.addrdata().clone().try_into()?));
            }
            _ => {
                return Ok(HostAddress::Raw(
                    address_type,
                    address.addrdata().clone().data_move(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn host_address_to_address() {
        let host_address = HostAddress::NetBios("KINGDOM.HEARTS".to_string());

        let address = Address::new(
            address_type::NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        );

        assert_eq!(
            address,
            AddressMapper::host_address_to_address(&host_address)
        );
    }

    #[test]
    fn host_addresses_to_address_vector() {
        let mut addresses = Vec::new();
        addresses.push(Address::new(
            address_type::NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        ));
        addresses.push(Address::new(
            7,
            CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec()),
        ));

        let mut host_addresses =
            HostAddresses::new(HostAddress::NetBios("KINGDOM.HEARTS".to_string()));
        host_addresses.push(HostAddress::Raw(7, "HOLLOWBASTION".as_bytes().to_vec()));

        assert_eq!(
            addresses,
            AddressMapper::host_addresses_to_address_vector(&host_addresses)
        );
    }

    #[test]
    fn address_to_host_address() {
        let host_address = HostAddress::NetBios("KINGDOM.HEARTS".to_string());

        let address = Address::new(
            address_type::NETBIOS as u16,
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec()),
        );

        assert_eq!(
            host_address,
            AddressMapper::address_to_host_address(&address).unwrap()
        );
    }

    #[test]
    fn address_to_host_address_raw() {
        let host_address = HostAddress::Raw(1, vec![1, 2, 3]);

        let address = Address::new(1, CountedOctetString::new(vec![1, 2, 3]));

        assert_eq!(
            host_address,
            AddressMapper::address_to_host_address(&address).unwrap()
        );
    }
}
