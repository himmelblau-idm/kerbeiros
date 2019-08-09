use crate::structs::*;


pub struct AddressMapper{}

impl AddressMapper {

    pub fn host_address_to_address(host_address: &HostAddress) -> Address {
        return Address::new(
            host_address.get_addr_type() as u16,
            CountedOctetString::new(host_address.get_address_without_modifications())
        )
    }

    pub fn host_addresses_to_address_vector(host_addresses: &HostAddresses) -> Vec<Address> {
        let mut addresses = Vec::new();
        for host_address in host_addresses.iter() {
            addresses.push(Self::host_address_to_address(host_address));
        }
        return addresses;
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
            CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec())
        );

        assert_eq!(address, AddressMapper::host_address_to_address(&host_address));
    }


    #[test]
    fn host_addresses_to_address_vector() {

        let mut addresses = Vec::new();
        addresses.push(
            Address::new(
                address_type::NETBIOS as u16,
                CountedOctetString::new("KINGDOM.HEARTS".as_bytes().to_vec())
            )
        );
        addresses.push(
            Address::new(
                7,
                CountedOctetString::new("HOLLOWBASTION".as_bytes().to_vec())
            )
        );

        let mut host_addresses = HostAddresses::new(HostAddress::NetBios("KINGDOM.HEARTS".to_string()));
        host_addresses.push(HostAddress::Raw(7, "HOLLOWBASTION".as_bytes().to_vec()));

        assert_eq!(addresses, AddressMapper::host_addresses_to_address_vector(&host_addresses));

    }
    
}
