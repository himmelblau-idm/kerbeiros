use asn1::*;
use super::hostaddress::*;


pub struct HostAddresses {
    addresses: Vec<HostAddress>
}

impl HostAddresses {
    pub fn new(address: HostAddress) -> HostAddresses {
        return HostAddresses{
            addresses: vec![address]
        };
    }

    pub fn asn1_type(&self) -> HostAddressesAsn1 {
        return HostAddressesAsn1::new(self);
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
}

impl Asn1Object for HostAddressesAsn1 {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>,Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }

}

impl Asn1Tagged for HostAddressesAsn1 {
    fn type_tag() -> Tag {
        return SequenceOf::<HostAddressAsn1>::type_tag();
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
}