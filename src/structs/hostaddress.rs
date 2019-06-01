use asn1::*;
use asn1_derive::*;
use super::int32::{Int32, Int32Asn1};

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


static NETBIOS_PADDING_CHAR: char = 32 as char;

pub enum HostAddress {
    NetBios(String)
}

impl HostAddress {

    pub fn bytes_value(&self) -> Vec<u8> {
        match self {
            HostAddress::NetBios(string) => {
                return HostAddress::_get_padded_netbios_string_bytes(&string);
            }
        }
    }

    fn _get_padded_netbios_string_bytes(string: &String) -> Vec<u8> {
        let mut padded_string = string.clone();
        let mut padded_len = padded_string.len() % 16;

        if padded_len > 0 {
            padded_len = 16 - padded_len;
            for _ in 0..padded_len {
                padded_string.push(NETBIOS_PADDING_CHAR);
            }
        }

        return padded_string.into_bytes();
    }

    pub fn into_i32(&self) -> i32 {
        match self {
            HostAddress::NetBios(_) => 20
        }
    }

    fn asn1_type(&self) -> HostAddressAsn1 {
        return HostAddressAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
struct HostAddressAsn1 {
    #[seq_comp(context_tag = 0)]
    addr_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1)]
    address: SeqField<OctetString>
}

impl HostAddressAsn1 {

    fn new(host_address: &HostAddress) -> HostAddressAsn1 {
        let mut host_address_asn1 = Self::new_empty();

        host_address_asn1.set_addr_type(Int32::new(host_address.into_i32()).asn1_type());
        host_address_asn1.set_address(OctetString::new(host_address.bytes_value()));
    
        return host_address_asn1;
    }

    fn new_empty() -> HostAddressAsn1 {
        return HostAddressAsn1{
            addr_type: SeqField::new(),
            address: SeqField::new()
        };
    }

}

impl Asn1InstanciableObject for HostAddressAsn1 {

    fn new_default() -> HostAddressAsn1 {
        return HostAddressAsn1::new_empty();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_netbios_host_address() {
        let netbios_address = HostAddress::NetBios("HOLLOWBASTION".to_string());
        assert_eq!(vec![0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 
                        0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 
                        0x42, 0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20],
                   netbios_address.asn1_type().encode().unwrap());
    }

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
    fn test_netbios_padding() {
        let mut host_address = HostAddress::NetBios("".to_string());
        assert_eq!(Vec::<u8>::new(), host_address.bytes_value());

        host_address = HostAddress::NetBios("1".to_string());
        assert_eq!(vec![0x31, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.bytes_value());
        
        host_address = HostAddress::NetBios("12345".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.bytes_value());

        host_address = HostAddress::NetBios("1234567890123456".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
                        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36], 
                    host_address.bytes_value());
        
        host_address = HostAddress::NetBios("12345678901234567".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
                        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                        0x37, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.bytes_value());
    }
}