use red_asn1::*;
use red_asn1_derive::*;
pub use super::super::int32::{Int32, Int32Asn1};
use crate::error::*;
use crate::constants::hostaddress::*;

static NETBIOS_PADDING_CHAR: char = 32 as char;

#[derive(Debug, PartialEq, Clone)]
pub enum HostAddress {
    NetBios(String),
    Raw(Int32, Vec<u8>)
}

impl HostAddress {

    pub fn get_address(&self) -> Vec<u8> {
        match self {
            HostAddress::NetBios(string) => {
                return HostAddress::_get_padded_netbios_string_bytes(&string);
            },
            HostAddress::Raw(_, bytes) => {
                return bytes.clone();
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

    pub fn get_address_without_modifications(&self) -> Vec<u8> {
        match self {
            HostAddress::NetBios(string) => {
                return string.as_bytes().to_vec();
            },
            HostAddress::Raw(_, bytes) => {
                return bytes.clone();
            }
        }
    }

    pub fn get_addr_type(&self) -> i32 {
        match self {
            HostAddress::NetBios(_) => NETBIOS_ADDRESS,
            HostAddress::Raw(kind,_) => *kind
        }
    }

    pub fn asn1_type(&self) -> HostAddressAsn1 {
        return HostAddressAsn1::new(self);
    }

}

#[derive(Asn1Sequence)]
pub struct HostAddressAsn1 {
    #[seq_comp(context_tag = 0)]
    addr_type: SeqField<Int32Asn1>,
    #[seq_comp(context_tag = 1)]
    address: SeqField<OctetString>
}

impl HostAddressAsn1 {

    fn new(host_address: &HostAddress) -> HostAddressAsn1 {
        let mut host_address_asn1 = Self::new_empty();

        host_address_asn1.set_addr_type(Int32Asn1::new(host_address.get_addr_type()));
        host_address_asn1.set_address(OctetString::new(host_address.get_address()));
    
        return host_address_asn1;
    }

    fn new_empty() -> HostAddressAsn1 {
        return HostAddressAsn1{
            addr_type: SeqField::new(),
            address: SeqField::new()
        };
    }

    pub fn no_asn1_type(&self) -> KerberosResult<HostAddress> {
        let addr_type_asn1 = self.get_addr_type().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("HostAddress::addr_type".to_string())
        )?;
        let addr_type = addr_type_asn1.no_asn1_type()?;
        let address_asn1 = self.get_address().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("HostAddress::address".to_string())
        )?;
        let address = address_asn1.value().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("HostAddress::address".to_string())
        )?;

        let host_address = match addr_type {
            NETBIOS_ADDRESS => {
                let addr_name = String::from_utf8_lossy(address).to_string().trim_end().to_string();
                HostAddress::NetBios(addr_name)
            },
            _ => {
                HostAddress::Raw(addr_type, address.clone())
            }
        };

        return Ok(host_address);
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
    fn test_netbios_padding() {
        let mut host_address = HostAddress::NetBios("".to_string());
        assert_eq!(Vec::<u8>::new(), host_address.get_address());

        host_address = HostAddress::NetBios("1".to_string());
        assert_eq!(vec![0x31, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.get_address());
        
        host_address = HostAddress::NetBios("12345".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.get_address());

        host_address = HostAddress::NetBios("1234567890123456".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
                        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36], 
                    host_address.get_address());
        
        host_address = HostAddress::NetBios("12345678901234567".to_string());
        assert_eq!(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 
                        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                        0x37, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
                        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20], 
                    host_address.get_address());
    }

    #[test]
    fn test_decode_netbios_host_address() {
        let mut netbios_address_asn1 = HostAddressAsn1::new_empty();

        netbios_address_asn1.decode(&[
            0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 
            0xa1, 0x12, 0x04, 0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 
            0x42, 0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20, 0x20
        ]).unwrap();

        let netbios_address = HostAddress::NetBios("HOLLOWBASTION".to_string());
        assert_eq!(netbios_address, netbios_address_asn1.no_asn1_type().unwrap());
    }
}