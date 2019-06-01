

use std::net::TcpStream;
use std::net::{SocketAddr, AddrParseError};
use std::io::{Write, Read};
use std::io;
use std::time::Duration;
use std::result::Result;
use super::super::byteparser;
use super::KerberosResult;
use super::error::*;
use failure::ResultExt;

static DEFAULT_KERBEROS_PORT: u16 = 88;

#[derive(Debug)]
pub struct KerberosRequester {
    dst_addr: SocketAddr
}

impl KerberosRequester {

    pub fn new(host: &String) -> KerberosResult<KerberosRequester> {
        return Self::new_port(host, DEFAULT_KERBEROS_PORT);
    }

    pub fn new_port(host: &String, port: u16) -> KerberosResult<KerberosRequester> {
        let dst_addr = Self::_host_port_to_addr(host, port).context(KerberosErrorKind::InvalidKDC)?;

        return Ok(KerberosRequester {
            dst_addr
        });
    }


    pub fn request(&self, raw_request: &Vec<u8>) -> KerberosResult<Vec<u8>> {
        let raw_response = self.request_tcp(raw_request).context(KerberosErrorKind::NetworkError)?;
        return Ok(raw_response);
    }

    fn request_tcp(&self, raw_request: &Vec<u8>) -> Result<Vec<u8>, io::Error> {
        
        let mut tcp_stream = TcpStream::connect_timeout(&self.dst_addr, Duration::new(5, 0))?;

        let raw_sized_request = Self::_set_size_header_to_request(raw_request);
        tcp_stream.write(&raw_sized_request)?;

        let mut len_data_bytes = [0 as u8; 4];
        tcp_stream.read_exact(&mut len_data_bytes)?;
        let data_length = byteparser::be_bytes_to_u32(&len_data_bytes);

        let mut raw_response: Vec<u8> = Vec::with_capacity(data_length as usize);
        tcp_stream.read_exact(&mut raw_response)?;

        return Ok(raw_response);
    }

    fn _set_size_header_to_request(raw_request: &Vec<u8>) -> Vec<u8> {
        let request_length = raw_request.len() as u32;
        let mut raw_sized_request: Vec<u8> = byteparser::u32_to_be_bytes(request_length).to_vec();
        raw_sized_request.append(&mut raw_request.clone());

        return raw_sized_request;
    }


    fn _host_port_to_addr(host: &String, port: u16) -> Result<SocketAddr, AddrParseError> {
        let mut addr_str = host.clone();
        addr_str.push_str(":");
        addr_str.push_str(&port.to_string());
        let dst_addr: SocketAddr = addr_str.parse()?;
        return Ok(dst_addr);
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[should_panic(expected = "Invalid KDC hostname")]
    #[test]
    fn test_invalid_host_format() {
        KerberosRequester::new(&"kdc.com".to_string()).unwrap();
    }

    #[test]
    fn test_valid_host_format() {
        KerberosRequester::new(&"1.2.3.4".to_string()).unwrap();
    }


    #[should_panic(expected = "Network error")]
    #[test]
    fn test_request_networks_error() {
        let requester = KerberosRequester::new(&"0.0.0.0".to_string()).unwrap();
        requester.request(&vec![]).unwrap();
    }


}