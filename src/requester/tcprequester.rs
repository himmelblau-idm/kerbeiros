pub use std::net::IpAddr;
use std::net::*;
use std::io::{Write, Read};
use std::io;
use std::time::Duration;
use std::result::Result;
use crate::byteparser;
use crate::error::*;
use failure::ResultExt;

use super::kerberosrequester::*;

#[derive(Debug)]
pub struct TCPRequester {
    dst_addr: SocketAddr
}

impl TCPRequester {

    pub fn new(host_address: IpAddr) -> Self {
        return Self{
            dst_addr: SocketAddr::new(host_address, DEFAULT_KERBEROS_PORT)
        };
    }

    fn request_and_response_tcp(&self, raw_request: &[u8]) -> Result<Vec<u8>, io::Error> {
        
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

    fn _set_size_header_to_request(raw_request: &[u8]) -> Vec<u8> {
        let request_length = raw_request.len() as u32;
        let mut raw_sized_request: Vec<u8> = byteparser::u32_to_be_bytes(request_length).to_vec();
        raw_sized_request.append(&mut raw_request.to_vec());

        return raw_sized_request;
    }

}

impl KerberosRequester for TCPRequester {

    fn request_and_response(&self, raw_request: &[u8]) -> KerberosResult<Vec<u8>> {
        let raw_response = self.request_and_response_tcp(raw_request).context(
            KerberosErrorKind::NetworkError
        )?;
        return Ok(raw_response);
    }
    
}


#[cfg(test)]
mod tests {
    use super::*;

    #[should_panic(expected = "Network error")]
    #[test]
    fn test_request_networks_error() {
        let requester = TCPRequester::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        requester.request_and_response(&vec![]).unwrap();
    }


}