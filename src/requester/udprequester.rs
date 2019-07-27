pub use std::net::IpAddr;
use std::net::*;
use std::io;
use std::result::Result;
use crate::error::*;
use failure::ResultExt;

use super::kerberosrequester::*;

#[derive(Debug)]
pub struct UDPRequester {
    dst_addr: SocketAddr
}

impl UDPRequester {

    pub fn new(host_address: IpAddr) -> Self {
        return Self{
            dst_addr: SocketAddr::new(host_address, DEFAULT_KERBEROS_PORT)
        };
    }

    fn request_and_response_udp(&self, raw_request: &[u8]) -> Result<Vec<u8>, io::Error> {
        
        let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
        udp_socket.connect(self.dst_addr)?;

        udp_socket.send(raw_request)?;

        let data_length = self.calculate_response_size(&udp_socket)?;

        let mut raw_response = vec![0; data_length as usize];
        udp_socket.recv(&mut raw_response)?;

        return Ok(raw_response);
    }

    fn calculate_response_size(&self, udp_socket: &UdpSocket) -> io::Result<usize> {
        let mut raw_response = vec![0; 2048];
        let mut data_length = udp_socket.peek(&mut raw_response)?;
        while data_length == raw_response.len() {
            raw_response.append(&mut raw_response.clone());
            data_length = udp_socket.peek(&mut raw_response)?;
        }
        return Ok(data_length);
    }

}

impl KerberosRequester for UDPRequester {

    fn request_and_response(&self, raw_request: &[u8]) -> KerberosResult<Vec<u8>> {
        let raw_response = self.request_and_response_udp(raw_request).context(
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
        let requester = UDPRequester::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        requester.request_and_response(&vec![]).unwrap();
    }

}