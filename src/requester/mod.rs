use std::net::IpAddr;

mod kerberosrequester;
pub use kerberosrequester::*;

mod tcprequester;
use tcprequester::TCPRequester;

mod udprequester;
use udprequester::UDPRequester;

mod transportprotocol;
pub use transportprotocol::TransportProtocol;

pub fn new_requester(host_address: IpAddr, transport_protocol: TransportProtocol) -> Box<KerberosRequester> {
    match transport_protocol {
        TransportProtocol::TCP => {
            return Box::new(TCPRequester::new(host_address)); 
        }
        TransportProtocol::UDP => {
            return Box::new(UDPRequester::new(host_address));
        }
    }
    
}