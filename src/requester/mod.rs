mod kerberosrequester;
pub use kerberosrequester::*;

mod tcprequester;
use tcprequester::*;

pub fn new_requester(host_address: IpAddr) -> Box<KerberosRequester> {
    return Box::new(TCPRequester::new(host_address));
}