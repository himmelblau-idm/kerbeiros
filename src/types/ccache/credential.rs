pub use super::principal::*;
pub use super::keyblock::*;
pub use super::times::*;
pub use super::address::*;
pub use super::authdata::*;
pub use super::countedoctetstring::*;

/// Represents a credential stored in ccache.
#[derive(Debug, PartialEq, Clone)]
pub struct CredentialEntry {
    client: Principal,
    server: Principal,
    key: KeyBlock,
    time: Times,
    is_skey: u8,
    tktflags: u32,
    addrs: Vec<Address>,
    authdata: Vec<AuthData>,
    ticket: CountedOctetString,
    second_ticket: CountedOctetString
}

impl CredentialEntry {

    pub fn new(
        client: Principal, server: Principal, key: KeyBlock,
        time: Times, is_skey: u8, tktflags: u32, ticket: CountedOctetString
        ) -> Self {
        return Self{
            client,
            server,
            key,
            time,
            is_skey,
            tktflags,
            addrs: Vec::new(),
            authdata: Vec::new(),
            ticket,
            second_ticket: CountedOctetString::default()
        };
    }

    pub fn set_authdata(&mut self, authdata: Vec<AuthData>) {
        return self.authdata = authdata;
    }

    pub fn set_addrs(&mut self, addrs: Vec<Address>) {
        return self.addrs = addrs;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.client.to_bytes();
        bytes.append(&mut self.server.to_bytes());
        bytes.append(&mut self.key.to_bytes());
        bytes.append(&mut self.time.to_bytes());
        bytes.push(self.is_skey);
        bytes.append(&mut self.tktflags.to_be_bytes().to_vec());

        let num_address = self.addrs.len() as u32;

        bytes.append(&mut num_address.to_be_bytes().to_vec());

        for addrs in self.addrs.iter() {
            bytes.append(&mut addrs.to_bytes());
        }

        let num_authdata = self.authdata.len() as u32;

        bytes.append(&mut num_authdata.to_be_bytes().to_vec());

        for authdata in self.authdata.iter() {
            bytes.append(&mut authdata.to_bytes());
        }

        bytes.append(&mut self.ticket.to_bytes());
        bytes.append(&mut self.second_ticket.to_bytes());

        return bytes;
    }

}
