use ascii::AsciiString;
pub type TGT = Ticket;

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    realm: AsciiString,
    sname: AsciiString,
    enc_part: EncryptedData
}

#[derive(Debug, Clone, PartialEq)]
struct EncryptedData {
    etype: i32,
    cipher: Vec<u8>
}