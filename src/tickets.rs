use ascii::AsciiString;
pub type TGT = Ticket;

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    realm: AsciiString,
    sname: String,
    enc_part: Vec<u8>

}