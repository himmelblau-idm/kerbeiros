use super::super::padata::*;

/// Includes additional information for [KrbError](./struct.KrbError.html).
#[derive(Debug, Clone, PartialEq)]
pub enum Edata {
    Raw(Vec<u8>),
    MethodData(MethodData)
}