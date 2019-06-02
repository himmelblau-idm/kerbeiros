use super::super::padata::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Edata {
    Raw(Vec<u8>),
    MethodData(MethodData)
}