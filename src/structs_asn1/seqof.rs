use asn1::*;
use std::ops::{Deref, DerefMut};
use crate::error::*;


hay que hacer un puñetero template para los seqof, y también para los NoAsn1 y Asn1...

#[derive(Debug, Clone, PartialEq)]
pub struct SeqOf<Subtype> {
    entries: Vec<Subtype>
}

impl Deref for SeqOf<Subtype, Tasn1> {
    type Target = Vec<Subtype>;
    fn deref(&self) -> &Vec<Subtype> {
        &self.entries
    }
}

impl DerefMut for SeqOf<Subtype, Tasn1> {
    fn deref_mut(&mut self) -> &mut Vec<Subtype> {
        &mut self.entries
    }
}

impl SeqOf<Subtype, Tasn1> {

    pub fn new() -> Self {
        return Self::new_empty();
    }

    fn new_empty() -> Self {
        return Self{ entries: Vec::new() };
    }

    pub fn asn1_type(&self) -> Tasn1 {
        return Tasn1::new(self);
    }

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<Self> {
        let mut seq_of_padata_asn1 = Tasn1::new_empty();
        seq_of_padata_asn1.decode(raw)?;
        return Ok(seq_of_padata_asn1.no_asn1_type().unwrap());
    }

}


pub struct SeqOfAsn1<SubtypeAsn1, TnoAsn1>  {
    subtype: SequenceOf<SubtypeAsn1>
}

impl SeqOfAsn1<SubtypeAsn1, TnoAsn1> {

    fn new(seq_of_entries: &TnoAsn1) -> Self {
        let mut seq_entries_asn1 = Self::new_empty();

        seq_entries_asn1._set_asn1_values(seq_of_entries);
        return seq_entries_asn1;
    }

    fn new_empty() -> Self {
        return Self{
            subtype: SequenceOf::new()
        };
    }

    fn _set_asn1_values(&mut self, seq_of_entries: &TnoAsn1) {
        for padata in seq_of_entries.iter() {
            self.subtype.push(padata.asn1_type());
        }
    }

    pub fn no_asn1_type(&self) -> KerberosResult<TnoAsn1> {
        let mut seq_of = SeqOf::new_empty();
        for entry_asn1 in self.subtype.iter() {
            seq_of.push(entry_asn1.no_asn1_type()?);
        }

        return Ok(seq_of);
    }
}

impl Asn1Object for SeqOfAsn1<SubtypeAsn1, TnoAsn1> {

    fn tag(&self) -> Tag {
        return self.subtype.tag();
    }

    fn encode_value(&self) -> Result<Vec<u8>, Asn1Error> {
        return self.subtype.encode_value();
    }

    fn decode_value(&mut self, raw: &[u8]) -> Result<(), Asn1Error> {
        return self.subtype.decode_value(raw);
    }

    fn unset_value(&mut self) {
        return self.subtype.unset_value();
    }
}


impl Asn1Tagged for SeqOfAsn1<SubtypeAsn1, TnoAsn1> {
    fn type_tag() -> Tag {
        return SequenceOf::<SubtypeAsn1>::type_tag();
    }
}

impl Asn1InstanciableObject for SeqOfAsn1<SubtypeAsn1, TnoAsn1> {
    fn new_default() -> Self {
        return Self::new_empty();
    }
}
