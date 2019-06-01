use super::super::error::*;
use super::kerberostime::KerberosTime;
use super::int32::Int32;
use super::realm::Realm;
use super::principalname::PrincipalName;
use super::kerberosstring::KerberosString;
use super::microseconds::Microseconds;

pub struct KrbError {
    pvno: i8,
    msg_type: i8,
    ctime: Option<KerberosTime>,
    cusec: Option<Microseconds>,
    stime: KerberosTime,
    susec: Microseconds,
    error_code: Int32,
    crealm: Option<Realm>,
    cname: Option<PrincipalName>,
    realm: Option<Realm>,
    sname: PrincipalName,
    e_text: Option<KerberosString>,
    e_data: Option<Vec<u8>>
}

impl KrbError {

    pub fn parse(raw: &Vec<u8>) -> KerberosResult<KrbError> {
        unimplemented!()
    }

}
