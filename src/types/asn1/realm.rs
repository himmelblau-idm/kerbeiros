pub use super::basics::kerberos_string::*;

/// (*Realm*) Kerberos realm.
pub type Realm = KerberosString;
pub(crate) type RealmAsn1 = KerberosStringAsn1;
