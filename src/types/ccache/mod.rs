//! Types used to store Kerberos credentials in a ccache
//!
//! # References
//! * [ccache definition](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
//! * [ccache types definition](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt)

mod header;
pub use header::*;

mod counted_octet_string;
pub use counted_octet_string::*;

mod principal;
pub use principal::*;

mod key_block;
pub use key_block::*;

mod times;
pub use times::*;

mod address;
pub use address::*;

mod auth_data;
pub use auth_data::*;

mod credential;
pub use credential::*;

mod ccache;
pub use ccache::*;
