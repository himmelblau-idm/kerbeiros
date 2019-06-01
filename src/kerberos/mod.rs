mod structs;

mod client;
mod request;
mod error;

use error::KerberosResult;
pub use client::KerberosClient;
