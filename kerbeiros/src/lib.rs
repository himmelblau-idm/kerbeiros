//! Kerberos client
//!
//! # Concepts
//! * KDC (Key Distribution Center): Service that distributes the tickets. The host that provides this server is also called KDC.
//! * TGS (Ticket Granting Server): Ticket used to authenticate the user against a specified service.
//! * TGT (Ticket Granting Ticket): Ticket used to retrieve the TGS's from the KDC.
//!
//! # Examples
//!
//! Asking for a TGT:
//!
//! ```no_run
//! use himmelblau_kerbeiros::*;
//! use ascii::AsciiString;
//! use std::net::*;
//! use himmelblau_kerberos_crypto::Key;
//!
//! // Prepare the arguments
//! let realm = AsciiString::from_ascii("CONTOSO.COM").unwrap();
//! let kdc_address = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
//! let username = AsciiString::from_ascii("Bob").unwrap();
//! let user_key = Key::Secret("S3cr3t".to_string());
//!
//! // Request the TGT
//! let tgt_requester = TgtRequester::new(realm, kdc_address);
//! let credential = tgt_requester.request(&username, Some(&user_key)).unwrap();
//!
//! // Save the ticket into a Windows format file
//! credential.clone().save_into_krb_cred_file("bob_tgt.krb").unwrap();
//!
//! // Save the ticket into a Linux format file
//! credential.save_into_ccache_file("bob_tgt.ccache").unwrap();
//! ```
//!
//! # Kerberos References
//! * [RFC 4120: The Kerberos Network Authentication Service (V5)](https://tools.ietf.org/html/rfc4120)
//! * [\[MS-KILE\]: Kerberos Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile)
//!

mod transporter;

mod error;
pub use error::{Error, Result};

pub mod messages;
pub use messages::*;

pub mod credentials;
pub use credentials::*;

pub mod requesters;
pub use requesters::*;

pub mod utils;
pub use utils::*;

mod mappers;
