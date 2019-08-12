//! Kerberos client
//! 
//! # Terminology
//! * KDC (Key Distribution Center): Service that distributes the tickets. The host that provides this server is also called KDC.
//! 


mod structs;
mod byteparser;
mod crypter;
mod transporter;
pub mod requesters;

pub mod error;
pub use error::*;

pub mod messages;
pub use messages::*;

pub mod constants;
pub use constants::*;

pub mod credential;
pub use credential::*;

pub mod key;
pub use key::*;

pub mod utils;
pub use utils::*;
