//! Types of names used by Kerberos protocol.
//!
//! # References
//! * RFC 4210, Section 6.2.

pub const NT_UNKNOWN: i32 = 0;
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;
pub const NT_SRV_HST: i32 = 3;
pub const NT_SRV_XHST: i32 = 4;
pub const NT_UID: i32 = 5;
pub const NT_X500_PRINCIPAL: i32 = 6;
pub const NT_SMTP_NAME: i32 = 7;
pub const NT_ENTERPRISE: i32 = 10;
