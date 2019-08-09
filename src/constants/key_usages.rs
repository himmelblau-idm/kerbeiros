//! These constants define the use of keys in Kerberos protocol.
//! 
//! # References
//! * RFC 4210, Section 7.5.1

pub const KEY_USAGE_AS_REQ_TIMESTAMP: i32 = 1;
pub const KEY_USAGE_AS_REP_TICKET: i32 = 2;
pub const KEY_USAGE_AS_REP_ENC_PART: i32 = 3;
pub const KEY_USAGE_TGS_REQ_AUTH_DATA_SESSION_KEY: i32 = 4;
pub const KEY_USAGE_TGS_REQ_AUTH_DATA_AUTHEN_SUBKEY: i32 = 5;
pub const KEY_USAGE_TGS_REQ_AUTHEN_CKSUM: i32 = 6;
pub const KEY_USAGE_TGS_REQ_AUTHEN: i32 = 7;
pub const KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY: i32 = 8;
pub const KEY_USAGE_TGS_REP_ENC_PART_AUTHEN_SUBKEY: i32  = 9;
pub const KEY_USAGE_AP_REQ_AUTHEN_CKSUM: i32 = 10;
pub const KEY_USAGE_AP_REQ_AUTHEN: i32 = 11;
pub const KEY_USAGE_AP_REP_ENC_PART: i32 = 12;
pub const KEY_USAGE_KRB_PRIV_ENC_PART: i32 = 13;
pub const KEY_USAGE_KRB_CRED_ENC_PART: i32 = 14;
pub const KEY_USAGE_KRB_SAFE_CKSUM: i32 = 15;
pub const KEY_USAGE_KERB_NON_KERB_SALT: i32 = 16;
pub const KEY_USAGE_KERB_NON_KERB_CKSUM_SALT: i32 = 17;
