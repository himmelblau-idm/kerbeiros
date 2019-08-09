//! Preauthentication data types used by Kerberos protocol.
//! 
//! References: 
//! * RFC 4210, Section 7.5.2. 
//! * [MS-KILE], Section 3.1.5.1

pub const PA_TGS_REQ : i32 = 1;
pub const PA_ENC_TIMESTAMP : i32 = 2;
pub const PA_ETYPE_INFO : i32 = 11;
pub const PA_PK_AS_REQ_OLD : i32 = 14;
pub const PA_PK_AS_REP_OLD : i32 = 15;
pub const PA_PK_AS_REQ : i32 = 16;
pub const PA_PK_AS_REP : i32 = 17;
pub const PA_ETYPE_INFO2 : i32 = 19;
pub const PA_PAC_REQUEST : i32 = 128;
pub const PA_SVR_REFERRAL_INFO : i32 = 20;
pub const PA_FX_COOKIE : i32 = 133;
pub const PA_FX_FAST : i32 = 136;
pub const PA_FX_ERROR : i32 = 137;
pub const PA_ENCRYPTED_CHALLENGE : i32 = 138;
pub const PA_SUPPORTED_ENCTYPES : i32 = 165;
pub const PA_PAC_OPTIONS : i32 = 167;