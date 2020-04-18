//! Error codes retrieved by [`KrbError`](../../messages/struct.KrbError.html).

pub const KDC_ERR_NONE: i32 = 0;
pub const KDC_ERR_NAME_EXP: i32 = 1;
pub const KDC_ERR_SERVICE_EXP: i32 = 2;
pub const KDC_ERR_BAD_PVNO: i32 = 3;
pub const KDC_ERR_C_OLD_MAST_KVNO: i32 = 4;
pub const KDC_ERR_S_OLD_MAST_KVNO: i32 = 5;
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
pub const KDC_ERR_NULL_KEY: i32 = 9;
pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10;
pub const KDC_ERR_NEVER_VALID: i32 = 11;
pub const KDC_ERR_POLICY: i32 = 12;
pub const KDC_ERR_BADOPTION: i32 = 13;
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;
pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;
pub const KDC_ERR_TRTYPE_NOSUPP: i32 = 17;
pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
pub const KDC_ERR_SERVICE_REVOKED: i32 = 19;
pub const KDC_ERR_TGT_REVOKED: i32 = 20;
pub const KDC_ERR_CLIENT_NOTYET: i32 = 21;
pub const KDC_ERR_SERVICE_NOTYET: i32 = 22;
pub const KDC_ERR_KEY_EXPIRED: i32 = 23;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;
pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 = 28;
pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
pub const KRB_AP_ERR_REPEAT: i32 = 34;
pub const KRB_AP_ERR_NOT_US: i32 = 35;
pub const KRB_AP_ERR_BADMATCH: i32 = 36;
pub const KRB_AP_ERR_SKEW: i32 = 37;
pub const KRB_AP_ERR_BADADDR: i32 = 38;
pub const KRB_AP_ERR_BADVERSION: i32 = 39;
pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
pub const KRB_AP_ERR_MODIFIED: i32 = 41;
pub const KRB_AP_ERR_BADORDER: i32 = 42;
pub const KRB_AP_ERR_BADKEYVER: i32 = 44;
pub const KRB_AP_ERR_NOKEY: i32 = 45;
pub const KRB_AP_ERR_MUT_FAIL: i32 = 46;
pub const KRB_AP_ERR_BADDIRECTION: i32 = 47;
pub const KRB_AP_ERR_METHOD: i32 = 48;
pub const KRB_AP_ERR_BADSEQ: i32 = 49;
pub const KRB_AP_ERR_INAPP_CKSUM: i32 = 50;
pub const KRB_AP_PATH_NOT_ACCEPTED: i32 = 51;
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
pub const KRB_ERR_GENERIC: i32 = 60;
pub const KRB_ERR_FIELD_TOOLONG: i32 = 61;
pub const KDC_ERROR_CLIENT_NOT_TRUSTED: i32 = 62;
pub const KDC_ERROR_KDC_NOT_TRUSTED: i32 = 63;
pub const KDC_ERROR_INVALID_SIG: i32 = 64;
pub const KDC_ERR_KEY_TOO_WEAK: i32 = 65;
pub const KDC_ERR_CERTIFICATE_MISMATCH: i32 = 66;
pub const KRB_AP_ERR_NO_TGT: i32 = 67;
pub const KDC_ERR_WRONG_REALM: i32 = 68;
pub const KRB_AP_ERR_USER_TO_USER_REQUIRED: i32 = 69;
pub const KDC_ERR_CANT_VERIFY_CERTIFICATE: i32 = 70;
pub const KDC_ERR_INVALID_CERTIFICATE: i32 = 71;
pub const KDC_ERR_REVOKED_CERTIFICATE: i32 = 72;
pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN: i32 = 73;
pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: i32 = 74;
pub const KDC_ERR_CLIENT_NAME_MISMATCH: i32 = 75;
pub const KDC_ERR_KDC_NAME_MISMATCH: i32 = 76;

pub fn error_code_to_string(error_code: i32) -> String {
    match error_code {
        0 => "KDC_ERR_NONE".to_string(),
        1 => "KDC_ERR_NAME_EXP".to_string(),
        2 => "KDC_ERR_SERVICE_EXP".to_string(),
        3 => "KDC_ERR_BAD_PVNO".to_string(),
        4 => "KDC_ERR_C_OLD_MAST_KVNO".to_string(),
        5 => "KDC_ERR_S_OLD_MAST_KVNO".to_string(),
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN".to_string(),
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN".to_string(),
        8 => "KDC_ERR_PRINCIPAL_NOT_UNIQUE".to_string(),
        9 => "KDC_ERR_NULL_KEY".to_string(),
        10 => "KDC_ERR_CANNOT_POSTDATE".to_string(),
        11 => "KDC_ERR_NEVER_VALID".to_string(),
        12 => "KDC_ERR_POLICY".to_string(),
        13 => "KDC_ERR_BADOPTION".to_string(),
        14 => "KDC_ERR_ETYPE_NOSUPP".to_string(),
        15 => "KDC_ERR_SUMTYPE_NOSUPP".to_string(),
        16 => "KDC_ERR_PADATA_TYPE_NOSUPP".to_string(),
        17 => "KDC_ERR_TRTYPE_NOSUPP".to_string(),
        18 => "KDC_ERR_CLIENT_REVOKED".to_string(),
        19 => "KDC_ERR_SERVICE_REVOKED".to_string(),
        20 => "KDC_ERR_TGT_REVOKED".to_string(),
        21 => "KDC_ERR_CLIENT_NOTYET".to_string(),
        22 => "KDC_ERR_SERVICE_NOTYET".to_string(),
        23 => "KDC_ERR_KEY_EXPIRED".to_string(),
        24 => "KDC_ERR_PREAUTH_FAILED".to_string(),
        25 => "KDC_ERR_PREAUTH_REQUIRED".to_string(),
        26 => "KDC_ERR_SERVER_NOMATCH".to_string(),
        27 => "KDC_ERR_MUST_USE_USER2USER".to_string(),
        28 => "KDC_ERR_PATH_NOT_ACCEPTED".to_string(),
        29 => "KDC_ERR_SVC_UNAVAILABLE".to_string(),
        31 => "KRB_AP_ERR_BAD_INTEGRITY".to_string(),
        32 => "KRB_AP_ERR_TKT_EXPIRED".to_string(),
        33 => "KRB_AP_ERR_TKT_NYV".to_string(),
        34 => "KRB_AP_ERR_REPEAT".to_string(),
        35 => "KRB_AP_ERR_NOT_US".to_string(),
        36 => "KRB_AP_ERR_BADMATCH".to_string(),
        37 => "KRB_AP_ERR_SKEW".to_string(),
        38 => "KRB_AP_ERR_BADADDR".to_string(),
        39 => "KRB_AP_ERR_BADVERSION".to_string(),
        40 => "KRB_AP_ERR_MSG_TYPE".to_string(),
        41 => "KRB_AP_ERR_MODIFIED".to_string(),
        42 => "KRB_AP_ERR_BADORDER".to_string(),
        44 => "KRB_AP_ERR_BADKEYVER".to_string(),
        45 => "KRB_AP_ERR_NOKEY".to_string(),
        46 => "KRB_AP_ERR_MUT_FAIL".to_string(),
        47 => "KRB_AP_ERR_BADDIRECTION".to_string(),
        48 => "KRB_AP_ERR_METHOD".to_string(),
        49 => "KRB_AP_ERR_BADSEQ".to_string(),
        50 => "KRB_AP_ERR_INAPP_CKSUM".to_string(),
        51 => "KRB_AP_PATH_NOT_ACCEPTED".to_string(),
        52 => "KRB_ERR_RESPONSE_TOO_BIG".to_string(),
        60 => "KRB_ERR_GENERIC".to_string(),
        61 => "KRB_ERR_FIELD_TOOLONG".to_string(),
        62 => "KDC_ERROR_CLIENT_NOT_TRUSTED".to_string(),
        63 => "KDC_ERROR_KDC_NOT_TRUSTED".to_string(),
        64 => "KDC_ERROR_INVALID_SIG".to_string(),
        65 => "KDC_ERR_KEY_TOO_WEAK".to_string(),
        66 => "KDC_ERR_CERTIFICATE_MISMATCH".to_string(),
        67 => "KRB_AP_ERR_NO_TGT".to_string(),
        68 => "KDC_ERR_WRONG_REALM".to_string(),
        69 => "KRB_AP_ERR_USER_TO_USER_REQUIRED".to_string(),
        70 => "KDC_ERR_CANT_VERIFY_CERTIFICATE".to_string(),
        71 => "KDC_ERR_INVALID_CERTIFICATE".to_string(),
        72 => "KDC_ERR_REVOKED_CERTIFICATE".to_string(),
        73 => "KDC_ERR_REVOCATION_STATUS_UNKNOWN".to_string(),
        74 => "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE".to_string(),
        75 => "KDC_ERR_CLIENT_NAME_MISMATCH".to_string(),
        76 => "KDC_ERR_KDC_NAME_MISMATCH".to_string(),
        _ => "".to_string(),
    }
}