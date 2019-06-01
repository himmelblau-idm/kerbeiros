use super::kerberosflags::{KerberosFlags, KerberosFlagsAsn1};


pub static NO_OPTION: u32 = 0x0;
pub static FORWARDABLE: u32 = 0x40;
pub static FORWARDED: u32 = 0x20;
pub static PROXIABLE: u32 = 0x10;
pub static PROXY: u32 = 0x08;
pub static ALLOW_POSTDATE: u32 = 0x04;
pub static POSTDATED: u32 = 0x02;
pub static RENEWABLE: u32 = 0x8000;
pub static OPT_HARDWARE_AUTH: u32 = 0x1000;
pub static CONSTRAINED_DELEGATION: u32 = 0x0200;
pub static CANONICALIZE: u32 = 0x0100;
pub static REQUEST_ANONYMOUS: u32 = 0x800000;
pub static DISABLE_TRANSITED_CHECK: u32 = 0x20000000;
pub static RENEWABLE_OK: u32 = 0x10000000;
pub static ENC_TKT_IN_SKEY: u32 = 0x08000000;
pub static RENEW: u32 = 0x02000000;
pub static VALIDATE: u32 = 0x01000000;

pub type KdcOptions = KerberosFlags;
pub type KdcOptionsAsn1 = KerberosFlagsAsn1;

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::*;

    #[test]
    fn test_set_option() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(FORWARDABLE);

        assert!(kdc_options.has_flag(FORWARDABLE)); 
    }

    #[test]
    fn test_delete_option() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(PROXIABLE);
        kdc_options.del_flags(PROXIABLE);

        assert!(!kdc_options.has_flag(PROXIABLE)); 
    }

    #[test]
    fn test_set_flags() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);

        assert!(kdc_options.has_flag(FORWARDABLE));
        assert!(kdc_options.has_flag(POSTDATED)); 
    }

    #[test]
    fn test_delete_options() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);
        kdc_options.del_flags(FORWARDABLE | POSTDATED);

        assert!(!kdc_options.has_flag(FORWARDABLE));
        assert!(!kdc_options.has_flag(POSTDATED)); 
    }

    #[test]
    fn test_delete_one_options() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);
        kdc_options.del_flags(FORWARDABLE);

        assert!(!kdc_options.has_flag(FORWARDABLE));
        assert!(kdc_options.has_flag(POSTDATED)); 
    }

    #[test]
    fn test_encode_kdcoptions() {
        let mut kdc_options = KdcOptions::new();
        kdc_options.set_flags(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);
        assert_eq!(vec![0x03, 0x05, 0x0, 0x40, 0x81, 0x00, 0x10],
        kdc_options.asn1_type().encode().unwrap())
    }

}