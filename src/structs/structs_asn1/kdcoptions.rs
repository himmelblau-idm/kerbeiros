use super::kerberosflags::{KerberosFlags, KerberosFlagsAsn1};

pub type KdcOptions = KerberosFlags;
pub type KdcOptionsAsn1 = KerberosFlagsAsn1;

#[cfg(test)]
mod tests {
    use super::*;
    use red_asn1::*;
    use crate::constants::kdcoptions::*;

    #[test]
    fn test_set_option() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(FORWARDABLE);

        assert!(kdc_options._has_flag(FORWARDABLE)); 
    }

    #[test]
    fn test_delete_option() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(PROXIABLE);
        kdc_options._del_flags(PROXIABLE);

        assert!(!kdc_options._has_flag(PROXIABLE)); 
    }

    #[test]
    fn test_set_flags() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);

        assert!(kdc_options._has_flag(FORWARDABLE));
        assert!(kdc_options._has_flag(POSTDATED)); 
    }

    #[test]
    fn test_delete_options() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);
        kdc_options._del_flags(FORWARDABLE | POSTDATED);

        assert!(!kdc_options._has_flag(FORWARDABLE));
        assert!(!kdc_options._has_flag(POSTDATED)); 
    }

    #[test]
    fn test_delete_one_options() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(FORWARDABLE | POSTDATED);
        kdc_options._del_flags(FORWARDABLE);

        assert!(!kdc_options._has_flag(FORWARDABLE));
        assert!(kdc_options._has_flag(POSTDATED)); 
    }

    #[test]
    fn test_encode_kdcoptions() {
        let mut kdc_options = KdcOptions::default();
        kdc_options.set_flags(FORWARDABLE | RENEWABLE | CANONICALIZE | RENEWABLE_OK);
        assert_eq!(vec![0x03, 0x05, 0x0, 0x40, 0x81, 0x00, 0x10],
        kdc_options.asn1_type().encode().unwrap())
    }

}