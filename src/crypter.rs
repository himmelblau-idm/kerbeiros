pub use super::cryptography::*;

pub fn encrypt_timestamp_rc4_hmac_md5(key: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let preamble = random_bytes(8);
    return _encrypt_timestamp_rc4_hmac_md5(key, timestamp, &preamble)
}

fn _encrypt_timestamp_rc4_hmac_md5(key: &[u8], timestamp: &[u8], preamble: &[u8]) -> Vec<u8> {
    let mut plaintext : Vec<u8> = Vec::new();
    plaintext.append(&mut preamble.to_vec());
    plaintext.append(&mut timestamp.to_vec());

    let ki = hmac_md5(key, &[1, 0, 0 ,0]);
    let mut cksum = hmac_md5(&ki, &plaintext);
    let ke = hmac_md5(&ki, &cksum);
    let mut enc = rc4_encrypt(&ke, &plaintext);

    cksum.append(&mut enc);

    return cksum;
}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::structs_asn1::PaEncTsEnc;
    use asn1::*;
    use chrono::prelude::*;

    #[test]
    fn test_encrypt_timestamp_rc4_hmac_md5() {
        let ntlm = ntlm_hash("test");
        let timestamp = PaEncTsEnc::from_datetime(Utc.ymd(2019, 6, 4).and_hms_micro(06, 13, 52, 016747)).unwrap();
        let timestamp_raw = timestamp.asn1_type().encode().unwrap();
        let preamble : [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

        let encrypted = _encrypt_timestamp_rc4_hmac_md5(&ntlm, &timestamp_raw, &preamble);

        assert_eq!(vec![0x8f, 0x24, 0x62, 0xd7, 0x70, 0xa7, 0xce, 0x9e, 
                        0x5b, 0x5e, 0xe6, 0x35, 0xd8, 0xbc, 0x54, 0x9a,
                        0x83, 0xb0, 0x93, 0xcf, 0xe2, 0x6b, 0x55, 0x25,
                        0xb7, 0x83, 0x33, 0x89, 0x35, 0xd1, 0xa9, 0xf2, 
                        0x8d, 0x48, 0xde, 0x78, 0xfe, 0x40, 0xf1, 0x22, 
                        0xb2, 0xec, 0xe5, 0x9a, 0x6f, 0x43, 0xfb, 0x14, 
                        0xaa, 0x03, 0x22], encrypted);

    }


}