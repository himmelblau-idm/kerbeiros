use crate::KeyBlock;
use himmelblau_kerberos_asn1::EncryptionKey;

pub fn encryption_key_to_keyblock(encryption_key: EncryptionKey) -> KeyBlock {
    return KeyBlock::new(
        encryption_key.keytype as u16,
        encryption_key.keyvalue,
    );
}

pub fn keyblock_to_encryption_key(key_block: KeyBlock) -> EncryptionKey {
    return EncryptionKey::new(key_block.keytype as i32, key_block.keyvalue);
}

#[cfg(test)]
mod test {
    use super::*;
    use himmelblau_kerberos_constants::etypes::*;

    #[test]
    fn test_encryption_key_to_key_block() {
        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let keyblock = KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        assert_eq!(keyblock, encryption_key_to_keyblock(encryption_key));
    }

    #[test]
    fn test_key_block_to_encryption() {
        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        let keyblock = KeyBlock::new(
            AES256_CTS_HMAC_SHA1_96 as u16,
            vec![
                0x01, 0x27, 0x59, 0x90, 0x9b, 0x2a, 0xbf, 0x45, 0xbc, 0x36,
                0x95, 0x7c, 0x32, 0xc9, 0x16, 0xe6, 0xde, 0xbe, 0x82, 0xfd,
                0x9d, 0x64, 0xcf, 0x28, 0x1b, 0x23, 0xea, 0x73, 0xfc, 0x91,
                0xd4, 0xc2,
            ],
        );

        assert_eq!(encryption_key, keyblock_to_encryption_key(keyblock));
    }
}
