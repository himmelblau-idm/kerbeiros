use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncryptMut;
use aes::cipher::KeyIvInit;
use aes::cipher::KeySizeUser;
use digest::KeyInit;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_MAC_SIZE: usize = 12;
pub const AES128_SEED_SIZE: usize = 16;
pub const AES256_SEED_SIZE: usize = 32;

/// Size of AES-128 key, 16 bytes
pub const AES128_KEY_SIZE: usize = 16;

/// Size of AES-256 key, 32 bytes
pub const AES256_KEY_SIZE: usize = 32;

/// Enum to provide asociated parameters with each size of the AES algorithm
pub enum AesSizes {
    Aes128,
    Aes256,
}

impl AesSizes {
    pub fn seed_size(&self) -> usize {
        match &self {
            AesSizes::Aes128 => return AES128_SEED_SIZE,
            AesSizes::Aes256 => return AES256_SEED_SIZE,
        }
    }

    pub fn block_size(&self) -> usize {
        return AES_BLOCK_SIZE;
    }

    pub fn key_size(&self) -> usize {
        match &self {
            AesSizes::Aes128 => return aes::Aes128::key_size(),
            AesSizes::Aes256 => return aes::Aes256::key_size(),
        }
    }

    pub fn mac_size(&self) -> usize {
        return AES_MAC_SIZE;
    }
}

pub fn pbkdf2_sha1(key: &[u8], salt: &[u8], seed_size: usize) -> Vec<u8> {
    let iteration_count = 0x1000;
    let mut seed: Vec<u8> = vec![0; seed_size];
    pbkdf2_hmac::<Sha1>(key, salt, iteration_count, &mut seed);
    return seed;
}

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;

pub fn decrypt_aes_ecb(
    key: &[u8],
    ciphertext: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    match aes_sizes {
        AesSizes::Aes128 => Aes128EcbDec::new(key.into())
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .unwrap(),
        AesSizes::Aes256 => Aes256EcbDec::new(key.into())
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .unwrap(),
    }
}

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub fn encrypt_aes_cbc(
    key: &[u8],
    plaintext: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let iv = [0; AES_BLOCK_SIZE];
    match aes_sizes {
        AesSizes::Aes128 => Aes128CbcEnc::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
        AesSizes::Aes256 => Aes256CbcEnc::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
    }
}
