use crypto::aes;
use crypto::blockmodes;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::pbkdf2::pbkdf2;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;

const AES_BLOCKSIZE: usize = 16;
const AES_MACSIZE: usize = 12;
const AES_128_SEEDSIZE: usize = 16;
const AES_256_SEEDSIZE: usize = 32;

pub enum AesSizes {
    Aes128,
    Aes256
}

impl AesSizes {
    pub fn seed_size(&self) -> usize {
        match &self {
            AesSizes::Aes128 => {return AES_128_SEEDSIZE},
            AesSizes::Aes256 => {return AES_256_SEEDSIZE}
        }
    }

    pub fn block_size(&self) -> usize {
        return AES_BLOCKSIZE;
    }

    pub fn key_size(&self) -> aes::KeySize {
        match &self {
            AesSizes::Aes128 => {return aes::KeySize::KeySize128},
            AesSizes::Aes256 => {return aes::KeySize::KeySize256}
        }
    }

    pub fn mac_size(&self) -> usize {
        return AES_MACSIZE;
    }
}


pub fn pbkdf2_sha1(key: &[u8], salt: &[u8], seed_size: usize) -> Vec<u8> {
    let iteration_count = 0x1000;
    let mut hmacker = Hmac::new(Sha1::new(), key);
    let mut seed : Vec<u8> = vec![0; seed_size];
    pbkdf2(&mut hmacker, salt, iteration_count, &mut seed);
    return seed;
}


pub fn decrypt_aes_ecb(key: &[u8], ciphertext: &[u8], aes_sizes: &AesSizes) -> Vec<u8> {
    let mut decryptor = aes::ecb_decryptor(aes_sizes.key_size(), key, blockmodes::NoPadding);
    let mut plaintext: Vec<u8> = vec![0; ciphertext.len()];
        decryptor.decrypt(&mut RefReadBuffer::new(ciphertext),
                        &mut RefWriteBuffer::new(&mut plaintext), true).unwrap();
    
    return plaintext;
}


pub fn encrypt_aes_cbc(key: &[u8], plaintext: &[u8], aes_sizes: &AesSizes) -> Vec<u8> {
    let mut encryptor = aes::cbc_encryptor(aes_sizes.key_size(), key, 
            &vec![0; aes_sizes.block_size()], blockmodes::NoPadding);

    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];
    encryptor.encrypt(&mut RefReadBuffer::new(plaintext),
                        &mut RefWriteBuffer::new(&mut ciphertext), true).unwrap();
    
    return ciphertext;
}
