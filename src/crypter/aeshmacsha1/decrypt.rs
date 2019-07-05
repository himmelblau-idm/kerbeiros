use super::super::cryptography::*;
use super::super::super::error::*;
use super::nfold_dk::*;
use crate::byteparser;

pub fn aes_hmac_sh1_decrypt(key: &[u8], key_usage: i32, ciphertext: &[u8], aes_sizes: &AesSizes) -> KerberosResult<Vec<u8>> {
    let key_usage_bytes = byteparser::i32_to_be_bytes(key_usage);

    let mut ki_seed = key_usage_bytes.to_vec();
    ki_seed.push(0x55);

    let mut ke_seed = key_usage_bytes.to_vec();
    ke_seed.push(0xaa);
    
    let ki = dk(key, &ki_seed, aes_sizes);
    let ke = dk(key, &ke_seed, aes_sizes);

    if ciphertext.len() < aes_sizes.block_size() + aes_sizes.mac_size() {
        return Err(KerberosCryptographyErrorKind::DecryptionError("Ciphertext too short".to_string()))?;
    }

    let ciphertext_end_index = ciphertext.len() - aes_sizes.mac_size();
    let pure_ciphertext = &ciphertext[0..ciphertext_end_index];
    let mac = &ciphertext[ciphertext_end_index..];

    let plaintext = basic_decrypt(&ke, &pure_ciphertext, aes_sizes)?;

    let calculated_mac = hmac_sha1(&ki, &plaintext);

    if calculated_mac[..aes_sizes.mac_size()] != mac[..] {
        return Err(KerberosCryptographyErrorKind::DecryptionError("Hmac integrity failure".to_string()))?;
    }

    return Ok(plaintext[aes_sizes.block_size()..].to_vec());
}


fn basic_decrypt(key: &[u8], ciphertext: &[u8], aes_sizes: &AesSizes) -> KerberosResult<Vec<u8>> {
    if ciphertext.len() == aes_sizes.block_size() {
        let plaintext = decrypt_aes_ecb(key, ciphertext, aes_sizes);
        return Ok(plaintext);
    }

    let blocks = divide_in_n_bytes_blocks(&ciphertext, aes_sizes.block_size());

    let second_last_index = blocks.len() - 2;

    let (mut plaintext, previous_block) = decrypt_several_blocks_xor_aes_ecb(
        key, &blocks[0..second_last_index], aes_sizes
    );

    let mut last_plaintext = decrypt_last_two_blocks(
        key, &blocks[second_last_index..], &previous_block, aes_sizes
    );
    
    plaintext.append(&mut last_plaintext);
    
    return Ok(plaintext);
}


fn divide_in_n_bytes_blocks(v: &[u8], nbytes: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    let mut i = 0;
    while i < v.len() {
        let mut j = i + nbytes;
        if j > v.len() {
            j = v.len();
        }

        blocks.push(v[i..j].to_vec());
        i += nbytes;
    }

    return blocks;
}

fn decrypt_several_blocks_xor_aes_ecb(key: &[u8], blocks: &[Vec<u8>], aes_sizes: &AesSizes) -> (Vec<u8>, Vec<u8>) {
    let mut plaintext: Vec<u8> = Vec::new();
    let mut previous_block = vec![0; aes_sizes.block_size()];

    for block in blocks.iter() {
        let mut block_plaintext = decrypt_aes_ecb(key, block, aes_sizes);
        block_plaintext = xorbytes(&block_plaintext, &previous_block);

        plaintext.append(&mut block_plaintext);
        previous_block = block.clone();
    }

    return (plaintext, previous_block);
}

fn decrypt_last_two_blocks(key: &[u8], blocks: &[Vec<u8>], previous_block: &[u8], aes_sizes: &AesSizes) -> Vec<u8> {
    let second_last_block_plaintext =  decrypt_aes_ecb(key, &blocks[0], aes_sizes);

    let last_block_length =  blocks[1].len();
    let mut last_block = blocks[1].to_vec();

    let mut last_plaintext = xorbytes(
        &second_last_block_plaintext[0..last_block_length], 
        &last_block
    );

    let mut omitted = second_last_block_plaintext[last_block_length..].to_vec();    

    last_block.append(&mut omitted);

    let last_block_plaintext = decrypt_aes_ecb(key, &last_block, aes_sizes);

    let mut plaintext = Vec::new();
    plaintext.append(&mut xorbytes(&last_block_plaintext, &previous_block));
    plaintext.append(&mut last_plaintext);

    return plaintext;
}
