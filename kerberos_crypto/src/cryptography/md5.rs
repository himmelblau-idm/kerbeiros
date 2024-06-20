use digest::Digest;
use md5::Md5;

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut md5 = Md5::new();
    md5.update(bytes);
    md5.finalize().to_vec()
}
