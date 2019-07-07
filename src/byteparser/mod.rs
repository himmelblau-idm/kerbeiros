
pub fn u16_array_to_le_bytes(u16_array: &[u16]) -> Vec<u8> {
    let mut u8_vec : Vec<u8> = Vec::with_capacity(u16_array.len() * 2);

    for u16_item in u16_array.iter() {
        let u8_min = *u16_item as u8;
        let u8_max = (*u16_item >> 8) as u8;

        u8_vec.push(u8_min);
        u8_vec.push(u8_max);
    }

    return u8_vec;
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_u16_array_to_le_bytes() {
        assert_eq!(vec![0,0], u16_array_to_le_bytes(&[0]));
        assert_eq!(vec![1,0], u16_array_to_le_bytes(&[1]));
        assert_eq!(vec![9,0,8,0,7,0,6,0], u16_array_to_le_bytes(&[9,8,7,6]));
        assert_eq!(vec![0x15,0x03], u16_array_to_le_bytes(&[789]));
        assert_eq!(vec![0x00,0x01], u16_array_to_le_bytes(&[256]));
        assert_eq!(vec![0xd2,0x04, 0xa5, 0x03, 0xbe, 0x6c], u16_array_to_le_bytes(&[1234, 933, 27838]));
    }
}