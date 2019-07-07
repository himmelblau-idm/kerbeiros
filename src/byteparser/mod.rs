
pub fn u32_to_be_bytes(u: u32) -> [u8;4] {
    return [
        (u >> 24) as u8,
        (u >> 16) as u8,
        (u >> 8) as u8,
        u as u8
    ];
}

pub fn u32_to_le_bytes(u: u32) -> [u8;4] {
    return [
        u as u8,
        (u >> 8) as u8,
        (u >> 16) as u8,
        (u >> 24) as u8
    ];
}

pub fn le_bytes_to_u32(b: &[u8;4]) -> u32 {
    let mut x =  b[3] as u32;
    x <<= 8;
    x += b[2] as u32;
    x <<= 8;
    x += b[1] as u32;
    x <<= 8;
    x += b[0] as u32;
    return x;
}

pub fn be_bytes_to_u32(b: &[u8;4]) -> u32 {
    let mut x =  b[0] as u32;
    x <<= 8;
    x += b[1] as u32;
    x <<= 8;
    x += b[2] as u32;
    x <<= 8;
    x += b[3] as u32;
    return x;
}

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
    fn test_u32_to_le_bytes() {
        assert_eq!([0x00, 0x00, 0x00, 0x00], u32_to_le_bytes(0));
        assert_eq!([0xff, 0xff, 0xff, 0xff], u32_to_le_bytes(0xffffffff));
        assert_eq!([0x12, 0x34, 0x56, 0x78], u32_to_le_bytes(0x78563412));
        assert_eq!([0x78, 0x56, 0x34, 0x12], u32_to_le_bytes(0x12345678));
        assert_eq!([0x01, 0x00, 0x00, 0x00], u32_to_le_bytes(0x1));
        assert_eq!([0x00, 0x01, 0x00, 0x00], u32_to_le_bytes(0x100));
        assert_eq!([0x00, 0x00, 0x01, 0x00], u32_to_le_bytes(0x10000));
        assert_eq!([0x00, 0x00, 0x00, 0x01], u32_to_le_bytes(0x1000000));
    }

    #[test]
    fn test_u32_to_be_bytes() {
        assert_eq!([0x00, 0x00, 0x00, 0x00], u32_to_be_bytes(0));
        assert_eq!([0xff, 0xff, 0xff, 0xff], u32_to_be_bytes(0xffffffff));
        assert_eq!([0x78, 0x56, 0x34, 0x12], u32_to_be_bytes(0x78563412));
        assert_eq!([0x12, 0x34, 0x56, 0x78], u32_to_be_bytes(0x12345678));
        assert_eq!([0x00, 0x00, 0x00, 0x01], u32_to_be_bytes(0x1));
        assert_eq!([0x00, 0x00, 0x01, 0x00], u32_to_be_bytes(0x100));
        assert_eq!([0x00, 0x01, 0x00, 0x00], u32_to_be_bytes(0x10000));
        assert_eq!([0x01, 0x00, 0x00, 0x00], u32_to_be_bytes(0x1000000));
    }

    #[test]
    fn test_le_bytes_to_u32() {
        assert_eq!(0x0, le_bytes_to_u32(&[0x00, 0x00, 0x00, 0x00]));
        assert_eq!(0xffffffff, le_bytes_to_u32(&[0xff, 0xff, 0xff, 0xff]));
        assert_eq!(0x78563412, le_bytes_to_u32(&[0x12, 0x34, 0x56, 0x78]));
        assert_eq!(0x12345678, le_bytes_to_u32(&[0x78, 0x56, 0x34, 0x12]));
        assert_eq!(0x1, le_bytes_to_u32(&[0x01, 0x00, 0x00, 0x00]));
        assert_eq!(0x100, le_bytes_to_u32(&[0x00, 0x01, 0x00, 0x00]));
        assert_eq!(0x10000, le_bytes_to_u32(&[0x00, 0x00, 0x01, 0x00]));
        assert_eq!(0x1000000, le_bytes_to_u32(&[0x00, 0x00, 0x00, 0x01]));
    }

    #[test]
    fn test_be_bytes_to_u32() {
        assert_eq!(0x0, be_bytes_to_u32(&[0x00, 0x00, 0x00, 0x00]));
        assert_eq!(0xffffffff, be_bytes_to_u32(&[0xff, 0xff, 0xff, 0xff]));
        assert_eq!(0x78563412, be_bytes_to_u32(&[0x78, 0x56, 0x34, 0x12]));
        assert_eq!(0x12345678, be_bytes_to_u32(&[0x12, 0x34, 0x56, 0x78]));
        assert_eq!(0x1, be_bytes_to_u32(&[0x00, 0x00, 0x00, 0x01]));
        assert_eq!(0x100, be_bytes_to_u32(&[0x00, 0x00, 0x01, 0x00]));
        assert_eq!(0x10000, be_bytes_to_u32(&[0x00, 0x01, 0x00, 0x00]));
        assert_eq!(0x1000000, be_bytes_to_u32(&[0x01, 0x00, 0x00, 0x00]));
    }

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