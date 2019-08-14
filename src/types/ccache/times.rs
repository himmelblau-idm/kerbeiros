
/// Holds the differents timestamps handled by Kerberos.
#[derive(Debug, PartialEq, Clone)]
pub struct Times {
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32
}

impl Times {

    pub fn new(authtime: u32, starttime: u32, endtime: u32, renew_till: u32) -> Self {
        return Self{
            authtime,
            starttime,
            endtime,
            renew_till
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.authtime.to_be_bytes().to_vec();
        bytes.append(&mut self.starttime.to_be_bytes().to_vec());
        bytes.append(&mut self.endtime.to_be_bytes().to_vec());
        bytes.append(&mut self.renew_till.to_be_bytes().to_vec());

        return bytes;
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn times_to_bytes() {
        assert_eq!(
            vec![
                0x5d, 0x22, 0x00, 0x65,
                0x5d, 0x22, 0x00, 0x65,
                0x5d, 0x22, 0x8d, 0x05,
                0x5d, 0x23, 0x51, 0xe2
            ],
            Times::new(
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 7).and_hms(14, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(0, 23, 33).timestamp() as u32,
                Utc.ymd(2019, 7, 8).and_hms(14, 23, 30).timestamp() as u32,
            ).to_bytes()
        )
    }


}