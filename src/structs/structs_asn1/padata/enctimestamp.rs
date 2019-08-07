use red_asn1::*;
use super::super::kerberostime::*;
use super::super::microseconds::*;
use crate::error::Result;


pub struct PaEncTsEnc {
    patimestamp: KerberosTime,
    pausec: Option<Microseconds>
}

impl PaEncTsEnc {

    pub fn new(patimestamp: KerberosTime) -> Self {
        return Self {
            patimestamp,
            pausec: None
        }
    }

    pub fn set_pausec(&mut self, pausec: Microseconds) {
        self.pausec = Some(pausec);
    }

    pub fn from_datetime(datetime: DateTime<Utc>) -> Result<Self> {
        let mut pa_enc_ts_enc = Self::new(datetime);
        pa_enc_ts_enc.set_pausec(Microseconds::new(datetime.timestamp_subsec_micros())?);
        
        return Ok(pa_enc_ts_enc);
    }

    pub fn build(&self) -> Vec<u8> {
        return self.asn1_type().encode().unwrap();
    }

    pub fn asn1_type(&self) -> PaEncTsEncAsn1 {
        return PaEncTsEncAsn1::new(self);
    }

}

#[derive(Sequence)]
pub struct PaEncTsEncAsn1 {
    #[seq_field(context_tag = 0)]
    patimestamp: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 1, optional)]
    pausec: SeqField<MicrosecondsAsn1>
}

impl PaEncTsEncAsn1 {

    fn new(pa_enc_ts_enc: &PaEncTsEnc) -> Self {
        let mut pa_enc_ts_enc_asn1 = Self::default();

        pa_enc_ts_enc_asn1.set_patimestamp(KerberosTimeAsn1::new(pa_enc_ts_enc.patimestamp.clone()));

        if let Some(pausec) = &pa_enc_ts_enc.pausec {
            pa_enc_ts_enc_asn1.set_pausec(pausec.asn1_type());
        }

        return pa_enc_ts_enc_asn1;
    }

    fn default() -> Self {
        return Self {
            patimestamp: SeqField::default(),
            pausec: SeqField::default()
        }
    }

}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn encode_timestamp() {
        let datetime = Utc.ymd(2019, 6, 4).and_hms_micro(05, 22, 12, 143725);

        let pa_enc_ts_enc = PaEncTsEnc::from_datetime(datetime).unwrap();

        assert_eq!(vec![0x30, 0x1a, 
                            0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 
                                0x30, 0x34, 0x30, 0x35, 0x32, 0x32, 0x31, 0x32, 0x5a, 
                            0xa1, 0x05, 0x02, 0x03, 0x02, 0x31, 0x6d],
                pa_enc_ts_enc.asn1_type().encode().unwrap());

    }

}

