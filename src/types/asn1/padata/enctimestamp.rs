use red_asn1::*;
use super::super::kerberostime::*;
use super::super::microseconds::*;
use chrono::prelude::*;


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

    pub fn build(&self) -> Vec<u8> {
        return PaEncTsEncAsn1::from(self).encode().unwrap();
    }

}

impl From<DateTime<Utc>> for PaEncTsEnc {
    fn from(datetime: DateTime<Utc>) -> Self {
        let mut pa_enc_ts_enc = Self::new(datetime);

        let mut microseconds = datetime.timestamp_subsec_micros();
        if microseconds > MAX_MICROSECONDS {
            microseconds = MAX_MICROSECONDS;
        }

        pa_enc_ts_enc.set_pausec(Microseconds::new(microseconds).unwrap());
        
        return pa_enc_ts_enc;
    }
}


#[derive(Sequence)]
pub(crate) struct PaEncTsEncAsn1 {
    #[seq_field(context_tag = 0)]
    patimestamp: SeqField<KerberosTimeAsn1>,
    #[seq_field(context_tag = 1, optional)]
    pausec: SeqField<MicrosecondsAsn1>
}

impl PaEncTsEncAsn1 {

    fn default() -> Self {
        return Self {
            patimestamp: SeqField::default(),
            pausec: SeqField::default()
        }
    }

}

impl From<&PaEncTsEnc> for PaEncTsEncAsn1 {
    fn from(pa_enc_ts_enc: &PaEncTsEnc) -> Self {
        let mut pa_enc_ts_enc_asn1 = Self::default();

        pa_enc_ts_enc_asn1.set_patimestamp(pa_enc_ts_enc.patimestamp.clone().into());

        if let Some(pausec) = &pa_enc_ts_enc.pausec {
            pa_enc_ts_enc_asn1.set_pausec(pausec.into());
        }

        return pa_enc_ts_enc_asn1;
    }
}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn encode_timestamp() {
        let datetime = Utc.ymd(2019, 6, 4).and_hms_micro(05, 22, 12, 143725);

        let pa_enc_ts_enc = PaEncTsEnc::from(datetime);

        assert_eq!(vec![0x30, 0x1a, 
                            0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x36, 
                                0x30, 0x34, 0x30, 0x35, 0x32, 0x32, 0x31, 0x32, 0x5a, 
                            0xa1, 0x05, 0x02, 0x03, 0x02, 0x31, 0x6d],
                PaEncTsEncAsn1::from(&pa_enc_ts_enc).encode().unwrap());

    }

}

