use crate::types::{KerberosTime, Times};
use chrono::{TimeZone, Utc};

pub struct TimesMapper {}

impl TimesMapper {
    pub fn authtime_starttime_endtime_renew_till_to_times(
        authtime: &KerberosTime,
        starttime: Option<&KerberosTime>,
        endtime: &KerberosTime,
        renew_till: Option<&KerberosTime>,
    ) -> Times {
        let authtime_timestamp = authtime.timestamp() as u32;
        let endtime_timestamp = endtime.timestamp() as u32;
        let starttime_timestamp;
        let renew_till_timestamp;

        if let Some(starttime) = starttime {
            starttime_timestamp = starttime.timestamp() as u32;
        } else {
            starttime_timestamp = authtime_timestamp;
        }

        if let Some(renew_till) = renew_till {
            renew_till_timestamp = renew_till.timestamp() as u32;
        } else {
            renew_till_timestamp = 0
        }

        return Times::new(
            authtime_timestamp,
            starttime_timestamp,
            endtime_timestamp,
            renew_till_timestamp,
        );
    }

    pub fn times_to_authtime_starttime_endtime_renew_till(
        times: &Times,
    ) -> (
        KerberosTime,
        Option<KerberosTime>,
        KerberosTime,
        Option<KerberosTime>,
    ) {
        let authtime = Utc.timestamp(times.authtime() as i64, 0);

        let starttime;
        if times.authtime() == times.starttime() {
            starttime = None;
        } else {
            starttime = Some(Utc.timestamp(times.starttime() as i64, 0));
        }

        let endtime = Utc.timestamp(times.endtime() as i64, 0);

        let renew_till;
        if times.renew_till() == 0 {
            renew_till = None;
        } else {
            renew_till = Some(Utc.timestamp(times.renew_till() as i64, 0));
        }

        return (authtime, starttime, endtime, renew_till);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn authtime_starttime_endtime_renew_till_to_times() {
        let authtime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let starttime = Utc.ymd(2019, 4, 19).and_hms(06, 00, 31);
        let endtime = Utc.ymd(2019, 4, 20).and_hms(16, 00, 31);
        let renew_till = Utc.ymd(2019, 4, 25).and_hms(06, 00, 31);

        let time = Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        assert_eq!(
            time,
            TimesMapper::authtime_starttime_endtime_renew_till_to_times(
                &authtime,
                Some(&starttime),
                &endtime,
                Some(&renew_till)
            )
        );
    }

    #[test]
    fn authtime_endtime_to_times() {
        let authtime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let endtime = Utc.ymd(2019, 4, 20).and_hms(16, 00, 31);

        let time = Times::new(
            authtime.timestamp() as u32,
            authtime.timestamp() as u32,
            endtime.timestamp() as u32,
            0,
        );

        assert_eq!(
            time,
            TimesMapper::authtime_starttime_endtime_renew_till_to_times(
                &authtime, None, &endtime, None
            )
        );
    }

    #[test]
    fn test_times_to_authtime_starttime_endtime_renew_till() {
        let authtime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let starttime = Utc.ymd(2019, 4, 19).and_hms(06, 00, 31);
        let endtime = Utc.ymd(2019, 4, 20).and_hms(16, 00, 31);
        let renew_till = Utc.ymd(2019, 4, 25).and_hms(06, 00, 31);

        let time = Times::new(
            authtime.timestamp() as u32,
            starttime.timestamp() as u32,
            endtime.timestamp() as u32,
            renew_till.timestamp() as u32,
        );

        assert_eq!(
            (authtime, Some(starttime), endtime, Some(renew_till)),
            TimesMapper::times_to_authtime_starttime_endtime_renew_till(&time)
        );
    }

    #[test]
    fn test_times_to_authtime_endtime() {
        let authtime = Utc.ymd(2019, 4, 18).and_hms(06, 00, 31);
        let endtime = Utc.ymd(2019, 4, 20).and_hms(16, 00, 31);

        let time = Times::new(
            authtime.timestamp() as u32,
            authtime.timestamp() as u32,
            endtime.timestamp() as u32,
            0,
        );

        assert_eq!(
            (authtime, None, endtime, None),
            TimesMapper::times_to_authtime_starttime_endtime_renew_till(&time)
        );
    }
}
