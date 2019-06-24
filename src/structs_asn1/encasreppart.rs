use asn1::*;
use asn1_derive::*;
use super::encryptionkey::*;
use super::uint32::*;
use super::lastreq::*;
use super::kerberostime::*;
use super::ticketflags::*;
use super::realm::*;
use super::principalname::*;
use super::hostaddress::*;
use super::padata::*;
use super::super::error::*;

#[derive(Debug, PartialEq, Clone)]
pub struct EncAsRepPart {
    key: EncryptionKey,
    last_req: LastReq,
    nonce: UInt32,
    key_expiration: Option<KerberosTime>,
    flags: TicketFlags,
    authtime: KerberosTime,
    starttime: Option<KerberosTime>,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
    srealm: Realm,
    sname: PrincipalName,
    caddr: Option<HostAddresses>,
    encrypted_pa_data: Option<MethodData>
}

impl EncAsRepPart {


    pub fn new(
        key: EncryptionKey, last_req: LastReq, nonce: UInt32, flags: TicketFlags,
        authtime: KerberosTime, endtime: KerberosTime, srealm: Realm, sname: PrincipalName    
    ) -> Self {
        return Self {
            key,
            last_req,
            nonce,
            key_expiration: None,
            flags,
            authtime,
            starttime: None,
            endtime,
            renew_till: None,
            srealm,
            sname,
            caddr: None,
            encrypted_pa_data: None
        };
    }

    pub fn set_key_expiration(&mut self, key_expiration: KerberosTime) {
        self.key_expiration = Some(key_expiration);
    }

    pub fn set_starttime(&mut self, starttime: KerberosTime) {
        self.starttime = Some(starttime);
    }

    pub fn set_renew_till(&mut self, renew_till: KerberosTime) {
        self.renew_till = Some(renew_till);
    }

    pub fn set_caddr(&mut self, caddr: HostAddresses) {
        self.caddr = Some(caddr);
    }

    pub fn set_encrypted_pa_data(&mut self, encrypted_pa_data: MethodData) {
        self.encrypted_pa_data = Some(encrypted_pa_data);
    }

    pub fn parse(raw: &[u8]) -> KerberosResult<Self> {
        let mut enc_as_rep_part_asn1 = EncAsRepPartAsn1::new_empty();
        enc_as_rep_part_asn1.decode(raw)?;
        return Ok(enc_as_rep_part_asn1.no_asn1_type().unwrap());
    }
}

#[derive(Asn1Sequence)]
#[seq(application_tag = 25)]
struct EncAsRepPartAsn1 {
    #[seq_comp(context_tag = 0)]
    key: SeqField<EncryptionKeyAsn1>,
    #[seq_comp(context_tag = 1)]
    last_req: SeqField<LastReqAsn1>,
    #[seq_comp(context_tag = 2)]
    nonce: SeqField<UInt32Asn1>,
    #[seq_comp(context_tag = 3, optional)]
    key_expiration: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 4)]
    flags: SeqField<TicketFlagsAsn1>,
    #[seq_comp(context_tag = 5)]
    authtime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 6, optional)]
    starttime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 7)]
    endtime: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 8, optional)]
    renew_till: SeqField<KerberosTimeAsn1>,
    #[seq_comp(context_tag = 9)]
    srealm: SeqField<RealmAsn1>,
    #[seq_comp(context_tag = 10)]
    sname: SeqField<PrincipalNameAsn1>,
    #[seq_comp(context_tag = 11, optional)]
    caddr: SeqField<HostAddressesAsn1>,
    #[seq_comp(context_tag = 12, optional)]
    encrypted_pa_data: SeqField<MethodDataAsn1>
}

impl EncAsRepPartAsn1 {


    fn new_empty() -> Self {
        return Self {
            key: SeqField::new(),
            last_req: SeqField::new(),
            nonce: SeqField::new(),
            key_expiration: SeqField::new(),
            flags: SeqField::new(),
            authtime: SeqField::new(),
            starttime: SeqField::new(),
            endtime: SeqField::new(),
            renew_till: SeqField::new(),
            srealm: SeqField::new(),
            sname: SeqField::new(),
            caddr: SeqField::new(),
            encrypted_pa_data: SeqField::new()
        };
    }

    fn no_asn1_type(&self) -> KerberosResult<EncAsRepPart> {
        let key = self.get_key().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::key".to_string())
        )?;
        let last_req = self.get_last_req().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::last_req".to_string())
        )?;
        let nonce = self.get_nonce().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::nonce".to_string())
        )?;
        let flags = self.get_flags().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::flags".to_string())
        )?;
        let authtime = self.get_authtime().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::authtime".to_string())
        )?;
        let endtime = self.get_endtime().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::endtime".to_string())
        )?;
        let srealm = self.get_srealm().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::srealm".to_string())
        )?;
        let sname = self.get_sname().ok_or_else(|| 
            KerberosErrorKind::NotAvailableData("EncAsRepPart::sname".to_string())
        )?;

        let mut enc_as_rep_part = EncAsRepPart::new(
            key.no_asn1_type()?,
            last_req.no_asn1_type()?,
            nonce.no_asn1_type()?,
            flags.no_asn1_type()?,
            authtime.no_asn1_type()?, 
            endtime.no_asn1_type()?,
            srealm.no_asn1_type()?,
            sname.no_asn1_type()?
        );

        if let Some(key_expiration) = self.get_key_expiration() {
            enc_as_rep_part.set_key_expiration(key_expiration.no_asn1_type()?);
        }

        if let Some(starttime) = self.get_starttime() {
            enc_as_rep_part.set_starttime(starttime.no_asn1_type()?);
        }
        if let Some(renew_till) = self.get_renew_till() {
            enc_as_rep_part.set_renew_till(renew_till.no_asn1_type()?);
        }

        if let Some(caddr) = self.get_caddr() {
            enc_as_rep_part.set_caddr(caddr.no_asn1_type()?);
        }

        if let Some(encrypted_pa_data) = self.get_encrypted_pa_data() {
            enc_as_rep_part.set_encrypted_pa_data(encrypted_pa_data.no_asn1_type()?);
        }
        
        return Ok(enc_as_rep_part);
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use super::super::super::constants::*;

    #[test]
    fn decode_enc_as_rep_part() {
        let raw: Vec<u8> = vec![
            0x79, 0x82, 0x01, 0x29, 0x30, 0x82, 0x01, 0x25,
            0xa0, 0x2b, 0x30, 0x29, 0xa0, 0x03, 0x02, 0x01,
            0x12, 0xa1, 0x22, 0x04, 0x20, 0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff, 0xa1, 0x1c, 0x30,
            0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x00,
            0xa1, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30,
            0x33, 0x31, 0x5a, 0xa2, 0x06, 0x02, 0x04, 0x06,
            0x3c, 0xc3, 0x54, 0xa3, 0x11, 0x18, 0x0f, 0x32,
            0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x34, 0x30,
            0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa4, 0x07,
            0x03, 0x05, 0x00, 0x40, 0xe0, 0x00, 0x00, 0xa5,
            0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39, 0x30,
            0x34, 0x31, 0x38, 0x30, 0x36, 0x30, 0x30, 0x33,
            0x31, 0x5a, 0xa6, 0x11, 0x18, 0x0f, 0x32, 0x30,
            0x31, 0x39, 0x30, 0x34, 0x31, 0x38, 0x30, 0x36,
            0x30, 0x30, 0x33, 0x31, 0x5a, 0xa7, 0x11, 0x18,
            0x0f, 0x32, 0x30, 0x31, 0x39, 0x30, 0x34, 0x31,
            0x38, 0x31, 0x36, 0x30, 0x30, 0x33, 0x31, 0x5a,
            0xa8, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x39,
            0x30, 0x34, 0x32, 0x35, 0x30, 0x36, 0x30, 0x30,
            0x33, 0x31, 0x5a, 0xa9, 0x10, 0x1b, 0x0e, 0x4b,
            0x49, 0x4e, 0x47, 0x44, 0x4f, 0x4d, 0x2e, 0x48,
            0x45, 0x41, 0x52, 0x54, 0x53, 0xaa, 0x23, 0x30,
            0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1a,
            0x30, 0x18, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74,
            0x67, 0x74, 0x1b, 0x0e, 0x4b, 0x49, 0x4e, 0x47,
            0x44, 0x4f, 0x4d, 0x2e, 0x48, 0x45, 0x41, 0x52,
            0x54, 0x53, 0xab, 0x1d, 0x30, 0x1b, 0x30, 0x19,
            0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12, 0x04,
            0x10, 0x48, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x42,
            0x41, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x20, 0x20,
            0x20, 0xac, 0x12, 0x30, 0x10, 0x30, 0x0e, 0xa1,
            0x04, 0x02, 0x02, 0x00, 0xa5, 0xa2, 0x06, 0x04,
            0x04, 0x1f, 0x00, 0x00, 0x00
        ];

        let mut enc_as_rep_part_asn1 = EncAsRepPartAsn1::new_empty();
        enc_as_rep_part_asn1.decode(&raw).unwrap();


        let encryption_key = EncryptionKey::new(
            AES256_CTS_HMAC_SHA1_96,
            vec![0x63, 0x7b, 0x4d,
            0x21, 0x38, 0x22, 0x5a, 0x3a, 0x0a, 0xd7, 0x93,
            0x5a, 0xf3, 0x31, 0x22, 0x68, 0x50, 0xeb, 0x53,
            0x1d, 0x2d, 0x40, 0xf2, 0x19, 0x19, 0xd0, 0x08,
            0x41, 0x91, 0x72, 0x17, 0xff]
        );

        let mut last_req = LastReq::new_empty();
        last_req.push(LastReqEntry::new(
            0,
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31))
        ));

        let mut ticket_flags = TicketFlags::new_empty();
        ticket_flags.set_flags(
            ticketflags::INITIAL 
            | ticketflags::FORWARDABLE 
            | ticketflags::PRE_AUTHENT 
            | ticketflags::RENEWABLE
        );

        let kerb_time = KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(06, 00, 31));

        let mut sname =  PrincipalName::new(NT_SRV_INST, KerberosString::_from("krbtgt"));
        sname.push(KerberosString::_from("KINGDOM.HEARTS"));

        let mut encrypted_pa_datas = MethodData::new();
        encrypted_pa_datas.push(
            PaData::Raw(PA_SUPPORTED_ENCTYPES, vec![0x1f, 0x0, 0x0, 0x0])
        );

        let mut enc_as_rep_part = EncAsRepPart::new(
            encryption_key,
            last_req,
            104645460,
            ticket_flags,
            kerb_time.clone(),
            KerberosTime::new(Utc.ymd(2019, 4, 18).and_hms(16, 00, 31)),
            Realm::_from("KINGDOM.HEARTS"),
            sname
        );

        enc_as_rep_part.set_key_expiration(
            KerberosTime::new(Utc.ymd(2037, 9, 14).and_hms(02, 48, 05))
        );

        enc_as_rep_part.set_starttime(kerb_time);
        enc_as_rep_part.set_renew_till(
            KerberosTime::new(Utc.ymd(2019, 4, 25).and_hms(06, 00, 31))
        );
        enc_as_rep_part.set_caddr(
            HostAddresses::new(
                HostAddress::NetBios("HOLLOWBASTION".to_string())
            )
        );
        enc_as_rep_part.set_encrypted_pa_data(encrypted_pa_datas);



        assert_eq!(enc_as_rep_part, enc_as_rep_part_asn1.no_asn1_type().unwrap());

    }

}