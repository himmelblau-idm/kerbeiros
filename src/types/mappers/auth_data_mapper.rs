use crate::types::*;

pub struct AuthDataMapper {}

impl AuthDataMapper {
    pub fn padata_to_auth_data(padata: &PaData) -> AuthData {
        return AuthData::new(
            padata.padata_type() as u16,
            CountedOctetString::new(padata.padata_value_as_bytes()),
        );
    }

    pub fn method_data_to_auth_data_vector(method_data: &MethodData) -> Vec<AuthData> {
        let mut auth_data = Vec::new();
        for padata in method_data.iter() {
            auth_data.push(Self::padata_to_auth_data(padata));
        }
        return auth_data;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn padata_to_auth_data() {
        let padata = PaData::PacRequest(PacRequest::new(true));

        let auth_data = AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]),
        );

        assert_eq!(auth_data, AuthDataMapper::padata_to_auth_data(&padata));
    }

    #[test]
    fn method_data_to_auth_data_vector() {
        let mut auth_datas = Vec::new();
        auth_datas.push(AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]),
        ));
        auth_datas.push(Address::new(9, CountedOctetString::new(vec![0x8, 0x9])));

        let mut method_data = MethodData::default();
        method_data.push(PaData::PacRequest(PacRequest::new(true)));
        method_data.push(PaData::Raw(9, vec![0x8, 0x9]));

        assert_eq!(
            auth_datas,
            AuthDataMapper::method_data_to_auth_data_vector(&method_data)
        );
    }

    #[test]
    fn auth_data_to_padata() {
        let padata = PaData::PacRequest(PacRequest::new(true));

        let auth_data = AuthData::new(
            PA_PAC_REQUEST as u16,
            CountedOctetString::new(vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]),
        );

        assert_eq!(padata, AuthDataMapper::auth_data_to_padata(&auth_data));
    }
}
