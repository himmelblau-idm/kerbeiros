use ascii::AsciiString;
use kerbeiros::*;

fn main() {
    // Prepare the arguments
    let realm = AsciiString::from_ascii("DEMO1.FREEIPA.ORG").unwrap();
    let kdc_address = kerbeiros::utils::resolve_realm_kdc(
        &AsciiString::from_ascii("ipa.demo1.freeipa.org").unwrap(),
    )
    .unwrap();
    let username = AsciiString::from_ascii("employee").unwrap();
    let user_key = Key::Password("Secret123".to_string());

    // Request the TGT
    let tgt_requester = TgtRequester::new(realm, kdc_address);
    let credential = tgt_requester.request(&username, Some(&user_key)).unwrap();

    // Save the ticket into a Linux format file
    credential
        .save_into_ccache_file("employee_tgt.ccache")
        .unwrap();
}

