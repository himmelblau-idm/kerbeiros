use gethostname::gethostname;

pub fn get_hostname() -> String {
    let hostname = gethostname();
    return hostname.to_string_lossy().to_string();
}
