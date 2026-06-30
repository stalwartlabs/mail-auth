use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=../Cargo.toml");
    let manifest = fs::read_to_string("../Cargo.toml").unwrap_or_default();
    let mut version = "unknown".to_string();
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package && line.starts_with("version") {
            if let Some(value) = line.split('=').nth(1) {
                version = value.trim().trim_matches('"').to_string();
                break;
            }
        }
    }
    println!("cargo:rustc-env=MAIL_AUTH_VERSION={version}");
}
