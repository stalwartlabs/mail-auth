/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

/*
    DISCLAIMER:
    This code has been written by an LLM and is inefficient and unidiomatic.
    It was created to demonstrate mail-auth in the browser and is not intended for production use.
    It may contain errors, security vulnerabilities, or other issues that could cause harm if used
    in a real-world application. Use at your own risk.
*/

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_auth::dkim::generate::DkimKeyPair;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct GeneratedKey {
    algorithm: String,
    private_pem: String,
    public_key: String,
    dns_record_name: String,
    dns_record_value: String,
}

#[wasm_bindgen]
pub fn generate_key(
    algorithm: &str,
    rsa_bits: u32,
    selector: &str,
    domain: &str,
) -> Result<JsValue, String> {
    let (pair, label, k) = match algorithm {
        "rsa" => (
            DkimKeyPair::generate_rsa(rsa_bits as usize),
            "RSA PRIVATE KEY",
            "rsa",
        ),
        "ed25519" => (DkimKeyPair::generate_ed25519(), "PRIVATE KEY", "ed25519"),
        other => return Err(format!("Unknown algorithm: {other}")),
    };
    let pair = pair.map_err(|err| err.to_string())?;
    let generated = GeneratedKey {
        algorithm: k.to_string(),
        private_pem: der_to_pem(label, pair.private_key()),
        public_key: pair.encoded_public_key(),
        dns_record_name: format!("{selector}._domainkey.{domain}"),
        dns_record_value: format!("v=DKIM1; k={k}; p={}", pair.encoded_public_key()),
    };
    serde_wasm_bindgen::to_value(&generated).map_err(|err| err.to_string())
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
