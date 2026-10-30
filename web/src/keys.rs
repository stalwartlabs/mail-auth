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

use crate::load_key;
use encodify::{base64, pem};
use mail_auth::{crypto::DkimKey, dkim::generate::DkimKeyPair};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct KeyInfo {
    algorithm: String,
    private_pem: String,
    public_key: String,
    dns_record_name: String,
    dns_record_value: String,
}

impl KeyInfo {
    fn new(k: &str, private_pem: String, public_key: String, selector: &str, domain: &str) -> Self {
        KeyInfo {
            algorithm: k.to_string(),
            private_pem,
            dns_record_name: format!("{selector}._domainkey.{domain}"),
            dns_record_value: format!("v=DKIM1; k={k}; p={public_key}"),
            public_key,
        }
    }

    fn into_js(self) -> Result<JsValue, String> {
        serde_wasm_bindgen::to_value(&self).map_err(|err| err.to_string())
    }
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
        "mldsa44" => (DkimKeyPair::generate_mldsa44(), "PRIVATE KEY", "mldsa44"),
        other => return Err(format!("Unknown algorithm: {other}")),
    };
    let pair = pair.map_err(|err| err.to_string())?;
    KeyInfo::new(
        k,
        pem::STANDARD.encode(label, pair.private_key()),
        pair.encoded_public_key(),
        selector,
        domain,
    )
    .into_js()
}

#[wasm_bindgen]
pub fn inspect_key(
    key_pem: &str,
    algorithm: &str,
    selector: &str,
    domain: &str,
) -> Result<JsValue, String> {
    let (k, public_key) = match load_key(key_pem, algorithm)? {
        DkimKey::Rsa(key) => ("rsa", key.public_key()),
        DkimKey::Ed25519(key) => ("ed25519", key.public_key()),
        DkimKey::MlDsa44(key) => ("mldsa44", key.public_key().map_err(|err| err.to_string())?),
    };
    if public_key.is_empty() {
        return Err("Could not derive the public key".to_string());
    }
    KeyInfo::new(
        k,
        key_pem.trim().to_string(),
        base64::STANDARD.encode(&public_key),
        selector,
        domain,
    )
    .into_js()
}
