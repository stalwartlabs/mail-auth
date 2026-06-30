/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

mod cache;
mod keys;
mod sign;
mod verify;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("MAIL_AUTH_VERSION").to_string()
}

pub(crate) fn normalize_eol(message: &str) -> String {
    message
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

pub(crate) fn load_key(
    key_pem: &str,
    algorithm: &str,
) -> Result<mail_auth::common::crypto::DkimKey, String> {
    use mail_auth::common::crypto::{DkimKey, Ed25519Key, RsaKey, Sha256};
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

    let der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|err| format!("Could not parse PEM private key: {err}"))?;
    match algorithm {
        "rsa" => RsaKey::<Sha256>::from_key_der(der)
            .map(DkimKey::from)
            .map_err(|err| format!("Invalid RSA key: {err}")),
        "ed25519" => {
            let pkcs8 = match &der {
                PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der(),
                _ => return Err("Ed25519 keys must be in PKCS#8 PEM format".to_string()),
            };
            Ed25519Key::from_pkcs8_der(pkcs8)
                .map(DkimKey::from)
                .map_err(|err| format!("Invalid Ed25519 key: {err}"))
        }
        other => Err(format!("Unknown algorithm: {other}")),
    }
}
