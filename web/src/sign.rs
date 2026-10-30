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

use crate::{
    dns::{DnsOpts, params},
    load_key, normalize_eol,
    verify::dkim2_result_label,
};
use encodify::base64;
use mail_auth::{
    AuthenticatedMessage, Dkim2Output, Dkim2Result,
    dkim::DkimSigner,
    dkim2::{Dkim2Hash, Dkim2Signed, Dkim2Signer, Envelope, Flag, Hop, MessageInstance},
    headers::HeaderWriter,
    signer::Ready,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sign_dkim1(
    key_pem: &str,
    algorithm: &str,
    domain: &str,
    selector: &str,
    headers: Vec<String>,
    message: &str,
) -> Result<String, String> {
    let key = load_key(key_pem, algorithm)?;
    let body = normalize_eol(message);
    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(headers)
        .sign(body.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(format!("{}{}", signature.to_header(), body))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dkim2Opts {
    key_pem: String,
    algorithm: String,
    domain: String,
    selector: String,
    hashes: Vec<String>,
    flags: Vec<String>,
    nonce: String,
    hop: HopOpts,
    gate: String,
    received: EnvelopeOpts,
    dns: DnsOpts,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HopOpts {
    kind: String,
    mail_from: String,
    rcpt_to: Vec<String>,
    next_domain: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeOpts {
    mail_from: String,
    rcpt_to: Vec<String>,
}

enum Gate {
    Verify,
    OutOfBand,
}

struct Dkim2Request {
    signer: Dkim2Signer<Ready>,
    hop: HopOpts,
    gate: Gate,
    received: EnvelopeOpts,
    dns: DnsOpts,
}

impl Dkim2Request {
    fn parse(opts: JsValue) -> Result<Self, String> {
        let opts: Dkim2Opts =
            serde_wasm_bindgen::from_value(opts).map_err(|err| err.to_string())?;
        let key = load_key(&opts.key_pem, &opts.algorithm)?;
        let hashes = opts
            .hashes
            .iter()
            .map(|name| {
                Dkim2Hash::parse(name.as_bytes()).ok_or_else(|| format!("Unknown hash: {name}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let gate = match opts.gate.as_str() {
            "verify" => Gate::Verify,
            "out-of-band" => Gate::OutOfBand,
            other => return Err(format!("Unknown validity gate: {other}")),
        };
        if !matches!(opts.hop.kind.as_str(), "smtp" | "imaginary") {
            return Err(format!("Unknown hop kind: {}", opts.hop.kind));
        }
        let mut signer = Dkim2Signer::from_key(key)
            .domain(opts.domain)
            .selector(opts.selector)
            .hashes(hashes)
            .flags(opts.flags.into_iter().map(Flag::Unknown))
            .nonce(opts.nonce);
        if matches!(gate, Gate::OutOfBand) {
            signer = signer.out_of_band_arrangement();
        }
        Ok(Dkim2Request {
            signer,
            hop: opts.hop,
            gate,
            received: opts.received,
            dns: opts.dns,
        })
    }

    fn hop(&self) -> Hop<&str, &[String], String> {
        if self.hop.kind == "imaginary" {
            Hop::Imaginary {
                next_domain: self.hop.next_domain.trim().to_string(),
            }
        } else {
            Hop::Real(Envelope::new(
                self.hop.mail_from.as_str(),
                self.hop.rcpt_to.as_slice(),
            ))
        }
    }

    async fn sign(
        &self,
        received: &str,
        modified: Option<&str>,
    ) -> Result<(Dkim2Signed, String), String> {
        let message = AuthenticatedMessage::parse(received.as_bytes())
            .ok_or_else(|| "Could not parse the message".to_string())?;
        let has_dkim2 = !message.dkim2_signatures().is_empty()
            || !message.dkim2_instances().is_empty()
            || message.has_dkim2_errors();
        let resolver = self.dns.resolver();
        let cache = self.dns.cache()?;
        let (verified, validity) = match (&self.gate, has_dkim2) {
            (_, false) => (
                None,
                "New message: no DKIM2 header fields, so no validity check is needed (-08 §12)."
                    .to_string(),
            ),
            (Gate::OutOfBand, true) => (
                None,
                "Signed under an out-of-band arrangement: the received message was not verified \
                 (-08 §12, §12.3)."
                    .to_string(),
            ),
            (Gate::Verify, true) => {
                let envelope = Envelope::new(
                    self.received.mail_from.as_str(),
                    self.received.rcpt_to.as_slice(),
                );
                let output = resolver
                    .verify_dkim2(params(&message, &cache), envelope)
                    .await;
                if !matches!(output.result(), Dkim2Result::Pass) {
                    return Err(not_fully_verified(&output));
                }
                (
                    Some(output),
                    "The received message passed full verification with the received envelope, \
                     so it is a Fully Verified DKIM2 Message (-08 §12, §13)."
                        .to_string(),
                )
            }
        };
        let signed = match modified {
            Some(modified) => self.signer.sign_revised(
                received.as_bytes(),
                modified.as_bytes(),
                self.hop(),
                verified.as_ref(),
            ),
            None => self
                .signer
                .sign(received.as_bytes(), self.hop(), verified.as_ref()),
        }
        .map_err(|err| err.to_string())?;
        Ok((signed, validity))
    }
}

fn not_fully_verified(output: &Dkim2Output<'_>) -> String {
    let (label, err) = dkim2_result_label(output.result());
    let reason = if err.is_empty() {
        label.to_string()
    } else {
        format!("{label}: {err}")
    };
    format!(
        "The received message is not a Fully Verified DKIM2 Message, so it cannot be signed \
         without an out-of-band arrangement (-08 §12). Full verification with the received \
         envelope returned {reason}"
    )
}

#[derive(Serialize)]
struct SignResult {
    signed_message: String,
    instance: String,
    validity: String,
}

impl SignResult {
    fn new(signed: &Dkim2Signed, message: &str, validity: String) -> Self {
        SignResult {
            signed_message: format!("{}{}", signed.to_header(), message),
            instance: instance_to_json(signed.message_instance.as_ref()),
            validity,
        }
    }

    fn into_js(self) -> Result<JsValue, String> {
        serde_wasm_bindgen::to_value(&self).map_err(|err| err.to_string())
    }
}

#[wasm_bindgen]
pub async fn sign_dkim2(opts: JsValue, message: String) -> Result<JsValue, String> {
    let request = Dkim2Request::parse(opts)?;
    let message = normalize_eol(&message);
    let (signed, validity) = request.sign(&message, None).await?;
    SignResult::new(&signed, &message, validity).into_js()
}

#[wasm_bindgen]
pub async fn sign_dkim2_revised(
    opts: JsValue,
    original: String,
    modified: String,
) -> Result<JsValue, String> {
    let request = Dkim2Request::parse(opts)?;
    let original = normalize_eol(&original);
    let modified = normalize_eol(&modified);
    let (signed, validity) = request.sign(&original, Some(&modified)).await?;
    SignResult::new(&signed, &modified, validity).into_js()
}

#[derive(Serialize)]
struct JsonInstance {
    m: u32,
    h: Vec<JsonHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    r: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonHash {
    algorithm: String,
    header_hash: String,
    body_hash: String,
}

fn instance_to_json(instance: Option<&MessageInstance>) -> String {
    let Some(instance) = instance else {
        return "null".to_string();
    };
    let recipe = match instance.recipe.as_ref() {
        Some(recipe) => {
            let mut json = Vec::new();
            match recipe.to_json(&mut json) {
                Ok(()) => serde_json::from_slice(&json).ok(),
                Err(err) => Some(serde_json::Value::String(err.to_string())),
            }
        }
        None => None,
    };
    let json = JsonInstance {
        m: instance.m,
        h: instance
            .hashes
            .iter()
            .map(|hash| JsonHash {
                algorithm: hash.name.as_str().to_string(),
                header_hash: base64::STANDARD.encode(&hash.header_hash),
                body_hash: base64::STANDARD.encode(&hash.body_hash),
            })
            .collect(),
        r: recipe,
    };
    serde_json::to_string_pretty(&json).unwrap_or_else(|err| err.to_string())
}
