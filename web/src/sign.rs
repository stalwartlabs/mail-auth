/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{load_key, normalize_eol};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_auth::{
    common::headers::HeaderWriter,
    dkim::DkimSigner,
    dkim2::{BodyRecipe, Dkim2Signer, Envelope, Hop, MessageInstance, Recipe, Step},
};
use serde::Serialize;
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

#[wasm_bindgen]
pub fn sign_dkim2(
    key_pem: &str,
    algorithm: &str,
    domain: &str,
    selector: &str,
    mail_from: &str,
    rcpt_to: Vec<String>,
    message: &str,
) -> Result<String, String> {
    let key = load_key(key_pem, algorithm)?;
    let body = normalize_eol(message);
    let rcpts: Vec<&str> = rcpt_to.iter().map(String::as_str).collect();
    let hop = Hop::Real(Envelope {
        mail_from,
        rcpt_to: &rcpts,
    });
    let signed = Dkim2Signer::from_key(key)
        .domain(domain)
        .selector(selector)
        .sign(body.as_bytes(), &hop)
        .map_err(|err| err.to_string())?;
    Ok(format!("{}{}", signed.to_header(), body))
}

#[derive(Serialize)]
struct RevisedResult {
    signed_message: String,
    recipe_debug: String,
}

#[wasm_bindgen]
pub fn sign_dkim2_revised(
    key_pem: &str,
    algorithm: &str,
    domain: &str,
    selector: &str,
    mail_from: &str,
    rcpt_to: Vec<String>,
    original: &str,
    modified: &str,
) -> Result<JsValue, String> {
    let key = load_key(key_pem, algorithm)?;
    let original = normalize_eol(original);
    let modified = normalize_eol(modified);
    let rcpts: Vec<&str> = rcpt_to.iter().map(String::as_str).collect();
    let hop = Hop::Real(Envelope {
        mail_from,
        rcpt_to: &rcpts,
    });
    let signed = Dkim2Signer::from_key(key)
        .domain(domain)
        .selector(selector)
        .sign_revised(original.as_bytes(), modified.as_bytes(), &hop)
        .map_err(|err| err.to_string())?;
    let result = RevisedResult {
        signed_message: format!("{}{}", signed.to_header(), modified),
        recipe_debug: instance_to_json(signed.message_instance.as_ref()),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|err| err.to_string())
}

#[derive(Serialize)]
struct JsonInstance {
    m: u32,
    hashes: Vec<JsonHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipe: Option<JsonRecipe>,
}

#[derive(Serialize)]
struct JsonHash {
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    header_hash: String,
    body_hash: String,
}

#[derive(Serialize)]
struct JsonRecipe {
    headers: Vec<JsonHeaderRecipe>,
    body: JsonBody,
}

#[derive(Serialize)]
struct JsonHeaderRecipe {
    name: String,
    steps: Vec<JsonStep>,
}

#[derive(Serialize)]
struct JsonBody {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    steps: Option<Vec<JsonStep>>,
}

#[derive(Serialize)]
struct JsonStep {
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Vec<String>>,
}

fn instance_to_json(instance: Option<&MessageInstance>) -> String {
    let Some(instance) = instance else {
        return "null".to_string();
    };
    let json = JsonInstance {
        m: instance.m,
        hashes: instance
            .hashes
            .iter()
            .map(|hash| JsonHash {
                algorithm: hash.name.map(|name| format!("{name:?}")),
                header_hash: STANDARD.encode(&hash.header_hash),
                body_hash: STANDARD.encode(&hash.body_hash),
            })
            .collect(),
        recipe: instance.recipe.as_ref().map(recipe_to_json),
    };
    serde_json::to_string_pretty(&json).unwrap_or_else(|err| err.to_string())
}

fn recipe_to_json(recipe: &Recipe) -> JsonRecipe {
    JsonRecipe {
        headers: recipe
            .headers
            .iter()
            .map(|header| JsonHeaderRecipe {
                name: header.name.clone(),
                steps: header.steps.iter().map(step_to_json).collect(),
            })
            .collect(),
        body: match &recipe.body {
            BodyRecipe::None => JsonBody {
                kind: "none".to_string(),
                steps: None,
            },
            BodyRecipe::Steps(steps) => JsonBody {
                kind: "steps".to_string(),
                steps: Some(steps.iter().map(step_to_json).collect()),
            },
            BodyRecipe::Unreconstructable => JsonBody {
                kind: "unreconstructable".to_string(),
                steps: None,
            },
        },
    }
}

fn step_to_json(step: &Step) -> JsonStep {
    match step {
        Step::Copy { start, end } => JsonStep {
            op: "copy".to_string(),
            start: Some(*start),
            end: Some(*end),
            data: None,
        },
        Step::Data(lines) => JsonStep {
            op: "data".to_string(),
            start: None,
            end: None,
            data: Some(lines.clone()),
        },
    }
}
