/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::cache::OfflineCache;
use crate::normalize_eol;
use mail_auth::{
    AuthenticatedMessage, Dkim2Result, DkimOutput, DkimResult, DmarcResult, MessageAuthenticator,
    Parameters, SpfResult, dkim2::Envelope, dmarc::verify::DmarcParameters,
    spf::verify::SpfParameters,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyOpts {
    mode: String,
    doh_endpoint: String,
    doh_format: String,
    records: String,
    check_dkim: bool,
    check_dkim2: bool,
    check_spf: bool,
    check_dmarc: bool,
    remote_ip: String,
    ehlo: String,
    host_domain: String,
    mail_from: String,
    rcpt_to: Vec<String>,
    message: String,
}

#[derive(Serialize)]
struct CheckResult {
    status: String,
    detail: String,
}

impl CheckResult {
    fn new(status: &str, detail: impl Into<String>) -> Self {
        CheckResult {
            status: status.to_string(),
            detail: detail.into(),
        }
    }
}

#[derive(Serialize, Default)]
struct VerifyResults {
    dkim: Option<CheckResult>,
    dkim2: Option<CheckResult>,
    spf: Option<CheckResult>,
    dmarc: Option<CheckResult>,
}

#[wasm_bindgen]
pub async fn verify(opts: JsValue) -> Result<JsValue, String> {
    let opts: VerifyOpts = serde_wasm_bindgen::from_value(opts).map_err(|err| err.to_string())?;
    let raw = normalize_eol(&opts.message).into_bytes();

    let offline = opts.mode == "offline";
    let resolver = if offline {
        MessageAuthenticator::new_doh("https://offline.invalid/dns-query")
    } else if opts.doh_format == "wire" {
        MessageAuthenticator::new_doh_wire(opts.doh_endpoint.clone())
    } else {
        MessageAuthenticator::new_doh(opts.doh_endpoint.clone())
    };
    let cache = if offline {
        OfflineCache::from_records(&opts.records)?
    } else {
        OfflineCache::default()
    };

    let message = AuthenticatedMessage::parse(&raw)
        .ok_or_else(|| "Could not parse the message".to_string())?;

    let mut results = VerifyResults::default();

    let need_dkim = opts.check_dkim || opts.check_dmarc;
    let need_spf = opts.check_spf || opts.check_dmarc;
    let ip = opts.remote_ip.trim().parse::<IpAddr>().ok();
    let host_domain = if opts.host_domain.trim().is_empty() {
        "localhost"
    } else {
        opts.host_domain.trim()
    };

    let dkim_output = if need_dkim {
        Some(resolver.verify_dkim(params(&message, &cache)).await)
    } else {
        None
    };

    let spf_output = match (need_spf, ip) {
        (true, Some(ip)) => Some(
            resolver
                .verify_spf(params(
                    SpfParameters::verify_mail_from(ip, &opts.ehlo, host_domain, &opts.mail_from),
                    &cache,
                ))
                .await,
        ),
        _ => None,
    };

    if opts.check_dkim {
        results.dkim = Some(dkim_check(dkim_output.as_deref().unwrap_or(&[])));
    }

    if opts.check_dkim2 {
        let rcpts: Vec<&str> = opts.rcpt_to.iter().map(String::as_str).collect();
        let envelope = Envelope {
            mail_from: &opts.mail_from,
            rcpt_to: &rcpts,
        };
        let output = resolver
            .verify_dkim2(params(&message, &cache), &envelope)
            .await;
        results.dkim2 = Some(dkim2_check(&output));
    }

    if opts.check_spf {
        results.spf = Some(match (&spf_output, ip) {
            (Some(output), _) => spf_check(output),
            (None, None) => CheckResult::new("NONE", "Enter a valid remote IP to evaluate SPF"),
            (None, _) => CheckResult::new("NONE", "SPF was not evaluated"),
        });
    }

    if opts.check_dmarc {
        results.dmarc = Some(match (dkim_output.as_ref(), spf_output.as_ref()) {
            (Some(dkim), Some(spf)) => {
                let from_domain = opts.mail_from.rsplit('@').next().unwrap_or(&opts.mail_from);
                let output = resolver
                    .verify_dmarc(params(
                        DmarcParameters::new(&message, dkim, from_domain, spf)
                            .with_domain_suffix_fn(org_domain),
                        &cache,
                    ))
                    .await;
                dmarc_check(&output)
            }
            _ => CheckResult::new(
                "NONE",
                "DMARC needs DKIM and a valid SPF remote IP to evaluate alignment",
            ),
        });
    }

    serde_wasm_bindgen::to_value(&results).map_err(|err| err.to_string())
}

type FullCache<'x, P> =
    Parameters<'x, P, OfflineCache, OfflineCache, OfflineCache, OfflineCache, OfflineCache>;

fn params<'x, P>(inner: P, cache: &'x OfflineCache) -> FullCache<'x, P> {
    Parameters::new(inner)
        .with_txt_cache(cache)
        .with_mx_cache(cache)
        .with_ipv4_cache(cache)
        .with_ipv6_cache(cache)
        .with_ptr_cache(cache)
}

fn org_domain(domain: &str) -> &str {
    match domain.rmatch_indices('.').nth(1) {
        Some((idx, _)) => &domain[idx + 1..],
        None => domain,
    }
}

fn dkim_result_label(result: &DkimResult) -> (&'static str, String) {
    match result {
        DkimResult::Pass => ("PASS", String::new()),
        DkimResult::Neutral(err) => ("NEUTRAL", err.to_string()),
        DkimResult::Fail(err) => ("FAIL", err.to_string()),
        DkimResult::PermError(err) => ("PERMERROR", err.to_string()),
        DkimResult::TempError(err) => ("TEMPERROR", err.to_string()),
        DkimResult::None => ("NONE", String::new()),
    }
}

fn dkim_check(outputs: &[DkimOutput]) -> CheckResult {
    if outputs.is_empty() {
        return CheckResult::new("NONE", "No DKIM-Signature headers found");
    }
    let mut lines = Vec::new();
    let mut has_pass = false;
    let mut has_fail = false;
    let mut first = "NONE";
    for (idx, output) in outputs.iter().enumerate() {
        let (label, err) = dkim_result_label(output.result());
        if idx == 0 {
            first = label;
        }
        has_pass |= label == "PASS";
        has_fail |= label == "FAIL" || label == "PERMERROR";
        let identity = output
            .signature()
            .map(|sig| format!("d={} s={} ({})", sig.d, sig.s, algorithm_name(sig.a)))
            .unwrap_or_else(|| "no signature".to_string());
        let suffix = if err.is_empty() {
            String::new()
        } else {
            format!(": {err}")
        };
        lines.push(format!("{label}  {identity}{suffix}"));
    }
    let status = if has_pass {
        "PASS"
    } else if has_fail {
        "FAIL"
    } else {
        first
    };
    CheckResult::new(status, lines.join("\n"))
}

fn algorithm_name(algorithm: mail_auth::common::crypto::Algorithm) -> &'static str {
    use mail_auth::common::crypto::Algorithm;
    match algorithm {
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::RsaSha1 => "rsa-sha1",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
    }
}

fn dkim2_check(output: &mail_auth::dkim2::Dkim2Output) -> CheckResult {
    let (status, top_err) = dkim2_result_label(output.result());
    let mut lines = Vec::new();
    if !top_err.is_empty() {
        lines.push(top_err);
    }
    for link in output.chain() {
        let (label, err) = dkim2_result_label(&link.result);
        let suffix = if err.is_empty() {
            String::new()
        } else {
            format!(": {err}")
        };
        let custody = if link.custody_ok { "" } else { " custody!" };
        lines.push(format!(
            "i={}  d={}  {label}{custody}{suffix}",
            link.signature.i, link.signature.d
        ));
    }
    if output.chain().is_empty() {
        lines.push("No DKIM2-Signature headers found".to_string());
    }
    CheckResult::new(status, lines.join("\n"))
}

fn dkim2_result_label(result: &Dkim2Result) -> (&'static str, String) {
    match result {
        Dkim2Result::Pass => ("PASS", String::new()),
        Dkim2Result::Fail(err) => ("FAIL", err.to_string()),
        Dkim2Result::PermError(err) => ("PERMERROR", err.to_string()),
        Dkim2Result::TempError(err) => ("TEMPERROR", err.to_string()),
        Dkim2Result::None => ("NONE", String::new()),
    }
}

fn spf_check(output: &mail_auth::SpfOutput) -> CheckResult {
    let status = match output.result() {
        SpfResult::Pass => "PASS",
        SpfResult::Fail => "FAIL",
        SpfResult::SoftFail => "SOFTFAIL",
        SpfResult::Neutral => "NEUTRAL",
        SpfResult::TempError => "TEMPERROR",
        SpfResult::PermError => "PERMERROR",
        SpfResult::None => "NONE",
    };
    let mut detail = format!("domain {}", output.domain());
    if let Some(explanation) = output.explanation() {
        detail.push_str(&format!("\n{explanation}"));
    } else if matches!(status, "FAIL" | "SOFTFAIL" | "NEUTRAL") {
        detail.push_str("\nThe remote IP is not authorized by the domain's SPF record");
    } else if status == "NONE" {
        detail.push_str("\nNo SPF record was found for the domain");
    }
    CheckResult::new(status, detail)
}

fn dmarc_result_label(result: &DmarcResult) -> (&'static str, String) {
    match result {
        DmarcResult::Pass => ("PASS", String::new()),
        DmarcResult::Fail(err) => ("FAIL", err.to_string()),
        DmarcResult::TempError(err) => ("TEMPERROR", err.to_string()),
        DmarcResult::PermError(err) => ("PERMERROR", err.to_string()),
        DmarcResult::None => ("NONE", String::new()),
    }
}

fn dmarc_check(output: &mail_auth::DmarcOutput) -> CheckResult {
    let (dkim, dkim_err) = dmarc_result_label(output.dkim_result());
    let (spf, spf_err) = dmarc_result_label(output.spf_result());
    let status = if dkim == "PASS" || spf == "PASS" {
        "PASS"
    } else {
        "FAIL"
    };
    let mut detail = format!("policy {:?} for {}", output.policy(), output.domain());
    detail.push_str(&format!("\nDKIM alignment: {dkim}"));
    if !dkim_err.is_empty() {
        detail.push_str(&format!(" ({dkim_err})"));
    }
    detail.push_str(&format!("\nSPF alignment: {spf}"));
    if !spf_err.is_empty() {
        detail.push_str(&format!(" ({spf_err})"));
    }
    if output.dmarc_record().is_none() {
        detail.push_str("\nNo DMARC record found for this domain");
    }
    if status == "FAIL" {
        detail.push_str(
            "\nDMARC passes when SPF or DKIM is aligned with the From domain; check that the \
             signing/sending domain matches and that the relevant record is published",
        );
    }
    CheckResult::new(status, detail)
}
