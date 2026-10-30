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

use crate::dns::{DnsOpts, params};
use crate::normalize_eol;
use mail_auth::{
    AuthenticatedMessage, Dkim2Output, Dkim2Result, DkimOutput, DkimResult, DmarcResult, SpfResult,
    dkim2::{BodyRecipe, ChainBinding, Envelope, MessageInstance, Signature, Verification},
    dmarc::verify::DmarcParameters,
    spf::verify::SpfParameters,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::net::IpAddr;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyOpts {
    dns: DnsOpts,
    check_dkim: bool,
    check_dkim2: bool,
    check_spf: bool,
    check_dmarc: bool,
    dkim2_mode: String,
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

    let resolver = opts.dns.resolver();
    let cache = opts.dns.cache()?;
    let provisional = match opts.dkim2_mode.as_str() {
        "full" => false,
        "provisional" => true,
        other => return Err(format!("Unknown DKIM2 verification mode: {other}")),
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
                    SpfParameters::mail_from(ip, &opts.ehlo, host_domain, &opts.mail_from),
                    &cache,
                ))
                .await,
        ),
        _ => None,
    };

    if opts.check_dkim {
        results.dkim = Some(dkim_check(dkim_output.as_deref().unwrap_or(&[])));
    }

    let dkim2_output = if opts.check_dkim2 {
        let envelope = Envelope::new(opts.mail_from.as_str(), opts.rcpt_to.as_slice());
        let output = if provisional {
            resolver
                .verify_dkim2_provisionally(params(&message, &cache), envelope)
                .await
        } else {
            resolver
                .verify_dkim2(params(&message, &cache), envelope)
                .await
        };
        results.dkim2 = Some(dkim2_check(&output, &message));
        Some(output)
    } else {
        None
    };

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
                let mut dmarc_params = DmarcParameters::new(&message, dkim, from_domain, spf);
                if let Some(dkim2) = dkim2_output.as_ref() {
                    dmarc_params = dmarc_params.with_dkim2_output(dkim2);
                }
                let output = resolver.verify_dmarc(params(dmarc_params, &cache)).await;
                dmarc_check(&output, dkim2_output.as_ref())
            }
            _ => CheckResult::new(
                "NONE",
                "DMARC needs DKIM and a valid SPF remote IP to evaluate alignment",
            ),
        });
    }

    serde_wasm_bindgen::to_value(&results).map_err(|err| err.to_string())
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

fn algorithm_name(algorithm: mail_auth::crypto::Algorithm) -> &'static str {
    algorithm.name()
}

fn dkim2_check(output: &Dkim2Output<'_>, message: &AuthenticatedMessage<'_>) -> CheckResult {
    let (status, top_err) = dkim2_result_label(output.result());
    let mut detail = String::new();
    match output.verification() {
        Verification::Full => detail.push_str("Full verification (-08 §14)"),
        Verification::Provisional => detail.push_str(
            "Provisional verification (-08 §13.2): only the most recent signature and \
             Message-Instance were checked",
        ),
    }
    if !top_err.is_empty() {
        let _ = write!(detail, "\n{top_err}");
    }

    if output.chain().is_empty() {
        let signatures = message.dkim2_signatures();
        if signatures.is_empty() {
            detail.push_str("\nNo DKIM2-Signature header fields found");
        } else {
            detail.push_str("\nSignatures in the message:");
            for header in signatures {
                let _ = write!(detail, "\n  {}", signature_summary(&header.header));
            }
        }
    } else {
        detail.push_str("\nVerified chain:");
        for link in output.chain() {
            let (label, err) = dkim2_result_label(&link.result);
            let _ = write!(detail, "\n  {label}  {}", signature_summary(link.signature));
            if !link.custody_ok {
                detail.push_str("  [chain of custody broken]");
            }
            if !err.is_empty() {
                let _ = write!(detail, ": {err}");
            }
        }
    }

    let instances = message.dkim2_instances();
    if !instances.is_empty() {
        detail.push_str("\nMessage-Instance header fields:");
        for header in instances {
            let _ = write!(detail, "\n  {}", instance_summary(&header.header));
        }
    }

    let feedback = output.feedback_domains().collect::<Vec<_>>();
    if !feedback.is_empty() {
        let _ = write!(detail, "\nFeedback requested by: {}", feedback.join(", "));
        if let Some(relay) = output.feedback_relay() {
            let _ = write!(detail, " (relayed via {relay})");
        }
    }
    CheckResult::new(status, detail)
}

fn signature_summary(signature: &Signature) -> String {
    let mut line = format!("i={} m={} d={}", signature.i, signature.m, signature.d);
    for value in &signature.s {
        let _ = write!(line, " s={}:{}", value.selector, value.a.as_str());
    }
    match &signature.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => {
            let _ = write!(line, " mf={mail_from} rt={}", rcpt_to.join(","));
        }
        ChainBinding::NextDomain(domain) => {
            let _ = write!(line, " nd={domain}");
        }
    }
    if !signature.flags.is_empty() {
        line.push_str(" f=");
        for (idx, flag) in signature.flags.iter().enumerate() {
            if idx > 0 {
                line.push(',');
            }
            line.push_str(&String::from_utf8_lossy(flag.as_bytes()));
        }
    }
    line
}

fn instance_summary(instance: &MessageInstance) -> String {
    let mut line = format!("m={} h=", instance.m);
    for (idx, hash) in instance.hashes.iter().enumerate() {
        if idx > 0 {
            line.push(',');
        }
        line.push_str(hash.name.as_str());
    }
    if let Some(recipe) = &instance.recipe {
        line.push_str(" r=");
        let headers = recipe
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect::<Vec<_>>();
        if !headers.is_empty() {
            let _ = write!(line, "headers({})", headers.join(","));
        }
        match &recipe.body {
            BodyRecipe::None => {}
            BodyRecipe::Steps(_) => {
                if !headers.is_empty() {
                    line.push('+');
                }
                line.push_str("body");
            }
            BodyRecipe::Unreconstructable => {
                if !headers.is_empty() {
                    line.push('+');
                }
                line.push_str("body(null)");
            }
        }
    }
    line
}

pub(crate) fn dkim2_result_label(result: &Dkim2Result) -> (&'static str, String) {
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

fn dmarc_check(output: &mail_auth::DmarcOutput, dkim2: Option<&Dkim2Output<'_>>) -> CheckResult {
    let (dkim, dkim_err) = dmarc_result_label(output.dkim_result());
    let (spf, spf_err) = dmarc_result_label(output.spf_result());
    let status = if dkim == "PASS" || spf == "PASS" {
        "PASS"
    } else {
        "FAIL"
    };
    let mut detail = format!("policy {:?} for {}", output.policy(), output.domain());
    let _ = write!(detail, "\nDKIM alignment: {dkim}");
    if !dkim_err.is_empty() {
        let _ = write!(detail, " ({dkim_err})");
    }
    let _ = write!(detail, "\nSPF alignment: {spf}");
    if !spf_err.is_empty() {
        let _ = write!(detail, " ({spf_err})");
    }
    match dkim2.map(Dkim2Output::verification) {
        Some(Verification::Full) => detail
            .push_str("\nDKIM alignment also considers the i=1 DKIM2-Signature when DKIM2 passes"),
        Some(Verification::Provisional) => detail
            .push_str("\nA provisional DKIM2 verification does not take part in DMARC alignment"),
        None => {}
    }
    if output.record().is_none() {
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
