/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

pub mod arf;
pub mod dmarc;

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DateRange {
    begin: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    org_name: String,
    email: String,
    extra_contact_info: Option<String>,
    report_id: String,
    date_range: DateRange,
    error: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alignment {
    Relaxed,
    Strict,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyPublished {
    domain: String,
    version_published: Option<f32>,
    adkim: Alignment,
    aspf: Alignment,
    p: Disposition,
    sp: Disposition,
    testing: bool,
    fo: Option<String>,
}

impl Eq for PolicyPublished {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcResult {
    Pass,
    Fail,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyOverrideReason {
    type_: PolicyOverride,
    comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    disposition: ActionDisposition,
    dkim: DmarcResult,
    spf: DmarcResult,
    reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    source_ip: IpAddr,
    count: u32,
    policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Extension {
    name: String,
    definition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identifier {
    envelope_to: Option<String>,
    envelope_from: String,
    header_from: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkimResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DKIMAuthResult {
    domain: String,
    selector: String,
    result: DkimResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SPFDomainScope {
    Helo,
    MailFrom,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SPFAuthResult {
    domain: String,
    scope: SPFDomainScope,
    result: SpfResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthResult {
    dkim: Vec<DKIMAuthResult>,
    spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Report {
    version: f32,
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
    extensions: Vec<Extension>,
}

impl Eq for Report {}

impl Default for Row {
    fn default() -> Self {
        Self {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            count: 0,
            policy_evaluated: PolicyEvaluated::default(),
        }
    }
}

impl Default for Alignment {
    fn default() -> Self {
        Alignment::Unspecified
    }
}

impl Default for Disposition {
    fn default() -> Self {
        Disposition::Unspecified
    }
}

impl Default for ActionDisposition {
    fn default() -> Self {
        ActionDisposition::None
    }
}

impl Default for DmarcResult {
    fn default() -> Self {
        DmarcResult::Unspecified
    }
}

impl Default for PolicyOverride {
    fn default() -> Self {
        PolicyOverride::Other
    }
}

impl Default for DkimResult {
    fn default() -> Self {
        DkimResult::None
    }
}

impl Default for SpfResult {
    fn default() -> Self {
        SpfResult::None
    }
}

impl Default for SPFDomainScope {
    fn default() -> Self {
        SPFDomainScope::Unspecified
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MailParseError,
    ReportParseError(String),
    UncompressError(String),
    NoReportsFound,
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::ReportParseError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Feedback<'x> {
    feedback_type: FeedbackType,
    arrival_date: Option<i64>,
    authentication_results: Vec<Cow<'x, str>>,
    incidents: u32,
    original_envelope_id: Option<Cow<'x, str>>,
    original_mail_from: Option<Cow<'x, str>>,
    original_rcpt_to: Option<Cow<'x, str>>,
    reported_domain: Vec<Cow<'x, str>>,
    reported_uri: Vec<Cow<'x, str>>,
    reporting_mta: Option<Cow<'x, str>>,
    source_ip: Option<IpAddr>,
    user_agent: Option<Cow<'x, str>>,
    version: u32,
    source_port: u32,

    // Auth-Failure keys
    auth_failure: AuthFailureType,
    delivery_result: DeliveryResult,
    dkim_adsp_dns: Option<Cow<'x, str>>,
    dkim_canonicalized_body: Option<Cow<'x, str>>,
    dkim_canonicalized_header: Option<Cow<'x, str>>,
    dkim_domain: Option<Cow<'x, str>>,
    dkim_identity: Option<Cow<'x, str>>,
    dkim_selector: Option<Cow<'x, str>>,
    dkim_selector_dns: Option<Cow<'x, str>>,
    spf_dns: Option<Cow<'x, str>>,
    identity_alignment: IdentityAlignment,

    message: Option<Cow<'x, [u8]>>,
    headers: Option<Cow<'x, [u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub enum AuthFailureType {
    Adsp,
    BodyHash,
    Revoked,
    Signature,
    Spf,
    Dmarc,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub enum IdentityAlignment {
    None,
    Spf,
    Dkim,
    DkimSpf,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub enum DeliveryResult {
    Delivered,
    Spam,
    Policy,
    Reject,
    Other,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub enum FeedbackType {
    Abuse,
    AuthFailure,
    Fraud,
    NotSpam,
    Other,
    Virus,
}

impl Default for AuthFailureType {
    fn default() -> Self {
        AuthFailureType::Unspecified
    }
}

impl Default for IdentityAlignment {
    fn default() -> Self {
        IdentityAlignment::Unspecified
    }
}

impl Default for DeliveryResult {
    fn default() -> Self {
        DeliveryResult::Unspecified
    }
}

impl Default for FeedbackType {
    fn default() -> Self {
        FeedbackType::Other
    }
}
