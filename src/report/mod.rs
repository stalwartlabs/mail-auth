/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod arf;
pub mod dmarc;
pub mod tlsrpt;

use std::{borrow::Cow, net::IpAddr};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Alignment {
    Relaxed,
    Strict,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyPublished {
    pub domain: String,
    pub version_published: Option<f32>,
    pub adkim: Alignment,
    pub aspf: Alignment,
    pub p: Disposition,
    pub sp: Disposition,
    pub testing: bool,
    pub fo: Option<String>,
}

impl Eq for PolicyPublished {}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DmarcResult {
    Pass,
    Fail,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    #[default]
    Other,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyOverrideReason {
    type_: PolicyOverride,
    comment: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    disposition: ActionDisposition,
    dkim: DmarcResult,
    spf: DmarcResult,
    reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    source_ip: Option<IpAddr>,
    count: u32,
    policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Extension {
    name: String,
    definition: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identifier {
    envelope_to: Option<String>,
    envelope_from: String,
    header_from: String,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DkimResult {
    #[default]
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DKIMAuthResult {
    domain: String,
    selector: String,
    result: DkimResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SPFDomainScope {
    Helo,
    MailFrom,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpfResult {
    #[default]
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SPFAuthResult {
    domain: String,
    scope: SPFDomainScope,
    result: SpfResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthResult {
    dkim: Vec<DKIMAuthResult>,
    spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    message: Option<Cow<'x, str>>,
    headers: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum AuthFailureType {
    Adsp,
    BodyHash,
    Revoked,
    Signature,
    Spf,
    Dmarc,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum IdentityAlignment {
    None,
    Spf,
    Dkim,
    DkimSpf,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum DeliveryResult {
    Delivered,
    Spam,
    Policy,
    Reject,
    Other,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum FeedbackType {
    Abuse,
    AuthFailure,
    Fraud,
    NotSpam,
    #[default]
    Other,
    Virus,
}

impl From<&crate::DkimResult> for AuthFailureType {
    fn from(value: &crate::DkimResult) -> Self {
        match value {
            crate::DkimResult::Neutral(err)
            | crate::DkimResult::Fail(err)
            | crate::DkimResult::PermError(err)
            | crate::DkimResult::TempError(err) => match err {
                crate::Error::FailedBodyHashMatch => AuthFailureType::BodyHash,
                crate::Error::RevokedPublicKey => AuthFailureType::Revoked,
                _ => AuthFailureType::Signature,
            },
            crate::DkimResult::Pass | crate::DkimResult::None => AuthFailureType::Signature,
        }
    }
}
