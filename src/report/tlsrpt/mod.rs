/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! SMTP TLS reports (RFC 8460).
//!
//! [`TlsReport`] models the JSON report document of RFC 8460 section 4.
//! Reports are parsed with [`TlsReport::parse_rfc5322`] or
//! [`TlsReport::parse_json`] and written with [`TlsReport::write_rfc5322`],
//! [`TlsReport::write_rfc5322_json`] or [`TlsReport::to_json`]. Serde
//! renames every field to its JSON member name, which the field
//! documentation also gives.

use mail_parser::DateTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;

mod generate;
mod parse;

/// SMTP TLS report (RFC 8460 section 4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct TlsReport {
    /// Name of the reporting organization (`organization-name`).
    #[serde(rename = "organization-name")]
    #[serde(default)]
    pub organization_name: Option<String>,

    /// Reporting period (`date-range`).
    #[serde(rename = "date-range")]
    pub date_range: DateRange,

    /// Contact address of the reporting organization (`contact-info`).
    #[serde(rename = "contact-info")]
    #[serde(default)]
    pub contact_info: Option<String>,

    /// Unique identifier of the report (`report-id`).
    #[serde(rename = "report-id")]
    #[serde(default)]
    pub report_id: String,

    /// Results per applied policy (`policies`).
    #[serde(rename = "policies")]
    #[serde(default)]
    pub policies: Vec<PolicyResult>,
}

/// Entry of the `policies` array: a policy with its session counts and
/// failure details.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct PolicyResult {
    /// The policy that was applied (`policy`).
    #[serde(rename = "policy")]
    pub policy: PolicyDetails,

    /// Session counts (`summary`).
    #[serde(rename = "summary")]
    pub summary: Summary,

    /// Failed sessions grouped by failure (`failure-details`).
    #[serde(rename = "failure-details")]
    #[serde(default)]
    pub failure_details: Vec<FailureDetails>,
}

/// Description of an applied policy (`policy` object).
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct PolicyDetails {
    /// Kind of policy (`policy-type`).
    #[serde(rename = "policy-type")]
    pub policy_type: PolicyType,

    /// Policy text, one entry per line or DANE TLSA record
    /// (`policy-string`).
    #[serde(rename = "policy-string")]
    #[serde(default)]
    pub policy_string: Vec<String>,

    /// Domain the policy applies to (`policy-domain`).
    #[serde(rename = "policy-domain")]
    #[serde(default)]
    pub policy_domain: String,

    /// MX host patterns listed in an MTA-STS policy (`mx-host`).
    #[serde(rename = "mx-host")]
    #[serde(default)]
    pub mx_host: Vec<String>,
}

/// Session counts for one policy (`summary` object).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Summary {
    /// Number of sessions that established TLS successfully
    /// (`total-successful-session-count`).
    #[serde(rename = "total-successful-session-count")]
    #[serde(default)]
    pub successful_sessions: u32,

    /// Number of sessions that failed (`total-failure-session-count`).
    #[serde(rename = "total-failure-session-count")]
    #[serde(default)]
    pub failed_sessions: u32,
}

/// Group of failed sessions sharing a failure type and endpoints (entry of
/// the `failure-details` array).
#[derive(Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct FailureDetails {
    /// Kind of failure (`result-type`).
    #[serde(rename = "result-type")]
    pub result_type: FailureType,

    /// IP address of the sending MTA (`sending-mta-ip`).
    #[serde(rename = "sending-mta-ip")]
    pub sending_mta_ip: Option<IpAddr>,

    /// Host name of the receiving MX (`receiving-mx-hostname`).
    #[serde(rename = "receiving-mx-hostname")]
    pub receiving_mx_hostname: Option<String>,

    /// Greeting name announced by the receiving MX (`receiving-mx-helo`).
    #[serde(rename = "receiving-mx-helo")]
    pub receiving_mx_helo: Option<String>,

    /// IP address of the receiving MX (`receiving-ip`).
    #[serde(rename = "receiving-ip")]
    pub receiving_ip: Option<IpAddr>,

    /// Number of sessions that failed this way (`failed-session-count`).
    #[serde(rename = "failed-session-count")]
    #[serde(default)]
    pub failed_session_count: u32,

    /// URI pointing to more information about the failure
    /// (`additional-information`).
    #[serde(rename = "additional-information")]
    pub additional_information: Option<String>,

    /// Free-form failure reason, such as a TLS alert (`failure-reason-code`).
    #[serde(rename = "failure-reason-code")]
    pub failure_reason_code: Option<String>,
}

/// Reporting period of a TLS report (`date-range` object).
///
/// Both ends are RFC 3339 timestamps in JSON. A timestamp that does not parse
/// becomes the Unix epoch.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct DateRange {
    /// Start of the period (`start-datetime`).
    #[serde(rename = "start-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub start_datetime: DateTime,
    /// End of the period (`end-datetime`).
    #[serde(rename = "end-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub end_datetime: DateTime,
}

/// Kind of policy (`policy-type` member).
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum PolicyType {
    /// DANE TLSA policy (`tlsa`).
    #[serde(rename = "tlsa")]
    Tlsa,
    /// MTA-STS policy (`sts`).
    #[serde(rename = "sts")]
    Sts,
    /// No policy was found (`no-policy-found`).
    #[serde(rename = "no-policy-found")]
    NoPolicyFound,
    /// An unrecognized policy type.
    #[serde(other)]
    #[default]
    Other,
}

/// Kind of TLS negotiation failure (`result-type` member, RFC 8460 section
/// 4.3).
#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureType {
    /// The receiving MX does not support STARTTLS (`starttls-not-supported`).
    #[serde(rename = "starttls-not-supported")]
    StartTlsNotSupported,
    /// The certificate does not match the host name
    /// (`certificate-host-mismatch`).
    #[serde(rename = "certificate-host-mismatch")]
    CertificateHostMismatch,
    /// The certificate has expired (`certificate-expired`).
    #[serde(rename = "certificate-expired")]
    CertificateExpired,
    /// The certificate chain is not trusted (`certificate-not-trusted`).
    #[serde(rename = "certificate-not-trusted")]
    CertificateNotTrusted,
    /// Any other validation failure (`validation-failure`).
    #[serde(rename = "validation-failure")]
    ValidationFailure,
    /// The TLSA record is invalid (`tlsa-invalid`).
    #[serde(rename = "tlsa-invalid")]
    TlsaInvalid,
    /// DNSSEC validation failed (`dnssec-invalid`).
    #[serde(rename = "dnssec-invalid")]
    DnssecInvalid,
    /// DANE is required but no DNSSEC-validated TLSA records were found
    /// (`dane-required`).
    #[serde(rename = "dane-required")]
    DaneRequired,
    /// The MTA-STS policy could not be fetched (`sts-policy-fetch-error`).
    #[serde(rename = "sts-policy-fetch-error")]
    StsPolicyFetchError,
    /// The MTA-STS policy is invalid (`sts-policy-invalid`).
    #[serde(rename = "sts-policy-invalid")]
    StsPolicyInvalid,
    /// The MTA-STS policy host failed PKIX validation
    /// (`sts-webpki-invalid`).
    #[serde(rename = "sts-webpki-invalid")]
    StsWebpkiInvalid,
    /// An unrecognized result type.
    #[serde(other)]
    #[default]
    Other,
}

fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        DateTime::parse_rfc3339(Deserialize::deserialize(deserializer)?)
            .unwrap_or_else(|| DateTime::from_timestamp(0)),
    )
}

fn serialize_datetime<S>(datetime: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&datetime.to_rfc3339())
}

impl PolicyDetails {
    /// Returns a policy of the given type for `policy_domain`, with no policy
    /// strings and no MX hosts.
    pub fn new(policy_type: PolicyType, policy_domain: impl Into<String>) -> Self {
        Self {
            policy_type,
            policy_string: vec![],
            policy_domain: policy_domain.into(),
            mx_host: vec![],
        }
    }
}

impl FailureDetails {
    /// Returns failure details of the given type with every other field
    /// unset and a zero session count.
    pub fn new(result_type: impl Into<FailureType>) -> Self {
        FailureDetails {
            result_type: result_type.into(),
            ..Default::default()
        }
    }
}

impl DateRange {
    /// Builds a date range from two timestamps in seconds since the Unix
    /// epoch.
    pub fn from_timestamps(start_datetime: i64, end_datetime: i64) -> Self {
        Self {
            start_datetime: DateTime::from_timestamp(start_datetime),
            end_datetime: DateTime::from_timestamp(end_datetime),
        }
    }
}
