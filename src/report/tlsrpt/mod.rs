/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::net::IpAddr;

use mail_parser::DateTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod generate;
pub mod parse;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct TlsReport {
    #[serde(rename = "organization-name")]
    #[serde(default)]
    pub organization_name: Option<String>,

    #[serde(rename = "date-range")]
    pub date_range: DateRange,

    #[serde(rename = "contact-info")]
    #[serde(default)]
    pub contact_info: Option<String>,

    #[serde(rename = "report-id")]
    #[serde(default)]
    pub report_id: String,

    #[serde(rename = "policies")]
    #[serde(default)]
    pub policies: Vec<Policy>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Policy {
    #[serde(rename = "policy")]
    pub policy: PolicyDetails,

    #[serde(rename = "summary")]
    pub summary: Summary,

    #[serde(rename = "failure-details")]
    #[serde(default)]
    pub failure_details: Vec<FailureDetails>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct PolicyDetails {
    #[serde(rename = "policy-type")]
    pub policy_type: PolicyType,

    #[serde(rename = "policy-string")]
    #[serde(default)]
    pub policy_string: Vec<String>,

    #[serde(rename = "policy-domain")]
    #[serde(default)]
    pub policy_domain: String,

    #[serde(rename = "mx-host")]
    #[serde(default)]
    pub mx_host: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Summary {
    #[serde(rename = "total-successful-session-count")]
    #[serde(default)]
    pub total_success: u32,

    #[serde(rename = "total-failure-session-count")]
    #[serde(default)]
    pub total_failure: u32,
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct FailureDetails {
    #[serde(rename = "result-type")]
    pub result_type: ResultType,

    #[serde(rename = "sending-mta-ip")]
    pub sending_mta_ip: Option<IpAddr>,

    #[serde(rename = "receiving-mx-hostname")]
    pub receiving_mx_hostname: Option<String>,

    #[serde(rename = "receiving-mx-helo")]
    pub receiving_mx_helo: Option<String>,

    #[serde(rename = "receiving-ip")]
    pub receiving_ip: Option<IpAddr>,

    #[serde(rename = "failed-session-count")]
    #[serde(default)]
    pub failed_session_count: u32,

    #[serde(rename = "additional-information")]
    pub additional_information: Option<String>,

    #[serde(rename = "failure-reason-code")]
    pub failure_reason_code: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct DateRange {
    #[serde(rename = "start-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub start_datetime: DateTime,
    #[serde(rename = "end-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub end_datetime: DateTime,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum PolicyType {
    #[serde(rename = "tlsa")]
    Tlsa,
    #[serde(rename = "sts")]
    Sts,
    #[serde(rename = "no-policy-found")]
    NoPolicyFound,
    #[serde(other)]
    #[default]
    Other,
}

#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum ResultType {
    #[serde(rename = "starttls-not-supported")]
    StartTlsNotSupported,
    #[serde(rename = "certificate-host-mismatch")]
    CertificateHostMismatch,
    #[serde(rename = "certificate-expired")]
    CertificateExpired,
    #[serde(rename = "certificate-not-trusted")]
    CertificateNotTrusted,
    #[serde(rename = "validation-failure")]
    ValidationFailure,
    #[serde(rename = "tlsa-invalid")]
    TlsaInvalid,
    #[serde(rename = "dnssec-invalid")]
    DnssecInvalid,
    #[serde(rename = "dane-required")]
    DaneRequired,
    #[serde(rename = "sts-policy-fetch-error")]
    StsPolicyFetchError,
    #[serde(rename = "sts-policy-invalid")]
    StsPolicyInvalid,
    #[serde(rename = "sts-webpki-invalid")]
    StsWebpkiInvalid,
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
    pub fn new(result_type: impl Into<ResultType>) -> Self {
        FailureDetails {
            result_type: result_type.into(),
            ..Default::default()
        }
    }

    pub fn with_failure_reason_code(mut self, value: impl Into<String>) -> Self {
        self.failure_reason_code = Some(value.into());
        self
    }

    pub fn with_receiving_mx_hostname(mut self, value: impl Into<String>) -> Self {
        self.receiving_mx_hostname = Some(value.into());
        self
    }

    pub fn with_receiving_ip(mut self, value: IpAddr) -> Self {
        self.receiving_ip = Some(value);
        self
    }
}
