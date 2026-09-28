/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DMARC aggregate reports (RFC 9990).
//!
//! [`AggregateReport`] models the XML `feedback` document. Reports are parsed
//! with [`AggregateReport::parse_rfc5322`] or [`AggregateReport::parse_xml`];
//! legacy reports in the RFC 7489 Appendix C format still parse. Reports are
//! built as struct literals, with [`Record`] and [`PolicyPublished`] filled
//! from verification results by [`Record::with_dkim_output`] and the other
//! `with_*_output` helpers and [`PolicyPublished::from_record`], and written with
//! [`AggregateReport::write_rfc5322`] or [`AggregateReport::to_xml`].
//!
//! Field documentation names the XML element each field maps to.

use crate::dmarc::{Alignment, Policy};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
    str::FromStr,
};

mod builder;
mod generate;
mod parse;

/// Reporting period covered by an aggregate report (`date_range` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DateRange {
    /// Start of the period in seconds since the Unix epoch (`begin`).
    pub begin: u64,
    /// End of the period in seconds since the Unix epoch (`end`).
    pub end: u64,
}

/// Information about the reporting organization (`report_metadata` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Name of the reporting organization (`org_name`).
    pub org_name: String,
    /// Contact email address of the reporting organization (`email`).
    pub email: String,
    /// Additional contact details (`extra_contact_info`).
    pub extra_contact_info: Option<String>,
    /// Unique identifier of the report within the reporting organization
    /// (`report_id`).
    pub report_id: String,
    /// Reporting period (`date_range`).
    pub date_range: DateRange,
    /// Errors encountered while generating the report, one per `error`
    /// element.
    pub errors: Vec<String>,
    /// Name and version of the software that generated the report
    /// (`generator`, RFC 9990 only).
    #[serde(default)]
    pub generator: Option<String>,
}

/// Policy applied to the messages of a row (`disposition` element of
/// `policy_evaluated`).
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Disposition {
    /// No action was taken (`none`).
    None,
    /// The messages passed DMARC (`pass`).
    Pass,
    /// The messages were quarantined (`quarantine`).
    Quarantine,
    /// The messages were rejected (`reject`).
    Reject,
    /// The element was absent or had an unrecognized value. Written as `none`.
    #[default]
    Unspecified,
}

/// DMARC policy published by the domain owner (`policy_published` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyPublished {
    /// Domain whose DMARC record was applied (`domain`). This is the Report
    /// Domain of the generated report message.
    pub domain: String,
    /// Version of the published policy (`version_published`). Not written by
    /// [`AggregateReport::to_xml`].
    #[serde(default, deserialize_with = "deserialize_version")]
    pub version_published: Option<ReportVersion>,
    /// DKIM identifier alignment mode (`adkim`). `None` when the element is
    /// absent or unrecognized.
    pub adkim: Option<Alignment>,
    /// SPF identifier alignment mode (`aspf`). `None` when the element is
    /// absent or unrecognized.
    pub aspf: Option<Alignment>,
    /// Policy for the domain (`p`). [`Policy::Unspecified`] when the element
    /// is absent or unrecognized.
    pub p: Policy,
    /// Policy for subdomains (`sp`). [`Policy::Unspecified`] when the element
    /// is absent or unrecognized; not written in that case.
    pub sp: Policy,
    /// Policy for non-existent subdomains (`np`, RFC 9990 only).
    /// [`Policy::Unspecified`] when the element is absent or unrecognized;
    /// not written in that case.
    #[serde(default)]
    pub np: Policy,
    /// Whether the policy is in test mode (`testing`, `y` or `n`), from the
    /// DMARC `t` tag.
    pub testing: bool,
    /// Method used to find the DMARC record (`discovery_method`, RFC 9990
    /// only).
    #[serde(default)]
    pub discovery_method: Discovery,
    /// Failure reporting options, verbatim (`fo`).
    pub fo: Option<String>,
}

/// Method used to discover the DMARC policy record (`discovery_method`
/// element).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Discovery {
    /// Public Suffix List lookup, as in RFC 7489 (`psl`).
    Psl,
    /// DNS tree walk, as in RFC 9989 (`treewalk`).
    Treewalk,
    /// The element was absent or had an unrecognized value. Not written.
    #[default]
    Unspecified,
}

/// DMARC-aligned result of one mechanism (`dkim` and `spf` elements of
/// `policy_evaluated`).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DmarcStatus {
    /// The mechanism passed and was aligned (`pass`).
    Pass,
    /// The mechanism failed or was not aligned (`fail`).
    Fail,
    /// The element was absent or had an unrecognized value. Written as an
    /// empty element.
    #[default]
    Unspecified,
}

/// Reason the applied disposition differs from the published policy (`type`
/// element of `reason`).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyOverride {
    /// A local policy overrode the published one (`local_policy`).
    LocalPolicy,
    /// The message came from a mailing list (`mailing_list`).
    MailingList,
    /// The policy was in test mode (`policy_test_mode`).
    PolicyTestMode,
    /// The message came from a trusted forwarder (`trusted_forwarder`).
    TrustedForwarder,
    /// `other`, or a value that is absent or unrecognized, such as the RFC
    /// 7489 `forwarded` and `sampled_out` types.
    #[default]
    Other,
}

/// One policy override reason (`reason` element of `policy_evaluated`).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyOverrideReason {
    /// Kind of override (`type`).
    pub kind: PolicyOverride,
    /// Free-form explanation (`comment`).
    pub comment: Option<String>,
}

/// Result of applying the DMARC policy to a row (`policy_evaluated` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    /// Action taken on the messages (`disposition`).
    pub disposition: Disposition,
    /// DMARC-aligned DKIM result (`dkim`).
    pub dkim: DmarcStatus,
    /// DMARC-aligned SPF result (`spf`).
    pub spf: DmarcStatus,
    /// Reasons the disposition differs from the published policy, one per
    /// `reason` element.
    pub reason: Vec<PolicyOverrideReason>,
}

/// Source and count of the messages of a record (`row` element).
#[derive(Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// IP address the messages came from (`source_ip`). `None` when the
    /// element is absent or not a valid address.
    pub source_ip: Option<IpAddr>,
    /// Number of messages this record covers (`count`).
    pub count: u32,
    /// Policy evaluation result (`policy_evaluated`).
    pub policy_evaluated: PolicyEvaluated,
}

/// Report extension declared with an `extension` element inside an
/// `extensions` element.
///
/// Only the `name` and `definition` attributes are kept; the extension content
/// is skipped. Extensions are not written by [`AggregateReport::to_xml`].
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Extension {
    /// Extension name (`name` attribute).
    pub name: String,
    /// URI of the extension definition (`definition` attribute).
    pub definition: String,
}

/// Identifiers of the messages of a record (`identifiers` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identifiers {
    /// Domain of the envelope recipient (`envelope_to`).
    pub envelope_to: Option<String>,
    /// Domain of the `MAIL FROM` envelope sender (`envelope_from`).
    pub envelope_from: String,
    /// Domain of the `From` header field (`header_from`).
    pub header_from: String,
}

/// Result of verifying one DKIM signature (`result` element of an
/// `auth_results/dkim` element).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DkimStatus {
    /// The message was not signed (`none`). Also used when the element is
    /// absent or has an unrecognized value.
    #[default]
    None,
    /// The signature verified (`pass`).
    Pass,
    /// The signature did not verify (`fail`).
    Fail,
    /// The signature verified but was not accepted by local policy (`policy`).
    Policy,
    /// The signature could not be processed (`neutral`).
    Neutral,
    /// A transient error, such as a DNS timeout, prevented verification
    /// (`temperror`).
    TempError,
    /// A permanent error, such as a malformed key record, prevented
    /// verification (`permerror`).
    PermError,
}

/// Raw result of one DKIM signature (`dkim` element of `auth_results`).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DkimAuthResult {
    /// Signing domain, from the signature's `d=` tag (`domain`).
    pub domain: String,
    /// Selector, from the signature's `s=` tag (`selector`).
    pub selector: String,
    /// Verification result (`result`).
    pub result: DkimStatus,
    /// Human-readable detail about the result (`human_result`).
    pub human_result: Option<String>,
}

/// Identity checked by SPF (`scope` element of an `auth_results/spf`
/// element).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpfScope {
    /// The `HELO` identity (`helo`, RFC 7489 only).
    Helo,
    /// The `MAIL FROM` identity (`mfrom`).
    MailFrom,
    /// The element was absent or had an unrecognized value. Not written by
    /// [`AggregateReport::to_xml`].
    #[default]
    Unspecified,
}

/// Result of an SPF check (`result` element of an `auth_results/spf`
/// element).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpfStatus {
    /// No SPF record was found (`none`). Also used when the element is absent
    /// or has an unrecognized value.
    #[default]
    None,
    /// The record makes no assertion about the sender (`neutral`).
    Neutral,
    /// The sender is authorized (`pass`).
    Pass,
    /// The sender is not authorized (`fail`).
    Fail,
    /// The sender is probably not authorized (`softfail`).
    SoftFail,
    /// A transient error, such as a DNS timeout, prevented the check
    /// (`temperror`).
    TempError,
    /// A permanent error, such as a malformed record, prevented the check
    /// (`permerror`).
    PermError,
}

/// Raw result of one SPF check (`spf` element of `auth_results`).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SpfAuthResult {
    /// Domain that was checked (`domain`).
    pub domain: String,
    /// Identity that was checked (`scope`).
    pub scope: SpfScope,
    /// Check result (`result`).
    pub result: SpfStatus,
    /// Human-readable detail about the result (`human_result`).
    pub human_result: Option<String>,
}

/// Raw authentication results of a record, before DMARC alignment
/// (`auth_results` element).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthResults {
    /// DKIM results, one per `dkim` element.
    pub dkim: Vec<DkimAuthResult>,
    /// SPF results, one per `spf` element.
    ///
    /// Parsing keeps every element. [`AggregateReport::to_xml`] writes at most
    /// one: the first result whose scope is not [`SpfScope::Helo`].
    pub spf: Vec<SpfAuthResult>,
}

/// Results for one group of messages sharing a source and identifiers
/// (`record` element).
///
/// Build it from verification outputs with [`Record::with_dkim_output`],
/// [`Record::with_spf_output`], [`Record::with_dmarc_output`],
/// [`Record::with_dkim2_output`] and `with_arc_output` (feature `arc`).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Record {
    /// Message source, count and policy evaluation (`row`).
    pub row: Row,
    /// Message identifiers (`identifiers`).
    pub identifiers: Identifiers,
    /// Raw DKIM and SPF results (`auth_results`).
    pub auth_results: AuthResults,
    /// Record-level extensions (`extensions`). Not written by
    /// [`AggregateReport::to_xml`].
    pub extensions: Vec<Extension>,
}

/// DMARC aggregate report (`feedback` element), as defined in RFC 9990.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AggregateReport {
    /// Report format version (`version`). `None` when the element is absent
    /// or holds a version other than 1.0; not written in that case.
    #[serde(default, deserialize_with = "deserialize_version")]
    pub version: Option<ReportVersion>,
    /// Reporting organization and period (`report_metadata`).
    pub report_metadata: ReportMetadata,
    /// Policy published by the domain owner (`policy_published`).
    pub policy_published: PolicyPublished,
    /// Per-source results, one per `record` element.
    pub records: Vec<Record>,
    /// Report-level extensions (`extensions`). Not written by
    /// [`AggregateReport::to_xml`].
    pub extensions: Vec<Extension>,
}

/// Aggregate report format version (`version` and `version_published`
/// elements).
///
/// Only version 1.0 is known. Parsing any other version, from XML or with
/// serde, yields `None` in the enclosing `Option`. Serde serializes
/// [`ReportVersion::V1`] as the number `1.0` and accepts `1`, `1.0` or the
/// string `"1.0"`.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ReportVersion {
    /// Version 1.0.
    V1,
}

impl ReportVersion {
    /// Returns the version as written in XML, such as `"1.0"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportVersion::V1 => "1.0",
        }
    }

    fn from_number(value: f64) -> Option<Self> {
        (value == 1.0).then_some(ReportVersion::V1)
    }
}

impl Display for ReportVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReportVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.trim()
            .parse::<f64>()
            .ok()
            .and_then(ReportVersion::from_number)
            .ok_or(())
    }
}

impl Serialize for ReportVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ReportVersion::V1 => serializer.serialize_f32(1.0),
        }
    }
}

struct VersionVisitor;

impl<'de> Visitor<'de> for VersionVisitor {
    type Value = Option<ReportVersion>;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a report version number")
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(ReportVersion::from_number(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok((value == 1).then_some(ReportVersion::V1))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok((value == 1).then_some(ReportVersion::V1))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.parse().ok())
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

fn deserialize_version<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ReportVersion>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_any(VersionVisitor)
    } else {
        Ok(Option::<f32>::deserialize(deserializer)?
            .and_then(|value| ReportVersion::from_number(value.into())))
    }
}

impl<'de> Deserialize<'de> for ReportVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = if deserializer.is_human_readable() {
            deserializer.deserialize_any(VersionVisitor)?
        } else {
            ReportVersion::from_number(f32::deserialize(deserializer)?.into())
        };
        version.ok_or_else(|| de::Error::custom("unsupported report version"))
    }
}
