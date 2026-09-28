/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Abuse Reporting Format feedback reports.
//!
//! [`FeedbackReport`] models the machine-readable `message/feedback-report`
//! part defined by RFC 5965, extended with the authentication failure fields
//! of RFC 6591 and the `not-spam` feedback type of RFC 6430. RFC 6650 covers
//! when to send these reports. Redacting the original message as described
//! in RFC 6590 is up to the caller.
//! Reports are parsed with [`FeedbackReport::parse_rfc5322`] or
//! [`FeedbackReport::parse_arf`] and written with
//! [`FeedbackReport::write_rfc5322`] or [`FeedbackReport::to_arf`].
//!
//! Field documentation names the ARF field each field maps to.

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, net::IpAddr};

mod builder;
mod generate;
mod parse;

/// ARF feedback report (RFC 5965), including the authentication failure
/// fields of RFC 6591.
///
/// String fields borrow from the parsed message; call
/// [`into_owned`](Self::into_owned) to detach them. Build a new report with
/// [`FeedbackReport::new`] and struct update syntax.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct FeedbackReport<'x> {
    /// Kind of feedback (`Feedback-Type`).
    pub feedback_type: FeedbackType,
    /// When the original message was received, in seconds since the Unix
    /// epoch (`Arrival-Date`, or the legacy `Received-Date`).
    pub arrival_date: Option<i64>,
    /// Authentication results for the original message, one per
    /// `Authentication-Results` field.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub authentication_results: Vec<Cow<'x, str>>,
    /// Number of incidents the report represents (`Incidents`). Parsing
    /// defaults to 1; the field is written only when greater than 1.
    pub incidents: u32,
    /// Envelope ID of the original message (`Original-Envelope-Id`).
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_envelope_id: Option<Cow<'x, str>>,
    /// Envelope sender of the original message (`Original-Mail-From`).
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_mail_from: Option<Cow<'x, str>>,
    /// Envelope recipient of the original message (`Original-Rcpt-To`).
    /// When the field repeats, the last value is kept.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_rcpt_to: Option<Cow<'x, str>>,
    /// Domains the report concerns, one per `Reported-Domain` field.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reported_domains: Vec<Cow<'x, str>>,
    /// URIs the report concerns, one per `Reported-URI` field.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reported_uris: Vec<Cow<'x, str>>,
    /// Host name of the MTA generating the report (`Reporting-MTA`), without
    /// the `dns;` type prefix, which is added when writing.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reporting_mta: Option<Cow<'x, str>>,
    /// IP address the original message came from (`Source-IP`).
    pub source_ip: Option<IpAddr>,
    /// Software that generated the report (`User-Agent`).
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub user_agent: Option<Cow<'x, str>>,
    /// ARF version (`Version`), 1 for RFC 5965. Parsing yields 0 when the
    /// field is absent or not a number.
    pub version: u32,
    /// Source TCP port of the original message (`Source-Port`, RFC 6692).
    /// 0 when unknown; the field is written only when nonzero.
    pub source_port: u16,
    /// Kind of authentication failure (`Auth-Failure`, RFC 6591).
    /// Auth-failure reports only.
    pub auth_failure: AuthFailureType,
    /// What the receiver did with the original message (`Delivery-Result`,
    /// RFC 6591). Auth-failure reports only.
    pub delivery_result: DeliveryResult,
    /// Retrieved ADSP record (`DKIM-ADSP-DNS`, RFC 6591). Auth-failure
    /// reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_adsp_dns: Option<Cow<'x, str>>,
    /// Base64 of the canonicalized body the verifier hashed
    /// (`DKIM-Canonicalized-Body`, RFC 6591). Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_canonicalized_body: Option<Cow<'x, str>>,
    /// Base64 of the canonicalized header the verifier hashed
    /// (`DKIM-Canonicalized-Header`, RFC 6591). Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_canonicalized_header: Option<Cow<'x, str>>,
    /// Signing domain of the failed signature (`DKIM-Domain`, RFC 6591).
    /// Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_domain: Option<Cow<'x, str>>,
    /// Agent or user identifier of the failed signature (`DKIM-Identity`, RFC
    /// 6591). Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_identity: Option<Cow<'x, str>>,
    /// Selector of the failed signature (`DKIM-Selector`, RFC 6591).
    /// Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_selector: Option<Cow<'x, str>>,
    /// Retrieved DKIM key record (`DKIM-Selector-DNS`, RFC 6591).
    /// Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_selector_dns: Option<Cow<'x, str>>,
    /// Retrieved SPF record (`SPF-DNS`, RFC 6591). Auth-failure reports only.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub spf_dns: Option<Cow<'x, str>>,
    /// Which mechanisms produced an aligned identifier
    /// (`Identity-Alignment`, DMARC failure reports). Auth-failure reports
    /// only.
    pub identity_alignment: IdentityAlignment,

    /// Full original message, from the `message/rfc822` part.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub message: Option<Cow<'x, str>>,
    /// Header section of the original message, from the
    /// `text/rfc822-headers` part. Written only when `message` is `None`.
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub headers: Option<Cow<'x, str>>,
}

/// Kind of authentication failure (`Auth-Failure` field, RFC 6591).
#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum AuthFailureType {
    /// The message failed an ADSP check (`adsp`).
    Adsp,
    /// The DKIM body hash did not match (`bodyhash`).
    BodyHash,
    /// The DKIM key has been revoked (`revoked`).
    Revoked,
    /// The DKIM signature did not verify (`signature`).
    Signature,
    /// The message failed an SPF check (`spf`).
    Spf,
    /// The message failed DMARC (`dmarc`).
    Dmarc,
    /// The field was absent or had an unrecognized value. Not written.
    #[default]
    Unspecified,
}

/// Mechanisms that produced a DMARC-aligned identifier
/// (`Identity-Alignment` field).
#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum IdentityAlignment {
    /// Neither mechanism produced an aligned identifier (`none`).
    None,
    /// Only SPF produced an aligned identifier (`spf`).
    Spf,
    /// Only DKIM produced an aligned identifier (`dkim`).
    Dkim,
    /// Both mechanisms produced an aligned identifier (`dkim, spf`).
    DkimSpf,
    /// The field was absent or had no recognized value. Not written.
    #[default]
    Unspecified,
}

/// What the receiver did with the original message (`Delivery-Result`
/// field, RFC 6591).
#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum DeliveryResult {
    /// Delivered to the recipient (`delivered`).
    Delivered,
    /// Delivered to a spam folder (`spam`).
    Spam,
    /// Not delivered because of local policy (`policy`).
    Policy,
    /// Rejected (`reject`).
    Reject,
    /// Any other outcome (`other`).
    Other,
    /// The field was absent or had an unrecognized value. Not written.
    #[default]
    Unspecified,
}

/// Kind of feedback (`Feedback-Type` field, RFC 5965).
#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum FeedbackType {
    /// Unsolicited or abusive email (`abuse`).
    Abuse,
    /// Authentication failure report, RFC 6591 (`auth-failure`).
    AuthFailure,
    /// Fraudulent email such as phishing (`fraud`).
    Fraud,
    /// The message was wrongly classified as spam, RFC 6430 (`not-spam`).
    NotSpam,
    /// Any other feedback (`other`). This is the `Default` value; unknown
    /// `Feedback-Type` values are rejected rather than mapped here.
    #[default]
    Other,
    /// The message contained a virus (`virus`).
    Virus,
}

impl From<&crate::DkimResult> for AuthFailureType {
    fn from(value: &crate::DkimResult) -> Self {
        match value {
            crate::DkimResult::Neutral(err)
            | crate::DkimResult::Fail(err)
            | crate::DkimResult::PermError(err)
            | crate::DkimResult::TempError(err) => match err {
                crate::Error::Dkim(crate::dkim::DkimError::BodyHashMismatch) => {
                    AuthFailureType::BodyHash
                }
                #[cfg(feature = "arc")]
                crate::Error::Arc(crate::arc::ArcError::BodyHashMismatch) => {
                    AuthFailureType::BodyHash
                }
                crate::Error::Dkim(crate::dkim::DkimError::PublicKeyRevoked) => {
                    AuthFailureType::Revoked
                }
                _ => AuthFailureType::Signature,
            },
            crate::DkimResult::Pass | crate::DkimResult::None => AuthFailureType::Signature,
        }
    }
}
