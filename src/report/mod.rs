/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod arf;
pub mod dmarc;
pub mod tlsrpt;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::Read, net::IpAddr};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct DateRange {
    pub begin: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
    pub error: Vec<String>,
    #[serde(default)]
    pub generator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Alignment {
    Relaxed,
    Strict,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct PolicyPublished {
    pub domain: String,
    pub version_published: Option<f32>,
    pub adkim: Alignment,
    pub aspf: Alignment,
    pub p: Disposition,
    pub sp: Disposition,
    #[serde(default)]
    pub np: Disposition,
    pub testing: bool,
    #[serde(default)]
    pub discovery_method: Discovery,
    pub fo: Option<String>,
}

impl Eq for PolicyPublished {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Discovery {
    Psl,
    Treewalk,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum DmarcResult {
    Pass,
    Fail,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum PolicyOverride {
    LocalPolicy,
    MailingList,
    PolicyTestMode,
    TrustedForwarder,
    #[default]
    Other,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct PolicyOverrideReason {
    pub type_: PolicyOverride,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct PolicyEvaluated {
    pub disposition: ActionDisposition,
    pub dkim: DmarcResult,
    pub spf: DmarcResult,
    pub reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Row {
    pub source_ip: Option<IpAddr>,
    pub count: u32,
    pub policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Extension {
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Identifier {
    pub envelope_to: Option<String>,
    pub envelope_from: String,
    pub header_from: String,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct DKIMAuthResult {
    pub domain: String,
    pub selector: String,
    pub result: DkimResult,
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum SPFDomainScope {
    Helo,
    MailFrom,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct SPFAuthResult {
    pub domain: String,
    pub scope: SPFDomainScope,
    pub result: SpfResult,
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct AuthResult {
    pub dkim: Vec<DKIMAuthResult>,
    pub spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifier,
    pub auth_results: AuthResult,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Report {
    pub version: f32,
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub record: Vec<Record>,
    pub extensions: Vec<Extension>,
}

impl Eq for Report {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MailParseError,
    ReportParseError(String),
    UncompressError(String),
    ReportTooLarge,
    NoReportsFound,
}

const MAX_SIZE_RESERVATION: u64 = 64 * 1024;

pub(crate) fn read_capped(
    reader: impl Read,
    size_hint: u64,
    max_size: usize,
) -> Result<Vec<u8>, Error> {
    let max_size = max_size as u64;
    if size_hint > max_size {
        return Err(Error::ReportTooLarge);
    }

    let mut buf = Vec::with_capacity(size_hint.min(MAX_SIZE_RESERVATION) as usize);
    reader
        .take(max_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| Error::UncompressError(err.to_string()))?;

    if buf.len() as u64 > max_size {
        return Err(Error::ReportTooLarge);
    }

    Ok(buf)
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::ReportParseError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Feedback<'x> {
    pub feedback_type: FeedbackType,
    pub arrival_date: Option<i64>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub authentication_results: Vec<Cow<'x, str>>,
    pub incidents: u32,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_envelope_id: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_mail_from: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub original_rcpt_to: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reported_domain: Vec<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reported_uri: Vec<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub reporting_mta: Option<Cow<'x, str>>,
    pub source_ip: Option<IpAddr>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub user_agent: Option<Cow<'x, str>>,
    pub version: u32,
    pub source_port: u32,

    // Auth-Failure keys
    pub auth_failure: AuthFailureType,
    pub delivery_result: DeliveryResult,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_adsp_dns: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_canonicalized_body: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_canonicalized_header: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_domain: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_identity: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_selector: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub dkim_selector_dns: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub spf_dns: Option<Cow<'x, str>>,
    pub identity_alignment: IdentityAlignment,

    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub message: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub headers: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum IdentityAlignment {
    None,
    Spf,
    Dkim,
    DkimSpf,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
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
                crate::Error::Dkim(crate::dkim::DkimError::FailedBodyHashMatch) => {
                    AuthFailureType::BodyHash
                }
                #[cfg(feature = "arc")]
                crate::Error::Arc(crate::arc::ArcError::FailedBodyHashMatch) => {
                    AuthFailureType::BodyHash
                }
                crate::Error::Dkim(crate::dkim::DkimError::RevokedPublicKey) => {
                    AuthFailureType::Revoked
                }
                _ => AuthFailureType::Signature,
            },
            crate::DkimResult::Pass | crate::DkimResult::None => AuthFailureType::Signature,
        }
    }
}

#[cfg(test)]
mod test {
    const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;
    use super::{Error, read_capped, test_util::gzip};

    #[test]
    fn read_capped_rejects_forged_size_hint() {
        assert_eq!(
            read_capped(&b"hello"[..], u32::MAX as u64, MAX_REPORT_SIZE),
            Err(Error::ReportTooLarge)
        );
        assert_eq!(
            read_capped(&b"hello"[..], u64::MAX, MAX_REPORT_SIZE),
            Err(Error::ReportTooLarge)
        );
    }

    #[test]
    fn read_capped_rejects_oversized_output() {
        assert_eq!(
            read_capped(&[0u8; 1024][..], 0, 1023),
            Err(Error::ReportTooLarge)
        );
        assert_eq!(read_capped(&b"hello"[..], 0, 0), Err(Error::ReportTooLarge));
    }

    #[test]
    fn read_capped_accepts_within_limit() {
        assert_eq!(read_capped(&b"hello"[..], 5, 5), Ok(b"hello".to_vec()));
        assert_eq!(read_capped(&b""[..], 0, 0), Ok(Vec::new()));
        assert_eq!(
            read_capped(&b"hello"[..], u32::MAX as u64, u32::MAX as usize),
            Ok(b"hello".to_vec())
        );
    }

    #[test]
    fn read_capped_bounds_decompressed_output() {
        let bomb = gzip(&vec![b'a'; 1024 * 1024]);
        assert!(bomb.len() < 8192);

        assert_eq!(
            read_capped(flate2::read::GzDecoder::new(&bomb[..]), 0, 64 * 1024),
            Err(Error::ReportTooLarge)
        );
        assert_eq!(
            read_capped(flate2::read::GzDecoder::new(&bomb[..]), 0, MAX_REPORT_SIZE)
                .map(|buf| buf.len()),
            Ok(1024 * 1024)
        );
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use flate2::{Compression, Crc, write::GzEncoder};
    use mail_builder::{
        MessageBuilder,
        mime::{BodyPart, MimePart},
    };
    use std::io::Write;

    pub(crate) fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    pub(crate) fn zip(
        name: &str,
        data: &[u8],
        compressed_size: Option<u32>,
        uncompressed_size: Option<u32>,
    ) -> Vec<u8> {
        let mut crc = Crc::new();
        crc.update(data);
        let crc = crc.sum();
        let compressed_size = compressed_size.unwrap_or(data.len() as u32);
        let uncompressed_size = uncompressed_size.unwrap_or(data.len() as u32);
        let name = name.as_bytes();

        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        let central_offset = out.len() as u32;
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name);

        let central_size = out.len() as u32 - central_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());

        out
    }

    pub(crate) fn message_with_attachment(
        content_type: &str,
        file_name: &str,
        contents: &[u8],
    ) -> Vec<u8> {
        MessageBuilder::new()
            .from(("Mail Delivery System", "postmaster@example.org"))
            .to("postmaster@example.com")
            .subject("Report Domain: example.com")
            .body(MimePart::new(
                "multipart/report",
                BodyPart::Multipart(vec![
                    MimePart::new("text/plain", BodyPart::Text("Report attached.".into())),
                    MimePart::new(content_type, BodyPart::Binary(contents.into()))
                        .attachment(file_name),
                ]),
            ))
            .write_to_vec()
            .unwrap()
    }
}
