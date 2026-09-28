/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsing and generation of email authentication reports (feature `report`).
//!
//! Three report formats are supported, one per submodule:
//!
//! - [`dmarc`]: DMARC aggregate reports ([`dmarc::AggregateReport`], RFC 9990).
//! - [`arf`]: Abuse Reporting Format feedback reports, including
//!   authentication failure reports ([`arf::FeedbackReport`], RFC 5965 and RFC 6591).
//! - [`tlsrpt`]: SMTP TLS reports ([`tlsrpt::TlsReport`], RFC 8460).
//!
//! Each report type has a `parse_rfc5322` function that extracts the report
//! from a complete email message, a function that parses the bare report
//! document (`parse_xml`, `parse_arf` or `parse_json`), and `write_rfc5322` and
//! `to_rfc5322` methods that wrap the report in a new email message. The
//! addressing of that message is taken from a [`ReportEnvelope`]. Parse
//! failures are reported as [`ReportError`].

pub mod arf;
pub mod dmarc;
pub mod tlsrpt;
use mail_builder::headers::{HeaderType, address::Address};
use std::{fmt::Display, io::Read};

/// Addressing and identification of a generated report message.
///
/// Passed to the `write_rfc5322` and `to_rfc5322` methods of every report
/// type. Not every report type reads every field; see the documentation of
/// each `write_rfc5322` method for the fields it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportEnvelope<'x> {
    /// Address written to the `From` header field.
    pub from: Address<'x>,
    /// Recipient addresses written to the `To` header field.
    pub to: Vec<&'x str>,
    /// Domain of the organization submitting the report.
    ///
    /// Used as the `Message-ID` host, in the default subject, the text body
    /// and the attachment file name.
    pub submitter: &'x str,
    /// Domain the report is about (TLS-RPT only).
    ///
    /// Written to the `TLS-Report-Domain` header field, the default subject
    /// and the attachment file name. DMARC and ARF reports ignore it.
    pub report_domain: &'x str,
    /// Subject of the message. When `None`, each report type writes its own
    /// default subject.
    pub subject: Option<&'x str>,
}

impl<'x> ReportEnvelope<'x> {
    pub(crate) fn to_header(&self) -> HeaderType<'x> {
        HeaderType::Address(Address::List(
            self.to.iter().map(|to| (*to).into()).collect(),
        ))
    }
}

/// Error returned when a report cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// The input is not a parseable RFC 5322 message.
    MailParse,
    /// The report document is malformed or lacks a required element. Holds
    /// the parser's error message.
    Parse(String),
    /// A gzip or zip attachment could not be decompressed. Holds the
    /// decompressor's error message.
    Decompress(String),
    /// The report exceeds the `max_size` passed to the parse function.
    TooLarge,
    /// The message contains no part that looks like a report.
    NotFound,
}

impl Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::MailParse => f.write_str("Failed to parse the report message"),
            ReportError::Parse(err) => write!(f, "Failed to parse the report: {err}"),
            ReportError::Decompress(err) => write!(f, "Failed to decompress the report: {err}"),
            ReportError::TooLarge => f.write_str("Report exceeds the maximum allowed size"),
            ReportError::NotFound => f.write_str("No report found in the message"),
        }
    }
}

impl std::error::Error for ReportError {}

const MAX_SIZE_RESERVATION: u64 = 64 * 1024;

pub(crate) fn read_capped(
    reader: impl Read,
    size_hint: u64,
    max_size: usize,
) -> Result<Vec<u8>, ReportError> {
    let max_size = max_size as u64;
    if size_hint > max_size {
        return Err(ReportError::TooLarge);
    }

    let mut buf = Vec::with_capacity(size_hint.min(MAX_SIZE_RESERVATION) as usize);
    reader
        .take(max_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| ReportError::Decompress(err.to_string()))?;

    if buf.len() as u64 > max_size {
        return Err(ReportError::TooLarge);
    }

    Ok(buf)
}

impl From<String> for ReportError {
    fn from(err: String) -> Self {
        ReportError::Parse(err)
    }
}

#[cfg(test)]
mod test {
    const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;
    use super::{ReportError, read_capped, test_util::gzip};

    #[test]
    fn read_capped_rejects_forged_size_hint() {
        assert_eq!(
            read_capped(&b"hello"[..], u32::MAX as u64, MAX_REPORT_SIZE),
            Err(ReportError::TooLarge)
        );
        assert_eq!(
            read_capped(&b"hello"[..], u64::MAX, MAX_REPORT_SIZE),
            Err(ReportError::TooLarge)
        );
    }

    #[test]
    fn read_capped_rejects_oversized_output() {
        assert_eq!(
            read_capped(&[0u8; 1024][..], 0, 1023),
            Err(ReportError::TooLarge)
        );
        assert_eq!(read_capped(&b"hello"[..], 0, 0), Err(ReportError::TooLarge));
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
            Err(ReportError::TooLarge)
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
