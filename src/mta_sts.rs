/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsers for the MTA-STS and SMTP TLS Reporting DNS TXT records.
//!
//! - [`MtaStsRecord`]: the `_mta-sts` TXT record of RFC 8461 Section 3.1,
//!   which announces that a domain publishes an MTA-STS policy.
//! - [`TlsRptRecord`]: the `_smtp._tls` TXT record of RFC 8460 Section 3,
//!   which lists where TLS failure reports are sent.
//!
//! Both are parsed with [`TxtRecordParser::parse`] and fetched through
//! [`MessageAuthenticator::txt_lookup`](crate::MessageAuthenticator::txt_lookup).
//! Fetching the MTA-STS policy file over HTTPS is out of scope.

use crate::{
    DnsError,
    parse::{TagParser, TxtRecordParser, V},
};
use serde::{Deserialize, Serialize};

/// An MTA-STS TXT record (RFC 8461 Section 3.1), published at
/// `_mta-sts.<domain>`.
///
/// Parsing requires a `v=STSv1` tag and an `id` tag; other tags are ignored.
#[derive(Debug, PartialEq, Eq)]
pub struct MtaStsRecord {
    /// Policy identifier (`id=` tag): an opaque string of up to 32
    /// alphanumeric characters that changes whenever the policy changes.
    pub id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
/// An SMTP TLS Reporting TXT record (RFC 8460 Section 3), published at
/// `_smtp._tls.<domain>`.
///
/// Parsing requires the `v=TLSRPTv1` tag first and at least one `mailto:` or
/// `https:` URI in `rua`.
pub struct TlsRptRecord {
    /// Aggregate report destinations (`rua=` tag), in record order. URIs with
    /// other schemes are ignored.
    pub rua: Vec<ReportUri>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
/// A TLS report destination from the `rua` tag of a [`TlsRptRecord`].
pub enum ReportUri {
    /// A `mailto:` destination: the email address, without the scheme.
    Mail(String),
    /// An `https:` destination: the full URL, including the scheme.
    Http(String),
}

const ID: u64 = (b'i' as u64) | ((b'd' as u64) << 8);
const RUA: u64 = (b'r' as u64) | ((b'u' as u64) << 8) | ((b'a' as u64) << 16);

const MAILTO: u64 = (b'm' as u64)
    | ((b'a' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'l' as u64) << 24)
    | ((b't' as u64) << 32)
    | ((b'o' as u64) << 40);
const HTTPS: u64 = (b'h' as u64)
    | ((b't' as u64) << 8)
    | ((b't' as u64) << 16)
    | ((b'p' as u64) << 24)
    | ((b's' as u64) << 32);

impl TxtRecordParser for MtaStsRecord {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> crate::Result<Self> {
        let mut record = record.iter();
        let mut id = None;
        let mut has_version = false;

        while let Some(key) = record.key() {
            match key {
                V => {
                    if !record.match_bytes(b"STSv1") || !record.seek_tag_end() {
                        return Err(crate::Error::Dns(DnsError::InvalidRecordType));
                    }
                    has_version = true;
                }
                ID => {
                    id = record.text(false).into();
                }
                _ => {
                    record.ignore();
                }
            }
        }

        if let Some(id) = id
            && has_version
        {
            return Ok(MtaStsRecord { id });
        }
        Err(crate::Error::Dns(DnsError::InvalidRecordType))
    }
}

impl TxtRecordParser for TlsRptRecord {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> crate::Result<Self> {
        let mut record = record.iter();

        if record.key().unwrap_or(0) != V
            || !record.match_bytes(b"TLSRPTv1")
            || !record.seek_tag_end()
        {
            return Err(crate::Error::Dns(DnsError::InvalidRecordType));
        }

        let mut rua = Vec::new();

        while let Some(key) = record.key() {
            match key {
                RUA => loop {
                    match record.flag_value() {
                        (MAILTO, b':') => {
                            let mail_to = record.uri(Vec::new());
                            if !mail_to.is_empty() {
                                rua.push(ReportUri::Mail(mail_to));
                            }
                        }
                        (HTTPS, b':') => {
                            let mut url = Vec::with_capacity(20);
                            url.extend_from_slice(b"https:");
                            let url = record.uri(url);
                            if !url.is_empty() {
                                rua.push(ReportUri::Http(url));
                            }
                        }
                        _ => {
                            record.ignore();
                            break;
                        }
                    }
                },
                _ => {
                    record.ignore();
                }
            }
        }

        if !rua.is_empty() {
            Ok(TlsRptRecord { rua })
        } else {
            Err(crate::Error::Dns(DnsError::InvalidRecordType))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mta_sts::{MtaStsRecord, ReportUri, TlsRptRecord},
        parse::TxtRecordParser,
    };

    #[test]
    fn mta_sts_record_parse() {
        for (mta_sts, expected_mta_sts) in [
            (
                "v=STSv1; id=20160831085700Z;",
                MtaStsRecord {
                    id: "20160831085700Z".to_string(),
                },
            ),
            (
                "v=STSv1; id=20190429T010101",
                MtaStsRecord {
                    id: "20190429T010101".to_string(),
                },
            ),
        ] {
            assert_eq!(
                MtaStsRecord::parse(mta_sts.as_bytes()).unwrap(),
                expected_mta_sts
            );
        }
    }

    #[test]
    fn tlsrpt_parse() {
        for (tls_rpt, expected_tls_rpt) in [
            (
                "v=TLSRPTv1;rua=mailto:reports@example.com",
                TlsRptRecord {
                    rua: vec![ReportUri::Mail("reports@example.com".to_string())],
                },
            ),
            (
                "v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt",
                TlsRptRecord {
                    rua: vec![ReportUri::Http(
                        "https://reporting.example.com/v1/tlsrpt".to_string(),
                    )],
                },
            ),
            (
                "v=TLSRPTv1; rua=mailto:tlsrpt@mydomain.com,https://tlsrpt.mydomain.com/v1",
                TlsRptRecord {
                    rua: vec![
                        ReportUri::Mail("tlsrpt@mydomain.com".to_string()),
                        ReportUri::Http("https://tlsrpt.mydomain.com/v1".to_string()),
                    ],
                },
            ),
            (
                "v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt?id=1",
                TlsRptRecord {
                    rua: vec![ReportUri::Http(
                        "https://reporting.example.com/v1/tlsrpt?id=1".to_string(),
                    )],
                },
            ),
            (
                "v=TLSRPTv1; rua=https://r.example.com/tlsrpt?id=abc&token=xyz",
                TlsRptRecord {
                    rua: vec![ReportUri::Http(
                        "https://r.example.com/tlsrpt?id=abc&token=xyz".to_string(),
                    )],
                },
            ),
            (
                "v=TLSRPTv1; rua=mailto:a@example.com , mailto:b=c@example.com ;",
                TlsRptRecord {
                    rua: vec![
                        ReportUri::Mail("a@example.com".to_string()),
                        ReportUri::Mail("b=c@example.com".to_string()),
                    ],
                },
            ),
        ] {
            assert_eq!(
                TlsRptRecord::parse(tls_rpt.as_bytes()).unwrap(),
                expected_tls_rpt
            );
        }
    }
}
