/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsing of TLS reports from JSON documents and from report email
//! messages.

use super::TlsReport;
use crate::report::{ReportError, read_capped};
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::io::Cursor;
use zip::ZipArchive;

impl TlsReport {
    /// Parses an RFC 8460 JSON report document.
    ///
    /// Unknown members are ignored. Unrecognized `policy-type` and
    /// `result-type` values map to the `Other` variant.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Parse`] if the JSON is malformed or a required
    /// member is missing: `date-range`, or `policy`, `summary`, `policy-type`
    /// or `result-type` inside a `policies` entry.
    pub fn parse_json(report: &[u8]) -> Result<Self, ReportError> {
        serde_json::from_slice(report).map_err(|err| ReportError::Parse(err.to_string()))
    }

    /// Extracts and parses the TLS report attached to an RFC 5322 message.
    ///
    /// Binary parts are tried in order when their subtype (`tlsrpt+gzip`,
    /// `tlsrpt+zip`, `tlsrpt+json`) or, failing that, file extension (`.gz`,
    /// `.zip`, `.json`) identifies the report. The first part that parses is
    /// returned. `max_size` caps the decompressed size of each gzip stream or
    /// zip member.
    ///
    /// # Errors
    ///
    /// - [`ReportError::MailParse`] if `report` is not a parseable message.
    /// - [`ReportError::TooLarge`] if a decompressed report exceeds `max_size`.
    /// - [`ReportError::Decompress`] if a gzip or zip attachment is corrupt.
    /// - [`ReportError::Parse`] if every candidate part failed to parse; the
    ///   error of the last one is returned.
    /// - [`ReportError::NotFound`] if the message has no candidate part.
    pub fn parse_rfc5322(report: &[u8], max_size: usize) -> Result<Self, ReportError> {
        let message = MessageParser::new()
            .parse(report)
            .ok_or(ReportError::MailParse)?;
        let mut error = ReportError::NotFound;

        for part in &message.parts {
            match &part.body {
                PartType::Binary(report) | PartType::InlineBinary(report) => {
                    enum ReportType {
                        Json,
                        Gzip,
                        Zip,
                    }

                    let (_, ext) = part
                        .attachment_name()
                        .unwrap_or("file.none")
                        .rsplit_once('.')
                        .unwrap_or(("file", "none"));
                    let subtype = part
                        .content_type()
                        .and_then(|ct| ct.subtype())
                        .unwrap_or("none");
                    let rt = if subtype.eq_ignore_ascii_case("tlsrpt+gzip") {
                        ReportType::Gzip
                    } else if subtype.eq_ignore_ascii_case("tlsrpt+zip") {
                        ReportType::Zip
                    } else if subtype.eq_ignore_ascii_case("tlsrpt+json") {
                        ReportType::Json
                    } else if ext.eq_ignore_ascii_case("gz") {
                        ReportType::Gzip
                    } else if ext.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if ext.eq_ignore_ascii_case("json") {
                        ReportType::Json
                    } else {
                        continue;
                    };

                    match rt {
                        ReportType::Gzip => {
                            let report: &[u8] = report.as_ref();
                            let buf = read_capped(GzDecoder::new(report), 0, max_size)?;

                            match Self::parse_json(&buf) {
                                Ok(report) => return Ok(report),
                                Err(err) => {
                                    error = err;
                                }
                            }
                        }
                        ReportType::Zip => {
                            let mut archive = ZipArchive::new(Cursor::new(report))
                                .map_err(|err| ReportError::Decompress(err.to_string()))?;
                            for i in 0..archive.len() {
                                match archive.by_index(i) {
                                    Ok(mut file) => {
                                        let size_hint = file.size();
                                        let buf = read_capped(&mut file, size_hint, max_size)?;
                                        match Self::parse_json(&buf) {
                                            Ok(report) => return Ok(report),
                                            Err(err) => {
                                                error = err;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        error = ReportError::Decompress(err.to_string());
                                    }
                                }
                            }
                        }
                        ReportType::Json => match Self::parse_json(report) {
                            Ok(report) => return Ok(report),
                            Err(err) => {
                                error = err;
                            }
                        },
                    }
                }
                _ => (),
            }
        }

        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use crate::report::{
        ReportError,
        test_util::{gzip, message_with_attachment, zip},
        tlsrpt::TlsReport,
    };
    use std::{fs, path::PathBuf};

    const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;
    const REPORT: &str = concat!(
        r#"{"organization-name":"Example","report-id":"1","date-range":"#,
        r#"{"start-datetime":"2023-01-01T00:00:00Z","end-datetime":"2023-01-02T00:00:00Z"},"#,
        r#""policies":[]}"#
    );

    #[test]
    fn tlsrpt_parse() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("tlsrpt");

        for file in fs::read_dir(&path).unwrap() {
            let file = file.as_ref().unwrap().path();
            if file.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let rpt = TlsReport::parse_json(&fs::read(&file).unwrap())
                .unwrap_or_else(|err| panic!("Failed to parse {}: {:?}", file.display(), err));
            let rpt_check: TlsReport =
                serde_json::from_str(&serde_json::to_string(&rpt).unwrap()).unwrap();
            assert_eq!(rpt, rpt_check);
        }

        for file in fs::read_dir(&path).unwrap() {
            let mut file = file.as_ref().unwrap().path();
            if file.extension().is_none_or(|e| e != "eml") {
                continue;
            }
            let rpt = TlsReport::parse_rfc5322(&fs::read(&file).unwrap(), MAX_REPORT_SIZE)
                .unwrap_or_else(|err| panic!("Failed to parse {}: {:?}", file.display(), err));
            file.set_extension("json");
            let rpt_check = TlsReport::parse_json(&fs::read(&file).unwrap())
                .unwrap_or_else(|err| panic!("Failed to parse {}: {:?}", file.display(), err));
            assert_eq!(rpt, rpt_check);
        }
    }

    #[test]
    fn tlsrpt_parse_zip_forged_size() {
        let archive = zip("report.json", REPORT.as_bytes(), None, Some(u32::MAX));
        let message = message_with_attachment("application/tlsrpt+zip", "report.zip", &archive);

        assert_eq!(
            TlsReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
            Err(ReportError::TooLarge)
        );
    }

    #[test]
    fn tlsrpt_parse_zip_forged_compressed_size() {
        let archive = zip("report.json", REPORT.as_bytes(), Some(u32::MAX), None);
        let message = message_with_attachment("application/tlsrpt+zip", "report.zip", &archive);

        assert!(TlsReport::parse_rfc5322(&message, MAX_REPORT_SIZE).is_err());
    }

    #[test]
    fn tlsrpt_parse_zip_within_limit() {
        let archive = zip("report.json", REPORT.as_bytes(), None, None);
        let message = message_with_attachment("application/tlsrpt+zip", "report.zip", &archive);

        assert_eq!(
            TlsReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
            Ok(TlsReport::parse_json(REPORT.as_bytes()).unwrap())
        );
        assert_eq!(
            TlsReport::parse_rfc5322(&message, REPORT.len() - 1),
            Err(ReportError::TooLarge)
        );
    }

    #[test]
    fn tlsrpt_parse_gzip_bomb() {
        let bomb = gzip(&vec![b' '; 1024 * 1024]);
        let message = message_with_attachment("application/tlsrpt+gzip", "report.json.gz", &bomb);

        assert_eq!(
            TlsReport::parse_rfc5322(&message, 64 * 1024),
            Err(ReportError::TooLarge)
        );
    }

    #[test]
    fn tlsrpt_parse_gzip_within_limit() {
        let message = message_with_attachment(
            "application/tlsrpt+gzip",
            "report.json.gz",
            &gzip(REPORT.as_bytes()),
        );

        assert_eq!(
            TlsReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
            Ok(TlsReport::parse_json(REPORT.as_bytes()).unwrap())
        );
        assert_eq!(
            TlsReport::parse_rfc5322(&message, REPORT.len() - 1),
            Err(ReportError::TooLarge)
        );
    }
}
