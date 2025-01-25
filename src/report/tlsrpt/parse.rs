/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use zip::ZipArchive;

use crate::report::Error;

use super::TlsReport;

impl TlsReport {
    pub fn parse_json(report: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(report).map_err(|err| Error::ReportParseError(err.to_string()))
    }

    pub fn parse_rfc5322(report: &[u8]) -> Result<Self, Error> {
        let message = MessageParser::new()
            .parse(report)
            .ok_or(Error::MailParseError)?;
        let mut error = Error::NoReportsFound;

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
                            let mut file = GzDecoder::new(report.as_ref());
                            let mut buf = Vec::new();
                            file.read_to_end(&mut buf)
                                .map_err(|err| Error::UncompressError(err.to_string()))?;

                            match Self::parse_json(&buf) {
                                Ok(report) => return Ok(report),
                                Err(err) => {
                                    error = err;
                                }
                            }
                        }
                        ReportType::Zip => {
                            let mut archive = ZipArchive::new(Cursor::new(report.as_ref()))
                                .map_err(|err| Error::UncompressError(err.to_string()))?;
                            for i in 0..archive.len() {
                                match archive.by_index(i) {
                                    Ok(mut file) => {
                                        let mut buf =
                                            Vec::with_capacity(file.compressed_size() as usize);
                                        file.read_to_end(&mut buf).map_err(|err| {
                                            Error::UncompressError(err.to_string())
                                        })?;
                                        match Self::parse_json(&buf) {
                                            Ok(report) => return Ok(report),
                                            Err(err) => {
                                                error = err;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        error = Error::UncompressError(err.to_string());
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
    use std::{fs, path::PathBuf};

    use crate::report::tlsrpt::TlsReport;

    #[test]
    fn tlsrpt_parse() {
        // Add dns entries
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
            let rpt = TlsReport::parse_rfc5322(&fs::read(&file).unwrap())
                .unwrap_or_else(|err| panic!("Failed to parse {}: {:?}", file.display(), err));
            file.set_extension("json");
            let rpt_check = TlsReport::parse_json(&fs::read(&file).unwrap())
                .unwrap_or_else(|err| panic!("Failed to parse {}: {:?}", file.display(), err));
            assert_eq!(rpt, rpt_check);
        }
    }
}
