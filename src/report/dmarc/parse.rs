/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsing of DMARC aggregate reports from XML documents and from report
//! email messages.

use crate::{
    dmarc::{Alignment, Policy},
    report::{
        ReportError,
        dmarc::{
            AggregateReport, AuthResults, DateRange, Discovery, Disposition, DkimAuthResult,
            DkimStatus, DmarcStatus, Extension, Identifiers, PolicyEvaluated, PolicyOverride,
            PolicyOverrideReason, PolicyPublished, Record, ReportMetadata, ReportVersion, Row,
            SpfAuthResult, SpfScope, SpfStatus,
        },
        read_capped,
    },
};
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::borrow::Cow;
use std::io::{BufRead, Cursor};
use std::net::IpAddr;
use std::str::FromStr;

impl AggregateReport {
    /// Extracts and parses the aggregate report attached to an RFC 5322
    /// message.
    ///
    /// Parts are tried in order: text parts with an `xml` subtype or `.xml`
    /// file name, and binary parts whose subtype (`gzip`, `zip`, `xml`) or,
    /// failing that, file extension (`.gz`, `.zip`, `.xml`) identifies the
    /// report. The first part that parses is returned. `max_size` caps the
    /// decompressed size of each gzip stream or zip member.
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
                PartType::Text(report)
                    if part
                        .content_type()
                        .and_then(|ct| ct.subtype())
                        .is_some_and(|t| t.eq_ignore_ascii_case("xml"))
                        || part
                            .attachment_name()
                            .and_then(|n| n.rsplit_once('.'))
                            .is_some_and(|(_, e)| e.eq_ignore_ascii_case("xml")) =>
                {
                    match AggregateReport::parse_xml(report.as_bytes()) {
                        Ok(feedback) => return Ok(feedback),
                        Err(err) => {
                            error = err;
                        }
                    }
                }
                PartType::Binary(report) | PartType::InlineBinary(report) => {
                    enum ReportType {
                        Xml,
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
                    let rt = if subtype.eq_ignore_ascii_case("gzip") {
                        ReportType::Gzip
                    } else if subtype.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if subtype.eq_ignore_ascii_case("xml") {
                        ReportType::Xml
                    } else if ext.eq_ignore_ascii_case("gz") {
                        ReportType::Gzip
                    } else if ext.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if ext.eq_ignore_ascii_case("xml") {
                        ReportType::Xml
                    } else {
                        continue;
                    };

                    match rt {
                        ReportType::Gzip => {
                            let report: &[u8] = report.as_ref();
                            let buf = read_capped(GzDecoder::new(report), 0, max_size)?;

                            match AggregateReport::parse_xml(&buf) {
                                Ok(feedback) => return Ok(feedback),
                                Err(err) => {
                                    error = err;
                                }
                            }
                        }
                        ReportType::Zip => {
                            let mut archive = zip::ZipArchive::new(Cursor::new(report))
                                .map_err(|err| ReportError::Decompress(err.to_string()))?;
                            for i in 0..archive.len() {
                                match archive.by_index(i) {
                                    Ok(mut file) => {
                                        let size_hint = file.size();
                                        let buf = read_capped(&mut file, size_hint, max_size)?;
                                        match AggregateReport::parse_xml(&buf) {
                                            Ok(feedback) => return Ok(feedback),
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
                        ReportType::Xml => match AggregateReport::parse_xml(report) {
                            Ok(feedback) => return Ok(feedback),
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

    /// Parses an aggregate report XML document.
    ///
    /// Accepts RFC 9990 reports and legacy RFC 7489 Appendix C reports, with
    /// or without a default namespace. Unknown elements are skipped.
    /// Unrecognized values map to the fallback documented on each field or
    /// type, such as an `Unspecified` or `Other` variant or `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Parse`] if the XML is malformed, the root
    /// element is not `feedback`, or `report_metadata` or `policy_published`
    /// is missing.
    pub fn parse_xml(report: &[u8]) -> Result<Self, ReportError> {
        Self::parse_xml_document(report).map_err(ReportError::Parse)
    }

    fn parse_xml_document(report: &[u8]) -> Result<Self, String> {
        let mut version = None;
        let mut report_metadata = None;
        let mut policy_published = None;
        let mut records = Vec::new();
        let mut extensions = Vec::new();

        let mut reader = Reader::from_reader(report);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::with_capacity(128);
        let mut found_feedback = false;

        while let Some(tag) = reader.next_tag(&mut buf)? {
            let name = tag.name();
            if found_feedback {
                hashify::fnc_map!(name.as_ref().as_bytes(),
                    b"version" => {
                        version = reader.next_value::<ReportVersion>(&mut buf)?;
                    },
                    b"report_metadata" => {
                        report_metadata = ReportMetadata::parse(&mut reader, &mut buf)?.into();
                    },
                    b"policy_published" => {
                        policy_published = PolicyPublished::parse(&mut reader, &mut buf)?.into();
                    },
                    b"record" => {
                        records.push(Record::parse(&mut reader, &mut buf)?);
                    },
                    b"extensions" => {
                        Extension::parse(&mut reader, &mut buf, &mut extensions)?;
                    },
                    b"" => (),
                    _ => {
                        reader.skip_tag(&mut buf)?;
                    }
                );
            } else if name.as_ref() == "feedback" {
                found_feedback = true;
            } else if !name.as_ref().is_empty() {
                return Err(format!(
                    "Unexpected tag {} at position {}.",
                    name.as_ref(),
                    reader.buffer_position()
                ));
            }
        }

        Ok(AggregateReport {
            version,
            report_metadata: report_metadata.ok_or("Missing feedback/report_metadata tag.")?,
            policy_published: policy_published.ok_or("Missing feedback/policy_published tag.")?,
            records,
            extensions,
        })
    }
}

impl ReportMetadata {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut rm = ReportMetadata::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"org_name" => {
                    rm.org_name = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"email" => {
                    rm.email = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"extra_contact_info" => {
                    rm.extra_contact_info = reader.next_value::<String>(buf)?;
                },
                b"report_id" => {
                    rm.report_id = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"date_range" => {
                    rm.date_range = DateRange::parse(reader, buf)?;
                },
                b"error" => {
                    if let Some(err) = reader.next_value::<String>(buf)? {
                        rm.errors.push(err);
                    }
                },
                b"generator" => {
                    rm.generator = reader.next_value::<String>(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(rm)
    }
}

impl DateRange {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut dr = DateRange::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"begin" => {
                    dr.begin = reader.next_value(buf)?.unwrap_or_default();
                },
                b"end" => {
                    dr.end = reader.next_value(buf)?.unwrap_or_default();
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(dr)
    }
}

impl PolicyPublished {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut p = PolicyPublished::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    p.domain = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"version_published" => {
                    p.version_published = reader.next_value(buf)?;
                },
                b"adkim" => {
                    p.adkim = reader.next_value::<String>(buf)?.and_then(|v| parse_alignment(&v));
                },
                b"aspf" => {
                    p.aspf = reader.next_value::<String>(buf)?.and_then(|v| parse_alignment(&v));
                },
                b"p" => {
                    p.p = reader.next_value::<String>(buf)?.map_or(Policy::Unspecified, |v| parse_policy(&v));
                },
                b"sp" => {
                    p.sp = reader.next_value::<String>(buf)?.map_or(Policy::Unspecified, |v| parse_policy(&v));
                },
                b"np" => {
                    p.np = reader.next_value::<String>(buf)?.map_or(Policy::Unspecified, |v| parse_policy(&v));
                },
                b"discovery_method" => {
                    p.discovery_method = reader.next_value(buf)?.unwrap_or_default();
                },
                b"testing" => {
                    p.testing = reader
                        .next_value::<String>(buf)?
                        .is_some_and(|s| s.eq_ignore_ascii_case("y"));
                },
                b"fo" => {
                    p.fo = reader.next_value::<String>(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(p)
    }
}

impl Extension {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
        extensions: &mut Vec<Extension>,
    ) -> Result<(), String> {
        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"extension" => {
                    let mut e = Extension::default();
                    if let Ok(Some(attr)) = tag.try_get_attribute("name")
                        && let Ok(attr) = attr.normalized_value(XmlVersion::Implicit1_0)
                    {
                        e.name = attr.to_string();
                    }
                    if let Ok(Some(attr)) = tag.try_get_attribute("definition")
                        && let Ok(attr) = attr.normalized_value(XmlVersion::Implicit1_0)
                    {
                        e.definition = attr.to_string();
                    }
                    extensions.push(e);
                    reader.skip_tag(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(())
    }
}

impl Record {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut r = Record::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"row" => {
                    r.row = Row::parse(reader, buf)?;
                },
                b"identifiers" => {
                    r.identifiers = Identifiers::parse(reader, buf)?;
                },
                b"auth_results" => {
                    r.auth_results = AuthResults::parse(reader, buf)?;
                },
                b"extensions" => {
                    Extension::parse(reader, buf, &mut r.extensions)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(r)
    }
}

impl Row {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut r = Row::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"source_ip" => {
                    if let Some(ip) = reader.next_value::<IpAddr>(buf)? {
                        r.source_ip = ip.into();
                    }
                },
                b"count" => {
                    r.count = reader.next_value(buf)?.unwrap_or_default();
                },
                b"policy_evaluated" => {
                    r.policy_evaluated = PolicyEvaluated::parse(reader, buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(r)
    }
}

impl PolicyEvaluated {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut pe = PolicyEvaluated::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"disposition" => {
                    pe.disposition = reader.next_value(buf)?.unwrap_or_default();
                },
                b"dkim" => {
                    pe.dkim = reader.next_value(buf)?.unwrap_or_default();
                },
                b"spf" => {
                    pe.spf = reader.next_value(buf)?.unwrap_or_default();
                },
                b"reason" => {
                    pe.reason.push(PolicyOverrideReason::parse(reader, buf)?);
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(pe)
    }
}

impl PolicyOverrideReason {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut por = PolicyOverrideReason::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"type" => {
                    por.kind = reader.next_value(buf)?.unwrap_or_default();
                },
                b"comment" => {
                    por.comment = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(por)
    }
}

impl Identifiers {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut i = Identifiers::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"envelope_to" => {
                    i.envelope_to = reader.next_value(buf)?;
                },
                b"envelope_from" => {
                    i.envelope_from = reader.next_value(buf)?.unwrap_or_default();
                },
                b"header_from" => {
                    i.header_from = reader.next_value(buf)?.unwrap_or_default();
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(i)
    }
}

impl AuthResults {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut ar = AuthResults::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"dkim" => {
                    ar.dkim.push(DkimAuthResult::parse(reader, buf)?);
                },
                b"spf" => {
                    ar.spf.push(SpfAuthResult::parse(reader, buf)?);
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(ar)
    }
}

impl DkimAuthResult {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut dar = DkimAuthResult::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    dar.domain = reader.next_value(buf)?.unwrap_or_default();
                },
                b"selector" => {
                    dar.selector = reader.next_value(buf)?.unwrap_or_default();
                },
                b"result" => {
                    dar.result = reader.next_value(buf)?.unwrap_or_default();
                },
                b"human_result" => {
                    dar.human_result = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(dar)
    }
}

impl SpfAuthResult {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut sar = SpfAuthResult::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    sar.domain = reader.next_value(buf)?.unwrap_or_default();
                },
                b"scope" => {
                    sar.scope = reader.next_value(buf)?.unwrap_or_default();
                },
                b"result" => {
                    sar.result = reader.next_value(buf)?.unwrap_or_default();
                },
                b"human_result" => {
                    sar.human_result = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(sar)
    }
}

impl FromStr for PolicyOverride {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), PolicyOverride,
            b"trusted_forwarder" => PolicyOverride::TrustedForwarder,
            b"mailing_list" => PolicyOverride::MailingList,
            b"local_policy" => PolicyOverride::LocalPolicy,
            b"policy_test_mode" => PolicyOverride::PolicyTestMode,
        )
        .copied()
        .unwrap_or(PolicyOverride::Other))
    }
}

impl FromStr for Discovery {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), Discovery,
            b"psl" => Discovery::Psl,
            b"treewalk" => Discovery::Treewalk,
        )
        .copied()
        .unwrap_or(Discovery::Unspecified))
    }
}

impl FromStr for DmarcStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), DmarcStatus,
            b"pass" => DmarcStatus::Pass,
            b"fail" => DmarcStatus::Fail,
        )
        .copied()
        .unwrap_or(DmarcStatus::Unspecified))
    }
}

impl FromStr for DkimStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), DkimStatus,
            b"none" => DkimStatus::None,
            b"pass" => DkimStatus::Pass,
            b"fail" => DkimStatus::Fail,
            b"policy" => DkimStatus::Policy,
            b"neutral" => DkimStatus::Neutral,
            b"temperror" => DkimStatus::TempError,
            b"permerror" => DkimStatus::PermError,
        )
        .copied()
        .unwrap_or(DkimStatus::None))
    }
}

impl FromStr for SpfStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), SpfStatus,
            b"none" => SpfStatus::None,
            b"pass" => SpfStatus::Pass,
            b"fail" => SpfStatus::Fail,
            b"softfail" => SpfStatus::SoftFail,
            b"neutral" => SpfStatus::Neutral,
            b"temperror" => SpfStatus::TempError,
            b"permerror" => SpfStatus::PermError,
        )
        .copied()
        .unwrap_or(SpfStatus::None))
    }
}

impl FromStr for SpfScope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), SpfScope,
            b"helo" => SpfScope::Helo,
            b"mfrom" => SpfScope::MailFrom,
        )
        .copied()
        .unwrap_or(SpfScope::Unspecified))
    }
}

impl FromStr for Disposition {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), Disposition,
            b"none" => Disposition::None,
            b"pass" => Disposition::Pass,
            b"quarantine" => Disposition::Quarantine,
            b"reject" => Disposition::Reject,
        )
        .copied()
        .unwrap_or(Disposition::Unspecified))
    }
}

fn parse_policy(value: &str) -> Policy {
    hashify::map!(value.as_bytes(), Policy,
        b"none" => Policy::None,
        b"quarantine" => Policy::Quarantine,
        b"reject" => Policy::Reject,
    )
    .copied()
    .unwrap_or(Policy::Unspecified)
}

fn parse_alignment(value: &str) -> Option<Alignment> {
    match value.as_bytes().first() {
        Some(b'r') => Some(Alignment::Relaxed),
        Some(b's') => Some(Alignment::Strict),
        _ => None,
    }
}

trait ReaderHelper {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String>;
    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String>;
    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String>;
}

impl<R: BufRead> ReaderHelper for Reader<R> {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String> {
        match self.read_event_into(buf) {
            Ok(Event::Start(e)) => Ok(Some(e)),
            Ok(Event::End(_)) | Ok(Event::Eof) => Ok(None),
            Err(e) => Err(format!(
                "Error at position {}: {:?}",
                self.buffer_position(),
                e
            )),
            _ => Ok(Some(BytesStart::new(""))),
        }
    }

    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String> {
        let mut value: Option<String> = None;

        loop {
            match self.read_event_into(buf) {
                Ok(Event::Text(e)) => {
                    let v = e.xml_content(XmlVersion::Implicit1_0);
                    if let Some(value) = &mut value {
                        value.push_str(&v);
                    } else {
                        value = Some(v.into_owned());
                    }
                }
                Ok(Event::GeneralRef(e)) => {
                    let v = hashify::map!(e.as_bytes(), &'static str,
                        b"lt" => "<",
                        b"gt" => ">",
                        b"amp" => "&",
                        b"apos" => "'",
                        b"quot" => "\"",
                    )
                    .copied()
                    .map(Cow::Borrowed)
                    .or_else(|| {
                        e.resolve_char_ref()
                            .ok()
                            .flatten()
                            .map(|v| Cow::Owned(v.to_string()))
                    })
                    .unwrap_or_else(|| e.xml_content(XmlVersion::Implicit1_0));

                    if let Some(value) = &mut value {
                        value.push_str(&v);
                    } else {
                        value = Some(v.into_owned());
                    }
                }
                Ok(Event::End(_)) => {
                    break;
                }
                Ok(Event::Start(e)) => {
                    return Err(format!(
                        "Expected value, found unexpected tag {} at position {}.",
                        e.name().as_ref(),
                        self.buffer_position()
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ));
                }
                _ => (),
            }
        }

        Ok(value.and_then(|v| T::from_str(&v).ok()))
    }

    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String> {
        let mut tag_count = 0;
        loop {
            match self.read_event_into(buf) {
                Ok(Event::End(_)) => {
                    if tag_count == 0 {
                        break;
                    } else {
                        tag_count -= 1;
                    }
                }
                Ok(Event::Start(_)) => {
                    tag_count += 1;
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ));
                }
                _ => (),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
