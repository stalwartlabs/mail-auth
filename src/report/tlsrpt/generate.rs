/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Serialization of [`TlsReport`] to JSON and to a complete TLS report email
//! message.

use super::{DateRange, TlsReport};
use crate::report::ReportEnvelope;
use flate2::{Compression, write::GzEncoder};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart, make_boundary},
};
use std::{borrow::Cow, io};

#[derive(serde::Deserialize)]
struct ReportHeader {
    #[serde(rename = "report-id")]
    #[serde(default)]
    report_id: String,
    #[serde(rename = "date-range")]
    date_range: DateRange,
}

impl TlsReport {
    /// Writes the report as an RFC 5322 `multipart/report` message with
    /// `report-type=tlsrpt` to `writer`, as described in RFC 8460 section 5.3.
    ///
    /// The parts are a `text/plain` summary and the output of
    /// [`to_json`](Self::to_json), gzip-compressed, as an
    /// `application/tlsrpt+gzip` attachment named
    /// `submitter!report_domain!start!end.json.gz`, where `start` and `end`
    /// are Unix timestamps. The message carries `TLS-Report-Domain`,
    /// `TLS-Report-Submitter` and `Auto-Submitted: auto-generated` header
    /// fields.
    ///
    /// Fields read from `envelope`:
    ///
    /// - `from`: the `From` header field.
    /// - `to`: the `To` header field.
    /// - `submitter`: the `TLS-Report-Submitter` header field, the
    ///   `Message-ID` host, the subject, the text body and the file name.
    /// - `report_domain`: the `TLS-Report-Domain` header field, the subject,
    ///   the text body and the file name.
    /// - `subject`: the subject; when `None`, defaults to
    ///   `Report Domain: <report_domain> Submitter: <submitter> Report-ID: <<report_id>>`.
    ///
    /// # Errors
    ///
    /// Returns any I/O error raised by `writer` or by the gzip encoder.
    pub fn write_rfc5322(
        &self,
        envelope: &ReportEnvelope<'_>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        let json = self.to_json();
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        io::Write::write_all(&mut e, json.as_bytes())?;
        let bytes = e.finish()?;
        Self::write_message(
            envelope,
            &self.report_id,
            self.date_range.start_datetime.to_timestamp(),
            self.date_range.end_datetime.to_timestamp(),
            &bytes,
            writer,
        )
    }

    /// Writes a report that is already serialized as uncompressed JSON as an
    /// RFC 5322 message to `writer`.
    ///
    /// Produces the same message as [`write_rfc5322`](Self::write_rfc5322)
    /// and reads the same `envelope` fields. Only the `report-id` and
    /// `date-range` members are read from `json`; the document is gzipped and
    /// attached as is.
    ///
    /// # Errors
    ///
    /// Returns an error of kind [`io::ErrorKind::InvalidData`] if `json` is
    /// not a JSON object with a valid `date-range` member, and any I/O error
    /// raised by `writer` or by the gzip encoder.
    pub fn write_rfc5322_json(
        json: &[u8],
        envelope: &ReportEnvelope<'_>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        let report = serde_json::from_slice::<ReportHeader>(json)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        io::Write::write_all(&mut e, json)?;
        let bytes = e.finish()?;
        Self::write_message(
            envelope,
            &report.report_id,
            report.date_range.start_datetime.to_timestamp(),
            report.date_range.end_datetime.to_timestamp(),
            &bytes,
            writer,
        )
    }

    fn write_message(
        envelope: &ReportEnvelope<'_>,
        report_id: &str,
        start: i64,
        end: i64,
        bytes: &[u8],
        writer: impl io::Write,
    ) -> io::Result<()> {
        let report_domain = envelope.report_domain;
        let submitter = envelope.submitter;
        let subject = envelope.subject.map_or_else(
            || {
                Cow::Owned(format!(
                    "Report Domain: {report_domain} Submitter: {submitter} Report-ID: <{report_id}>"
                ))
            },
            Cow::Borrowed,
        );

        MessageBuilder::new()
            .from(envelope.from.clone())
            .header("To", envelope.to_header())
            .message_id(format!("{}@{}", make_boundary("."), submitter))
            .header("TLS-Report-Domain", HeaderType::Text(report_domain.into()))
            .header("TLS-Report-Submitter", HeaderType::Text(submitter.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "tlsrpt"),
                BodyPart::Multipart(vec![
                    MimePart::new(
                        ContentType::new("text/plain"),
                        BodyPart::Text(
                            format!(
                                concat!(
                                    "TLS report from {}\r\n\r\n",
                                    "Report Domain: {}\r\n",
                                    "Submitter: {}\r\n",
                                    "Report-ID: {}\r\n",
                                ),
                                submitter, report_domain, submitter, report_id
                            )
                            .into(),
                        ),
                    ),
                    MimePart::new(
                        ContentType::new("application/tlsrpt+gzip"),
                        BodyPart::Binary(bytes.into()),
                    )
                    .attachment(format!("{submitter}!{report_domain}!{start}!{end}.json.gz")),
                ]),
            ))
            .write_to(writer)
    }

    /// Returns the report as an RFC 5322 message.
    ///
    /// Same as [`write_rfc5322`](Self::write_rfc5322), collected into a
    /// `String`.
    ///
    /// # Errors
    ///
    /// Returns an error if the gzip encoder fails or the message is not valid
    /// UTF-8.
    pub fn to_rfc5322(&self, envelope: &ReportEnvelope<'_>) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(envelope, &mut buf)?;
        String::from_utf8(buf).map_err(io::Error::other)
    }

    /// Serializes the report as an RFC 8460 JSON document.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use crate::report::{
        ReportEnvelope,
        tlsrpt::{DateRange, TlsReport},
    };
    use mail_parser::DateTime;
    const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;

    #[test]
    fn tlsrpt_generate() {
        let report = TlsReport {
            organization_name: "Hello World, Inc.".to_string().into(),
            date_range: DateRange {
                start_datetime: DateTime::from_timestamp(49823749),
                end_datetime: DateTime::from_timestamp(49823899),
            },
            contact_info: "tls-report@hello-world.inc".to_string().into(),
            report_id: "abc-123".to_string(),
            policies: vec![],
        };

        let envelope = ReportEnvelope {
            from: "no-reply@example.org".into(),
            to: vec!["tls-reports@hello-world.inc"],
            submitter: "example.org",
            report_domain: "hello-world.inc",
            subject: None,
        };
        let message = report.to_rfc5322(&envelope).unwrap();
        let parsed_report = TlsReport::parse_rfc5322(message.as_bytes(), MAX_REPORT_SIZE).unwrap();
        assert_eq!(report, parsed_report);

        let mut message = Vec::new();
        TlsReport::write_rfc5322_json(report.to_json().as_bytes(), &envelope, &mut message)
            .unwrap();
        let parsed_report = TlsReport::parse_rfc5322(&message, MAX_REPORT_SIZE).unwrap();
        assert_eq!(report, parsed_report);
    }
}
