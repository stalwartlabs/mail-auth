/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::io;

use flate2::{write::GzEncoder, Compression};
use mail_builder::{
    headers::{address::Address, content_type::ContentType, HeaderType},
    mime::{make_boundary, BodyPart, MimePart},
    MessageBuilder,
};

use super::TlsReport;

impl TlsReport {
    pub fn write_rfc5322<'x>(
        &self,
        report_domain: &'x str,
        submitter: &'x str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        // Compress JSON report
        let json = self.to_json();
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        io::Write::write_all(&mut e, json.as_bytes())?;
        let bytes = e.finish()?;
        self.write_rfc5322_from_bytes(report_domain, submitter, from, to, &bytes, writer)
    }

    pub fn write_rfc5322_from_bytes<'x>(
        &self,
        report_domain: &str,
        submitter: &str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
        bytes: &[u8],
        writer: impl io::Write,
    ) -> io::Result<()> {
        MessageBuilder::new()
            .from(from)
            .header(
                "To",
                HeaderType::Address(Address::List(to.map(|to| (*to).into()).collect())),
            )
            .message_id(format!("{}@{}", make_boundary("."), submitter))
            .header("TLS-Report-Domain", HeaderType::Text(report_domain.into()))
            .header("TLS-Report-Submitter", HeaderType::Text(submitter.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .subject(format!(
                "Report Domain: {} Submitter: {} Report-ID: <{}>",
                report_domain, submitter, self.report_id
            ))
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
                                submitter, report_domain, submitter, self.report_id
                            )
                            .into(),
                        ),
                    ),
                    MimePart::new(
                        ContentType::new("application/tlsrpt+gzip"),
                        BodyPart::Binary(bytes.into()),
                    )
                    .attachment(format!(
                        "{}!{}!{}!{}.json.gz",
                        submitter,
                        report_domain,
                        self.date_range.start_datetime.to_timestamp(),
                        self.date_range.end_datetime.to_timestamp()
                    )),
                ]),
            ))
            .write_to(writer)
    }

    pub fn to_rfc5322<'x>(
        &self,
        report_domain: &'x str,
        submitter: &'x str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
    ) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(report_domain, submitter, from, to, &mut buf)?;
        String::from_utf8(buf).map_err(io::Error::other)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use mail_parser::DateTime;

    use crate::report::tlsrpt::{DateRange, TlsReport};

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

        let message = report
            .to_rfc5322(
                "hello-world.inc",
                "example.org",
                "no-reply@example.org",
                ["tls-reports@hello-world.inc"].iter().copied(),
            )
            .unwrap();

        //println!("{message}");

        let parsed_report = TlsReport::parse_rfc5322(message.as_bytes()).unwrap();

        assert_eq!(report, parsed_report);
    }
}
