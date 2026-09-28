/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Serialization of [`FeedbackReport`] to the ARF field format and to a
//! complete feedback report email message.

use crate::{
    SystemTime,
    report::{
        ReportEnvelope,
        arf::{AuthFailureType, DeliveryResult, FeedbackReport, FeedbackType, IdentityAlignment},
    },
    utf8::into_string,
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart, make_boundary},
};
use mail_parser::DateTime;
use std::{fmt::Write, io};

impl<'x> FeedbackReport<'x> {
    /// Writes the report as an RFC 5322 `multipart/report` message with
    /// `report-type=feedback-report` to `writer`.
    ///
    /// The parts are a `text/plain` summary, the output of
    /// [`to_arf`](Self::to_arf) as `message/feedback-report`, and the original
    /// message as `message/rfc822` or, when `message` is `None`, its headers
    /// as `text/rfc822-headers`. The summary uses `arrival_date`, or the
    /// current time when it is unset. The message carries an
    /// `Auto-Submitted: auto-generated` header field.
    ///
    /// Fields read from `envelope`:
    ///
    /// - `from`: the `From` header field.
    /// - `to`: the `To` header field.
    /// - `subject`: the subject; when `None`, defaults to
    ///   `Authentication Failure Report` for [`FeedbackType::AuthFailure`]
    ///   and `Abuse Report` otherwise.
    /// - `submitter`: the `Message-ID` host, only when `reporting_mta` is
    ///   `None`. When both are empty, `localhost` is used.
    ///
    /// `envelope.report_domain` is ignored.
    ///
    /// # Errors
    ///
    /// Returns any I/O error raised by `writer`.
    pub fn write_rfc5322(
        &self,
        envelope: &ReportEnvelope<'_>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        let arf = self.to_arf();

        let mut text_body = String::with_capacity(128);
        if self.feedback_type == FeedbackType::AuthFailure {
            write!(
                &mut text_body,
                "This is an authentication failure report for an email message received\r\n"
            )
        } else {
            write!(
                &mut text_body,
                "This is an email abuse report for an email message received\r\n"
            )
        }
        .ok();
        if let Some(ip) = &self.source_ip {
            write!(&mut text_body, "from IP address {ip} ").ok();
        }
        let dt = DateTime::from_timestamp(if let Some(ad) = &self.arrival_date {
            *ad
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0) as i64
        });
        write!(&mut text_body, "on {}.\r\n", dt.to_rfc822()).ok();

        let mut parts = vec![
            MimePart::new(
                ContentType::new("text/plain"),
                BodyPart::Text(text_body.into()),
            ),
            MimePart::new(
                ContentType::new("message/feedback-report"),
                BodyPart::Text(arf.into()),
            ),
        ];
        if let Some(message) = self.message.as_deref() {
            parts.push(MimePart::new(
                ContentType::new("message/rfc822"),
                BodyPart::Text(message.into()),
            ));
        } else if let Some(headers) = self.headers.as_deref() {
            parts.push(MimePart::new(
                ContentType::new("text/rfc822-headers"),
                BodyPart::Text(headers.into()),
            ));
        }

        let host = self
            .reporting_mta
            .as_deref()
            .filter(|host| !host.is_empty())
            .or((!envelope.submitter.is_empty()).then_some(envelope.submitter))
            .unwrap_or("localhost");
        let subject = envelope.subject.unwrap_or(match self.feedback_type {
            FeedbackType::AuthFailure => "Authentication Failure Report",
            _ => "Abuse Report",
        });

        MessageBuilder::new()
            .from(envelope.from.clone())
            .header("To", envelope.to_header())
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("{}@{}", make_boundary("."), host))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "feedback-report"),
                BodyPart::Multipart(parts),
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
    /// Returns an error if the message is not valid UTF-8.
    pub fn to_rfc5322(&self, envelope: &ReportEnvelope<'_>) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(envelope, &mut buf)?;
        into_string(buf).map_err(io::Error::other)
    }

    /// Serializes the machine-readable part of the report as ARF fields,
    /// each terminated by CRLF.
    ///
    /// Unset optional fields are omitted. The RFC 6591 fields (`Auth-Failure`
    /// through `Identity-Alignment`) are written only for
    /// [`FeedbackType::AuthFailure`] reports.
    pub fn to_arf(&self) -> String {
        let mut arf = String::with_capacity(128);

        write!(&mut arf, "Version: {}\r\n", self.version).ok();
        write!(
            &mut arf,
            "Feedback-Type: {}\r\n",
            match self.feedback_type {
                FeedbackType::Abuse => "abuse",
                FeedbackType::AuthFailure => "auth-failure",
                FeedbackType::Fraud => "fraud",
                FeedbackType::NotSpam => "not-spam",
                FeedbackType::Other => "other",
                FeedbackType::Virus => "virus",
            }
        )
        .ok();
        if let Some(ad) = &self.arrival_date {
            let ad = DateTime::from_timestamp(*ad);
            write!(&mut arf, "Arrival-Date: {}\r\n", ad.to_rfc822()).ok();
        }

        if self.feedback_type == FeedbackType::AuthFailure {
            if self.auth_failure != AuthFailureType::Unspecified {
                write!(
                    &mut arf,
                    "Auth-Failure: {}\r\n",
                    match self.auth_failure {
                        AuthFailureType::Adsp => "adsp",
                        AuthFailureType::BodyHash => "bodyhash",
                        AuthFailureType::Revoked => "revoked",
                        AuthFailureType::Signature => "signature",
                        AuthFailureType::Spf => "spf",
                        AuthFailureType::Dmarc => "dmarc",
                        AuthFailureType::Unspecified => unreachable!(),
                    }
                )
                .ok();
            }

            if self.delivery_result != DeliveryResult::Unspecified {
                write!(
                    &mut arf,
                    "Delivery-Result: {}\r\n",
                    match self.delivery_result {
                        DeliveryResult::Delivered => "delivered",
                        DeliveryResult::Spam => "spam",
                        DeliveryResult::Policy => "policy",
                        DeliveryResult::Reject => "reject",
                        DeliveryResult::Other => "other",
                        DeliveryResult::Unspecified => unreachable!(),
                    }
                )
                .ok();
            }
            if let Some(value) = &self.dkim_adsp_dns {
                write!(&mut arf, "DKIM-ADSP-DNS: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_canonicalized_body {
                write!(&mut arf, "DKIM-Canonicalized-Body: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_canonicalized_header {
                write!(&mut arf, "DKIM-Canonicalized-Header: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_domain {
                write!(&mut arf, "DKIM-Domain: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_identity {
                write!(&mut arf, "DKIM-Identity: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_selector {
                write!(&mut arf, "DKIM-Selector: {value}\r\n").ok();
            }
            if let Some(value) = &self.dkim_selector_dns {
                write!(&mut arf, "DKIM-Selector-DNS: {value}\r\n").ok();
            }
            if let Some(value) = &self.spf_dns {
                write!(&mut arf, "SPF-DNS: {value}\r\n").ok();
            }
            if self.identity_alignment != IdentityAlignment::Unspecified {
                write!(
                    &mut arf,
                    "Identity-Alignment: {}\r\n",
                    match self.identity_alignment {
                        IdentityAlignment::None => "none",
                        IdentityAlignment::Spf => "spf",
                        IdentityAlignment::Dkim => "dkim",
                        IdentityAlignment::DkimSpf => "dkim, spf",
                        IdentityAlignment::Unspecified => unreachable!(),
                    }
                )
                .ok();
            }
        }

        for value in &self.authentication_results {
            write!(&mut arf, "Authentication-Results: {value}\r\n").ok();
        }
        if self.incidents > 1 {
            write!(&mut arf, "Incidents: {}\r\n", self.incidents).ok();
        }
        if let Some(value) = &self.original_envelope_id {
            write!(&mut arf, "Original-Envelope-Id: {value}\r\n").ok();
        }
        if let Some(value) = &self.original_mail_from {
            write!(&mut arf, "Original-Mail-From: {value}\r\n").ok();
        }
        if let Some(value) = &self.original_rcpt_to {
            write!(&mut arf, "Original-Rcpt-To: {value}\r\n").ok();
        }
        for value in &self.reported_domains {
            write!(&mut arf, "Reported-Domain: {value}\r\n").ok();
        }
        for value in &self.reported_uris {
            write!(&mut arf, "Reported-URI: {value}\r\n").ok();
        }
        if let Some(value) = &self.reporting_mta {
            write!(&mut arf, "Reporting-MTA: dns;{value}\r\n").ok();
        }
        if let Some(value) = &self.source_ip {
            write!(&mut arf, "Source-IP: {value}\r\n").ok();
        }
        if self.source_port != 0 {
            write!(&mut arf, "Source-Port: {}\r\n", self.source_port).ok();
        }
        if let Some(value) = &self.user_agent {
            write!(&mut arf, "User-Agent: {value}\r\n").ok();
        }

        arf
    }
}

#[cfg(test)]
mod test {
    use crate::report::{
        ReportEnvelope,
        arf::{AuthFailureType, FeedbackReport, FeedbackType, IdentityAlignment},
    };

    #[test]
    fn arf_report_generate() {
        let feedback = FeedbackReport {
            arrival_date: Some(5934759438),
            authentication_results: vec!["dkim=pass".into()],
            incidents: 10,
            original_envelope_id: Some("821-abc-123".into()),
            original_mail_from: Some("hello@world.org".into()),
            original_rcpt_to: Some("ciao@mundo.org".into()),
            reported_domains: vec!["example.org".into(), "example2.org".into()],
            reported_uris: vec!["uri:domain.org".into(), "uri:domain2.org".into()],
            reporting_mta: Some("Manchegator 2.0".into()),
            source_ip: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("DMARC-Meister".into()),
            version: 2,
            source_port: 1234,
            auth_failure: AuthFailureType::Dmarc,
            dkim_adsp_dns: Some("v=dkim1".into()),
            dkim_canonicalized_body: Some("base64 goes here".into()),
            dkim_canonicalized_header: Some("more base64".into()),
            dkim_domain: Some("dkim-domain.org".into()),
            dkim_identity: Some("my-dkim-identity@domain.org".into()),
            dkim_selector: Some("the-selector".into()),
            dkim_selector_dns: Some("v=dkim1;".into()),
            spf_dns: Some("v=spf1".into()),
            identity_alignment: IdentityAlignment::DkimSpf,
            message: Some("From: hello@world.org\r\nTo: ciao@mondo.org\r\n\r\n".into()),
            ..FeedbackReport::new(FeedbackType::AuthFailure)
        };

        let message = feedback
            .to_rfc5322(&ReportEnvelope {
                from: ("DMARC Reporter", "no-reply@example.org").into(),
                to: vec!["ruf@otherdomain.com"],
                submitter: "example.org",
                report_domain: "",
                subject: Some("DMARC Authentication Failure Report"),
            })
            .unwrap();

        let parsed_feedback =
            FeedbackReport::parse_rfc5322(message.as_bytes(), message.len()).unwrap();

        assert_eq!(feedback, parsed_feedback);
    }
}
