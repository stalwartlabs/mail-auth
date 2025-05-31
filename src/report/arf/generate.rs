/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{fmt::Write, io, time::SystemTime};

use mail_builder::{
    headers::{address::Address, content_type::ContentType, HeaderType},
    mime::{make_boundary, BodyPart, MimePart},
    MessageBuilder,
};
use mail_parser::DateTime;

use crate::report::{AuthFailureType, DeliveryResult, Feedback, FeedbackType, IdentityAlignment};

impl<'x> Feedback<'x> {
    pub fn write_rfc5322(
        &self,
        from: impl Into<Address<'x>>,
        to: &'x str,
        subject: &'x str,
        writer: impl io::Write,
    ) -> io::Result<()> {
        // Generate ARF
        let arf = self.to_arf();

        // Generate text/plain body
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

        // Build message parts
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
        if let Some(message) = self.message.as_ref() {
            parts.push(MimePart::new(
                ContentType::new("message/rfc822"),
                BodyPart::Text(message.as_ref().into()),
            ));
        } else if let Some(headers) = self.headers.as_ref() {
            parts.push(MimePart::new(
                ContentType::new("text/rfc822-headers"),
                BodyPart::Text(headers.as_ref().into()),
            ));
        }

        MessageBuilder::new()
            .from(from)
            .header("To", HeaderType::Text(to.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!(
                "{}@{}",
                make_boundary("."),
                self.reporting_mta().unwrap_or("localhost")
            ))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "feedback-report"),
                BodyPart::Multipart(parts),
            ))
            .write_to(writer)
    }

    pub fn to_rfc5322(
        &self,
        from: impl Into<Address<'x>>,
        to: &'x str,
        subject: &'x str,
    ) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(from, to, subject, &mut buf)?;
        String::from_utf8(buf).map_err(io::Error::other)
    }

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
        for value in &self.reported_domain {
            write!(&mut arf, "Reported-Domain: {value}\r\n").ok();
        }
        for value in &self.reported_uri {
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
    use crate::report::{AuthFailureType, Feedback, FeedbackType, IdentityAlignment};

    #[test]
    fn arf_report_generate() {
        let feedback = Feedback::new(FeedbackType::AuthFailure)
            .with_arrival_date(5934759438)
            .with_authentication_results("dkim=pass")
            .with_incidents(10)
            .with_original_envelope_id("821-abc-123")
            .with_original_mail_from("hello@world.org")
            .with_original_rcpt_to("ciao@mundo.org")
            .with_reported_domain("example.org")
            .with_reported_domain("example2.org")
            .with_reported_uri("uri:domain.org")
            .with_reported_uri("uri:domain2.org")
            .with_reporting_mta("Manchegator 2.0")
            .with_source_ip("192.168.1.1".parse().unwrap())
            .with_user_agent("DMARC-Meister")
            .with_version(2)
            .with_source_port(1234)
            .with_auth_failure(AuthFailureType::Dmarc)
            .with_dkim_adsp_dns("v=dkim1")
            .with_dkim_canonicalized_body("base64 goes here")
            .with_dkim_canonicalized_header("more base64")
            .with_dkim_domain("dkim-domain.org")
            .with_dkim_identity("my-dkim-identity@domain.org")
            .with_dkim_selector("the-selector")
            .with_dkim_selector_dns("v=dkim1;")
            .with_spf_dns("v=spf1")
            .with_identity_alignment(IdentityAlignment::DkimSpf)
            .with_message("From: hello@world.org\r\nTo: ciao@mondo.org\r\n\r\n");

        let message = feedback
            .to_rfc5322(
                ("DMARC Reporter", "no-reply@example.org"),
                "ruf@otherdomain.com",
                "DMARC Authentication Failure Report",
            )
            .unwrap();

        let parsed_feedback = Feedback::parse_rfc5322(message.as_bytes()).unwrap();

        assert_eq!(feedback, parsed_feedback);
    }
}
