/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{fmt::Write, io, time::SystemTime};

use mail_builder::{
    headers::{content_type::ContentType, HeaderType},
    mime::{BodyPart, MimePart},
    MessageBuilder,
};
use mail_parser::DateTime;

use crate::report::{AuthFailureType, DeliveryResult, Feedback, FeedbackType, IdentityAlignment};

impl<'x> Feedback<'x> {
    pub fn write_rfc5322(
        &self,
        from: &'x str,
        to: &'x str,
        subject: &'x str,
        writer: impl io::Write,
    ) -> io::Result<()> {
        // Generate ARF

        let arf = self.as_arf();

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
            write!(&mut text_body, "from IP address {} ", ip).ok();
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
        if let Some(message) = self
            .message
            .as_ref()
            .and_then(|v| std::str::from_utf8(v.as_ref()).ok())
        {
            parts.push(MimePart::new(
                ContentType::new("message/rfc822"),
                BodyPart::Text(message.into()),
            ));
        } else if let Some(headers) = self
            .headers
            .as_ref()
            .and_then(|v| std::str::from_utf8(v.as_ref()).ok())
        {
            parts.push(MimePart::new(
                ContentType::new("text/rfc822-headers"),
                BodyPart::Text(headers.into()),
            ));
        }

        MessageBuilder::new()
            .header("From", HeaderType::Text(from.into()))
            .header("To", HeaderType::Text(to.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "feedback-report"),
                BodyPart::Multipart(parts),
            ))
            .write_to(writer)
    }

    pub fn as_rfc5322(&self, from: &str, to: &str, subject: &str) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(from, to, subject, &mut buf)?;
        String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    pub fn as_arf(&self) -> String {
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
                write!(&mut arf, "DKIM-ADSP-DNS: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_canonicalized_body {
                write!(&mut arf, "DKIM-Canonicalized-Body: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_canonicalized_header {
                write!(&mut arf, "DKIM-Canonicalized-Header: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_domain {
                write!(&mut arf, "DKIM-Domain: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_identity {
                write!(&mut arf, "DKIM-Identity: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_selector {
                write!(&mut arf, "DKIM-Selector: {}\r\n", value).ok();
            }
            if let Some(value) = &self.dkim_selector_dns {
                write!(&mut arf, "DKIM-Selector-DNS: {}\r\n", value).ok();
            }
            if let Some(value) = &self.spf_dns {
                write!(&mut arf, "SPF-DNS: {}\r\n", value).ok();
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
            write!(&mut arf, "Authentication-Results: {}\r\n", value).ok();
        }
        if self.incidents > 1 {
            write!(&mut arf, "Incidents: {}\r\n", self.incidents).ok();
        }
        if let Some(value) = &self.original_envelope_id {
            write!(&mut arf, "Original-Envelope-Id: {}\r\n", value).ok();
        }
        if let Some(value) = &self.original_mail_from {
            write!(&mut arf, "Original-Mail-From: {}\r\n", value).ok();
        }
        if let Some(value) = &self.original_rcpt_to {
            write!(&mut arf, "Original-Rcpt-To: {}\r\n", value).ok();
        }
        for value in &self.reported_domain {
            write!(&mut arf, "Reported-Domain: {}\r\n", value).ok();
        }
        for value in &self.reported_uri {
            write!(&mut arf, "Reported-URI: {}\r\n", value).ok();
        }
        if let Some(value) = &self.reporting_mta {
            write!(&mut arf, "Reporting-MTA: {}\r\n", value).ok();
        }
        if let Some(value) = &self.source_ip {
            write!(&mut arf, "Source-IP: {}\r\n", value).ok();
        }
        if self.source_port != 0 {
            write!(&mut arf, "Source-Port: {}\r\n", self.source_port).ok();
        }
        if let Some(value) = &self.user_agent {
            write!(&mut arf, "User-Agent: {}\r\n", value).ok();
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
            .with_message(&b"From: hello@world.org\r\nTo: ciao@mundo.org\r\n\r\n"[..]);

        let message = feedback
            .as_rfc5322(
                "no-reply@example.org",
                "ruf@otherdomain.com",
                "DMARC Authentication Failure Report",
            )
            .unwrap();

        let parsed_feedback = Feedback::parse_rfc5322(message.as_bytes()).unwrap();

        assert_eq!(feedback, parsed_feedback);
    }
}
