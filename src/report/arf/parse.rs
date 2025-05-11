/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::borrow::Cow;

use mail_parser::{parsers::MessageStream, HeaderValue, MessageParser, MimeHeaders, PartType};

use crate::{
    common::headers::HeaderIterator,
    report::{AuthFailureType, DeliveryResult, Error, Feedback, FeedbackType, IdentityAlignment},
};

impl<'x> Feedback<'x> {
    pub fn parse_rfc5322(message: &'x [u8]) -> Result<Self, Error> {
        let message = MessageParser::new()
            .parse(message)
            .ok_or(Error::MailParseError)?;
        let mut feedback = None;
        let mut included_message = None;
        let mut included_headers = None;

        for part in message.parts {
            let arf = match part.body {
                PartType::Text(arf) | PartType::Html(arf)
                    if part.is_content_type("message", "feedback-report") =>
                {
                    match arf {
                        Cow::Borrowed(arf) => Cow::Borrowed(arf.as_bytes()),
                        Cow::Owned(arf) => Cow::Owned(arf.into_bytes()),
                    }
                }
                PartType::Binary(arf) | PartType::InlineBinary(arf)
                    if part.is_content_type("message", "feedback-report") =>
                {
                    arf
                }
                PartType::Text(headers) if part.is_content_type("text", "rfc822-headers") => {
                    included_headers = match headers {
                        Cow::Borrowed(arf) => Cow::Borrowed(arf.as_bytes()),
                        Cow::Owned(arf) => Cow::Owned(arf.into_bytes()),
                    }
                    .into();
                    continue;
                }
                PartType::Message(message) => {
                    included_message = match message.raw_message {
                        Cow::Borrowed(message) => Cow::Borrowed(
                            message
                                .get(part.offset_body as usize..part.offset_end as usize)
                                .unwrap_or_default(),
                        ),
                        message => message,
                    }
                    .into();
                    continue;
                }
                _ => continue,
            };

            feedback = match arf {
                Cow::Borrowed(arf) => Feedback::parse_arf(arf),
                Cow::Owned(arf) => Feedback::parse_arf(&arf).map(|f| f.into_owned()),
            };
        }

        if let Some(mut feedback) = feedback {
            for (feedback, included) in [
                (&mut feedback.message, included_message),
                (&mut feedback.headers, included_headers),
            ] {
                if let Some(included) = included {
                    *feedback = match included {
                        Cow::Borrowed(bytes) => Some(String::from_utf8_lossy(bytes)),
                        Cow::Owned(bytes) => Some(
                            String::from_utf8(bytes)
                                .unwrap_or_else(|err| {
                                    String::from_utf8_lossy(err.as_bytes()).into_owned()
                                })
                                .into(),
                        ),
                    };
                }
            }

            Ok(feedback)
        } else {
            Err(Error::NoReportsFound)
        }
    }

    pub fn parse_arf(arf: &'x [u8]) -> Option<Self> {
        let mut f = Feedback {
            incidents: 1,
            ..Default::default()
        };
        let mut has_ft = false;

        let mut fields = HeaderIterator::new(arf);
        fields.seek_start();

        for (key, value) in fields {
            let txt_value = std::str::from_utf8(value).unwrap_or_default().trim();

            match key.first() {
                Some(b'A' | b'a') => {
                    if key.eq_ignore_ascii_case(b"Arrival-Date") {
                        if let HeaderValue::DateTime(dt) = MessageStream::new(value).parse_date() {
                            f.arrival_date = dt.to_timestamp().into();
                        }
                    } else if key.eq_ignore_ascii_case(b"Auth-Failure") {
                        f.auth_failure = if txt_value.eq_ignore_ascii_case("adsp") {
                            AuthFailureType::Adsp
                        } else if txt_value.eq_ignore_ascii_case("bodyhash") {
                            AuthFailureType::BodyHash
                        } else if txt_value.eq_ignore_ascii_case("revoked") {
                            AuthFailureType::Revoked
                        } else if txt_value.eq_ignore_ascii_case("signature") {
                            AuthFailureType::Signature
                        } else if txt_value.eq_ignore_ascii_case("spf") {
                            AuthFailureType::Spf
                        } else if txt_value.eq_ignore_ascii_case("dmarc") {
                            AuthFailureType::Dmarc
                        } else {
                            continue;
                        };
                    } else if key.eq_ignore_ascii_case(b"Authentication-Results") {
                        f.authentication_results.push(txt_value.into());
                    }
                }
                Some(b'D' | b'd') => {
                    if key.eq_ignore_ascii_case(b"DKIM-ADSP-DNS") {
                        f.dkim_adsp_dns = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Canonicalized-Body") {
                        f.dkim_canonicalized_body = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Canonicalized-Header") {
                        f.dkim_canonicalized_header = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Domain") {
                        f.dkim_domain = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Identity") {
                        f.dkim_identity = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Selector") {
                        f.dkim_selector = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"DKIM-Selector-DNS") {
                        f.dkim_selector_dns = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Delivery-Result") {
                        f.delivery_result = if txt_value.eq_ignore_ascii_case("delivered") {
                            DeliveryResult::Delivered
                        } else if txt_value.eq_ignore_ascii_case("spam") {
                            DeliveryResult::Spam
                        } else if txt_value.eq_ignore_ascii_case("policy") {
                            DeliveryResult::Policy
                        } else if txt_value.eq_ignore_ascii_case("reject") {
                            DeliveryResult::Reject
                        } else if txt_value.eq_ignore_ascii_case("other") {
                            DeliveryResult::Other
                        } else {
                            continue;
                        };
                    }
                }
                Some(b'F' | b'f') => {
                    if key.eq_ignore_ascii_case(b"Feedback-Type") {
                        f.feedback_type = if txt_value.eq_ignore_ascii_case("abuse") {
                            FeedbackType::Abuse
                        } else if txt_value.eq_ignore_ascii_case("auth-failure") {
                            FeedbackType::AuthFailure
                        } else if txt_value.eq_ignore_ascii_case("fraud") {
                            FeedbackType::Fraud
                        } else if txt_value.eq_ignore_ascii_case("not-spam") {
                            FeedbackType::NotSpam
                        } else if txt_value.eq_ignore_ascii_case("other") {
                            FeedbackType::Other
                        } else if txt_value.eq_ignore_ascii_case("virus") {
                            FeedbackType::Virus
                        } else {
                            continue;
                        };
                        has_ft = true;
                    }
                }
                Some(b'I' | b'i') => {
                    if key.eq_ignore_ascii_case(b"Identity-Alignment") {
                        for id in txt_value.split(',') {
                            let id = id.trim();
                            if id.eq_ignore_ascii_case("dkim") {
                                f.identity_alignment =
                                    if f.identity_alignment == IdentityAlignment::Spf {
                                        IdentityAlignment::DkimSpf
                                    } else {
                                        IdentityAlignment::Dkim
                                    };
                            } else if id.eq_ignore_ascii_case("spf") {
                                f.identity_alignment =
                                    if f.identity_alignment == IdentityAlignment::Dkim {
                                        IdentityAlignment::DkimSpf
                                    } else {
                                        IdentityAlignment::Spf
                                    };
                            } else if id.eq_ignore_ascii_case("none") {
                                f.identity_alignment = IdentityAlignment::None;
                                break;
                            }
                        }
                    } else if key.eq_ignore_ascii_case(b"Incidents") {
                        f.incidents = txt_value.parse().unwrap_or(1);
                    }
                }
                Some(b'O' | b'o') => {
                    if key.eq_ignore_ascii_case(b"Original-Envelope-Id") {
                        f.original_envelope_id = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Original-Mail-From") {
                        f.original_mail_from = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Original-Rcpt-To") {
                        f.original_rcpt_to = Some(txt_value.into());
                    }
                }
                Some(b'R' | b'r') => {
                    if key.eq_ignore_ascii_case(b"Reported-Domain") {
                        f.reported_domain.push(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Reported-URI") {
                        f.reported_uri.push(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Reporting-MTA") {
                        f.reporting_mta = Some(if let Some(mta) = txt_value.strip_prefix("dns;") {
                            mta.trim().into()
                        } else {
                            txt_value.into()
                        });
                    } else if key.eq_ignore_ascii_case(b"Received-Date") {
                        if let HeaderValue::DateTime(dt) = MessageStream::new(value).parse_date() {
                            f.arrival_date = dt.to_timestamp().into();
                        }
                    }
                }
                Some(b'S' | b's') => {
                    if key.eq_ignore_ascii_case(b"SPF-DNS") {
                        f.spf_dns = Some(txt_value.into());
                    } else if key.eq_ignore_ascii_case(b"Source-IP") {
                        f.source_ip = if let Some((ip, _)) = txt_value.split_once(' ') {
                            ip.parse().ok()
                        } else {
                            txt_value.parse().ok()
                        };
                    } else if key.eq_ignore_ascii_case(b"Source-Port") {
                        f.source_port = txt_value.parse().unwrap_or(0);
                    }
                }
                Some(b'U' | b'u') => {
                    if key.eq_ignore_ascii_case(b"User-Agent") {
                        f.user_agent = Some(txt_value.into());
                    }
                }
                Some(b'V' | b'v') => {
                    if key.eq_ignore_ascii_case(b"Version") {
                        f.version = txt_value.parse().unwrap_or(0);
                    }
                }
                _ => (),
            }
        }

        if has_ft {
            Some(f)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use std::{fs, path::PathBuf};

    use crate::report::Feedback;

    #[test]
    fn arf_report_parse() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arf");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let mut file_name = file_name.unwrap().path();
            if !file_name.extension().unwrap().to_str().unwrap().eq("eml") {
                continue;
            }
            println!("Parsing ARF feedback {}", file_name.to_str().unwrap());

            let arf = fs::read(&file_name).unwrap();
            let mut feedback = Feedback::parse_rfc5322(&arf).unwrap();
            feedback.message = None;

            file_name.set_extension("json");

            let expected_feedback =
                serde_json::from_slice::<Feedback>(&fs::read(&file_name).unwrap()).unwrap();

            assert_eq!(expected_feedback, feedback);

            /*fs::write(
                &file_name,
                serde_json::to_string_pretty(&feedback).unwrap().as_bytes(),
            )
            .unwrap();*/
        }
    }
}
