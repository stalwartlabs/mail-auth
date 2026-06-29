/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainBinding, Dkim2Result, Signature, sign::Envelope};
use crate::{
    AuthenticatedMessage, MX, MessageAuthenticator, Parameters, RecordSet, ResolverCache, Txt,
};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2Dsn<'x> {
    pub raw: &'x [u8],
    pub human_readable: &'x [u8],
    pub delivery_status: &'x [u8],
    pub returned: ReturnedMessage<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnedMessage<'x> {
    Full(&'x [u8]),
    HeadersOnly(&'x [u8]),
}

impl<'x> ReturnedMessage<'x> {
    pub fn bytes(&self) -> &'x [u8] {
        match self {
            ReturnedMessage::Full(bytes) | ReturnedMessage::HeadersOnly(bytes) => bytes,
        }
    }
}

impl<'x> Dkim2Dsn<'x> {
    /// Parses a multipart/report DSN and locates the embedded returned message
    /// (message/rfc822 or text/rfc822-headers).
    pub fn parse(raw_message: &'x [u8]) -> Option<Dkim2Dsn<'x>> {
        let message = MessageParser::new().parse(raw_message)?;
        let PartType::Multipart(children) = &message.root_part().body else {
            return None;
        };

        let mut human_readable = None;
        let mut delivery_status = None;
        let mut returned = None;

        for child in children {
            let part = message.parts.get(*child as usize)?;
            let slice = raw_message.get(part.offset_body as usize..part.offset_end as usize)?;
            if part.is_content_type("message", "delivery-status") {
                delivery_status = Some(slice);
            } else if part.is_content_type("message", "rfc822") {
                returned = Some(ReturnedMessage::Full(slice));
            } else if part.is_content_type("text", "rfc822-headers") {
                returned = Some(ReturnedMessage::HeadersOnly(slice));
            } else if human_readable.is_none() {
                human_readable = Some(slice);
            }
        }

        Some(Dkim2Dsn {
            raw: raw_message,
            human_readable: human_readable?,
            delivery_status: delivery_status?,
            returned: returned?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2DsnOutput {
    pub dsn: Dkim2Result,
    pub returned: Dkim2Result,
    pub aligned: bool,
    pub(crate) failure: Option<String>,
}

impl Dkim2DsnOutput {
    pub fn is_authentic(&self) -> bool {
        matches!(self.dsn, Dkim2Result::Pass)
            && matches!(self.returned, Dkim2Result::Pass)
            && self.aligned
    }

    pub fn failure_reason(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

fn top_signature(message: &AuthenticatedMessage<'_>) -> Option<(String, String, Vec<String>)> {
    let top = message
        .dkim2_signatures
        .iter()
        .map(|h| &h.header)
        .max_by_key(|s| s.i)?;
    match &top.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => {
            Some((top.d.clone(), mail_from.clone(), rcpt_to.clone()))
        }
        ChainBinding::NextDomain(_) => Some((top.d.clone(), String::new(), Vec::new())),
    }
}

fn aligned_domain(recipient_domain: &str, signing_domain: &str) -> bool {
    let signing = signing_domain.to_ascii_lowercase();
    let mut current = recipient_domain.to_ascii_lowercase();
    loop {
        if current == signing {
            return true;
        }
        match current.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => current = rest.to_string(),
            _ => return false,
        }
    }
}

impl Signature {
    /// Returns the address a DSN for this message must be returned to
    pub fn dsn_return_path(signatures: &[Signature]) -> Option<&str> {
        let top = signatures.iter().max_by_key(|s| s.i)?;
        match &top.chain {
            ChainBinding::Envelope { mail_from, .. }
                if !mail_from.is_empty() && mail_from != "<>" =>
            {
                Some(mail_from)
            }
            _ => None,
        }
    }
}

impl MessageAuthenticator {
    /// Authenticates an inbound DKIM2-signed DSN
    pub async fn verify_dkim2_dsn<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, &'x Dkim2Dsn<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
        envelope: &Envelope<'x>,
    ) -> Dkim2DsnOutput
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
    {
        let params = params.into();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.verify_dkim2_dsn_(params.params, envelope, params.cache_txt, now)
            .await
    }

    pub(crate) async fn verify_dkim2_dsn_<'x, TXT>(
        &self,
        dsn: &'x Dkim2Dsn<'x>,
        envelope: &Envelope<'x>,
        cache_txt: Option<&TXT>,
        now: u64,
    ) -> Dkim2DsnOutput
    where
        TXT: ResolverCache<Box<str>, Txt>,
    {
        let Some(dsn_message) = AuthenticatedMessage::parse(dsn.raw) else {
            return Dkim2DsnOutput {
                dsn: Dkim2Result::None,
                returned: Dkim2Result::None,
                aligned: false,
                failure: Some("DSN could not be parsed".to_string()),
            };
        };
        let dsn_output = self
            .verify_dkim2_(&dsn_message, envelope, cache_txt, now)
            .await;
        let dsn_result = dsn_output.result().clone();
        let dsn_signing_domain = top_signature(&dsn_message).map(|(d, _, _)| d);

        let Some(returned_message) = AuthenticatedMessage::parse(dsn.returned.bytes()) else {
            return Dkim2DsnOutput {
                dsn: dsn_result,
                returned: Dkim2Result::None,
                aligned: false,
                failure: Some("Returned message could not be parsed".to_string()),
            };
        };
        let returned_top = top_signature(&returned_message);
        let returned_envelope = returned_top
            .as_ref()
            .map(|(_, mail_from, rcpt_to)| (mail_from.clone(), rcpt_to.clone()))
            .unwrap_or_default();
        let returned_rcpts: Vec<&str> = returned_envelope.1.iter().map(|r| r.as_str()).collect();
        let returned_output = self
            .verify_dkim2_(
                &returned_message,
                &Envelope {
                    mail_from: &returned_envelope.0,
                    rcpt_to: &returned_rcpts,
                },
                cache_txt,
                now,
            )
            .await;
        let returned_result = returned_output.result().clone();

        let aligned = match (dsn_signing_domain, returned_top) {
            (Some(dsn_domain), Some((_, _, rcpt_to))) => rcpt_to.iter().any(|rcpt| {
                let rcpt = rcpt.trim_start_matches('<').trim_end_matches('>');
                let domain = rcpt.rsplit_once('@').map(|(_, d)| d).unwrap_or(rcpt);
                aligned_domain(domain, &dsn_domain)
            }),
            _ => false,
        };

        let failure = if !matches!(dsn_result, Dkim2Result::Pass) {
            Some("DSN signature chain failed".to_string())
        } else if !matches!(returned_result, Dkim2Result::Pass) {
            Some("Returned message signature chain failed".to_string())
        } else if !aligned {
            Some("DSN signer is not aligned with the returned message recipient".to_string())
        } else {
            None
        };

        Dkim2DsnOutput {
            dsn: dsn_result,
            returned: returned_result,
            aligned,
            failure,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Dkim2Dsn, Signature};
    use crate::{
        MessageAuthenticator,
        common::{
            cache::test::DummyCaches, crypto::Ed25519Key, parse::TxtRecordParser, verify::DomainKey,
        },
        dkim2::{ChainBinding, Dkim2Signer, Envelope, Hop},
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };

    const NOW: u64 = 1740002100;
    const T: u64 = 1740000000;

    fn resource(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources/dkim2");
        for part in parts {
            path.push(part);
        }
        path
    }

    fn load_key(domain: &str, selector: &str) -> Ed25519Key {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    }

    fn load_caches() -> DummyCaches {
        let caches = DummyCaches::new();
        let dns = std::fs::read(resource(&["dns.json"])).unwrap();
        let dns: serde_json::Value = serde_json::from_slice(&dns).unwrap();
        let valid_until = Instant::now() + Duration::new(3600, 0);
        for (domain, selectors) in dns.as_object().unwrap() {
            for (selector, records) in selectors.as_object().unwrap() {
                caches.txt_add(
                    format!("{selector}.{domain}."),
                    DomainKey::parse(records[0][1].as_str().unwrap().as_bytes()).unwrap(),
                    valid_until,
                );
            }
        }
        caches
    }

    fn sign_full(
        key: Ed25519Key,
        domain: &str,
        selector: &str,
        message: &[u8],
        hop: &Hop,
    ) -> Vec<u8> {
        let signer = Dkim2Signer::from_key(key).domain(domain).selector(selector);
        let signed = signer.sign_at(message, hop, T).unwrap();
        let mut out = signed.to_header().into_bytes();
        out.extend_from_slice(message);
        out
    }

    #[test]
    fn dsn_return_path_null() {
        let mut signature = Signature {
            i: 1,
            chain: ChainBinding::Envelope {
                mail_from: "<>".to_string(),
                rcpt_to: vec!["recipient@example.com".to_string()],
            },
            ..Default::default()
        };
        assert_eq!(
            Signature::dsn_return_path(std::slice::from_ref(&signature)),
            None
        );

        signature.chain = ChainBinding::Envelope {
            mail_from: "sender@test1.dkim2.com".to_string(),
            rcpt_to: vec!["recipient@example.com".to_string()],
        };
        assert_eq!(
            Signature::dsn_return_path(std::slice::from_ref(&signature)),
            Some("sender@test1.dkim2.com")
        );
    }

    #[tokio::test]
    async fn verify_dsn_round_trip() {
        let returned_plain = concat!(
            "From: sender@test1.dkim2.com\r\n",
            "To: user@test2.dkim2.com\r\n",
            "Subject: Hello\r\n",
            "Date: Sat, 01 Mar 2026 12:00:00 +0000\r\n",
            "Message-ID: <m@test1.dkim2.com>\r\n",
            "\r\n",
            "This is the original body.\r\n",
        );
        let returned = sign_full(
            load_key("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "ed25519",
            returned_plain.as_bytes(),
            &Hop::Real(Envelope {
                mail_from: "sender@test1.dkim2.com",
                rcpt_to: &["user@test2.dkim2.com"],
            }),
        );

        let mut body = Vec::new();
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: text/plain\r\n\r\n");
        body.extend_from_slice(b"Delivery to user@test2.dkim2.com failed.\r\n");
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: message/delivery-status\r\n\r\n");
        body.extend_from_slice(b"Reporting-MTA: dns; test2.dkim2.com\r\n\r\n");
        body.extend_from_slice(b"Final-Recipient: rfc822; user@test2.dkim2.com\r\n");
        body.extend_from_slice(b"Action: failed\r\nStatus: 5.1.1\r\n");
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: message/rfc822\r\n\r\n");
        body.extend_from_slice(&returned);
        body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");

        let mut dsn_plain = Vec::new();
        dsn_plain.extend_from_slice(b"From: postmaster@test2.dkim2.com\r\n");
        dsn_plain.extend_from_slice(b"To: sender@test1.dkim2.com\r\n");
        dsn_plain.extend_from_slice(b"Subject: Delivery Status Notification (Failure)\r\n");
        dsn_plain.extend_from_slice(b"Date: Sat, 01 Mar 2026 12:05:00 +0000\r\n");
        dsn_plain.extend_from_slice(
            b"Content-Type: multipart/report; report-type=delivery-status; boundary=\"BOUNDARY\"\r\n",
        );
        dsn_plain.extend_from_slice(b"\r\n");
        dsn_plain.extend_from_slice(&body);

        let dsn_signed = sign_full(
            load_key("test2.dkim2.com", "ed25519"),
            "test2.dkim2.com",
            "ed25519",
            &dsn_plain,
            &Hop::Real(Envelope {
                mail_from: "<>",
                rcpt_to: &["sender@test1.dkim2.com"],
            }),
        );

        let dsn = Dkim2Dsn::parse(&dsn_signed).expect("parse DSN");
        assert!(matches!(dsn.returned, super::ReturnedMessage::Full(_)));

        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let params = caches.parameters(&dsn);
        let envelope = Envelope {
            mail_from: "<>",
            rcpt_to: &["sender@test1.dkim2.com"],
        };
        let output = resolver
            .verify_dkim2_dsn_(&dsn, &envelope, params.cache_txt, NOW)
            .await;

        assert!(
            output.is_authentic(),
            "dsn={:?} returned={:?} aligned={} reason={:?}",
            output.dsn,
            output.returned,
            output.aligned,
            output.failure_reason()
        );
    }
}
