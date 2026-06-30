/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainBinding, Dkim2Result, Signature, sign::Envelope, verify::relaxed_domain_match};
use crate::{
    AuthenticatedMessage, MX, MessageAuthenticator, Parameters, RecordSet, ResolverCache, Txt,
    dkim2::sign::now,
};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2Dsn<'x> {
    pub raw: AuthenticatedMessage<'x>,
    pub returned: AuthenticatedMessage<'x>,
    pub returned_full: bool,
}

impl<'x> Dkim2Dsn<'x> {
    /// Creates a new Dkim2Dsn from the raw DSN and the returned message
    pub fn new(
        raw: AuthenticatedMessage<'x>,
        returned: AuthenticatedMessage<'x>,
        returned_full: bool,
    ) -> Self {
        Dkim2Dsn {
            raw,
            returned,
            returned_full,
        }
    }

    /// Parses a multipart/report DSN and locates the embedded returned message
    /// (message/rfc822 or text/rfc822-headers).
    pub fn parse(raw_message: &'x [u8]) -> Result<Dkim2Dsn<'x>, Dkim2DsnFailure> {
        let message = MessageParser::new()
            .parse(raw_message)
            .ok_or(Dkim2DsnFailure::DsnUnparseable)?;
        let PartType::Multipart(children) = &message.root_part().body else {
            return Err(Dkim2DsnFailure::DsnUnparseable);
        };

        let mut returned = None;
        for child in children {
            let part = message
                .parts
                .get(*child as usize)
                .ok_or(Dkim2DsnFailure::DsnUnparseable)?;
            let slice = raw_message
                .get(part.offset_body as usize..part.offset_end as usize)
                .ok_or(Dkim2DsnFailure::DsnUnparseable)?;
            if part.is_content_type("message", "rfc822") {
                returned = Some((slice, true));
            } else if part.is_content_type("text", "rfc822-headers") {
                returned = Some((slice, false));
            }
        }

        let (returned_slice, returned_full) =
            returned.ok_or(Dkim2DsnFailure::ReturnedUnparseable)?;
        Ok(Dkim2Dsn {
            raw: AuthenticatedMessage::parse(raw_message).ok_or(Dkim2DsnFailure::DsnUnparseable)?,
            returned: AuthenticatedMessage::parse(returned_slice)
                .ok_or(Dkim2DsnFailure::ReturnedUnparseable)?,
            returned_full,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2DsnOutput {
    pub dsn: Dkim2Result,
    pub returned: Dkim2Result,
}

/// Why an inbound DSN failed authentication (draft-ietf-dkim-dkim2-spec-03 §12.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dkim2DsnFailure {
    DsnUnparseable,
    ReturnedUnparseable,
    DsnNotSigned,
    DsnChainFailed,
    ReturnedNotSigned,
    ReturnedChainFailed,
    NotAligned,
}

impl std::fmt::Display for Dkim2DsnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Dkim2DsnFailure::DsnUnparseable => "DSN could not be parsed",
            Dkim2DsnFailure::ReturnedUnparseable => "Returned message could not be parsed",
            Dkim2DsnFailure::DsnNotSigned => "DSN is not DKIM2 signed",
            Dkim2DsnFailure::DsnChainFailed => "DSN signature chain failed",
            Dkim2DsnFailure::ReturnedNotSigned => "Returned message is not DKIM2 signed",
            Dkim2DsnFailure::ReturnedChainFailed => "Returned message signature chain failed",
            Dkim2DsnFailure::NotAligned => {
                "DSN signer is not aligned with the returned message recipient"
            }
        })
    }
}

fn top_signature<'x>(
    message: &'x AuthenticatedMessage<'x>,
) -> Option<(&'x String, &'x str, &'x [String])> {
    let top = message
        .dkim2_signatures
        .iter()
        .map(|h| &h.header)
        .max_by_key(|s| s.i)?;
    match &top.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => {
            Some((&top.d, mail_from, rcpt_to.as_slice()))
        }
        ChainBinding::NextDomain(_) => Some((&top.d, "", &[])),
    }
}

fn domain_of(address: &str) -> &str {
    let address = address.trim_start_matches('<').trim_end_matches('>');
    address.rsplit_once('@').map(|(_, d)| d).unwrap_or(address)
}

fn is_dkim2_signed(message: &AuthenticatedMessage<'_>) -> bool {
    !message.dkim2_signatures.is_empty() || message.has_dkim2_errors
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
    ) -> Result<Dkim2DsnOutput, Dkim2DsnFailure>
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
    {
        let params = params.into();
        self.verify_dkim2_dsn_(params.params, envelope, params.cache_txt, now())
            .await
    }

    pub(crate) async fn verify_dkim2_dsn_<'x, TXT>(
        &self,
        dsn: &'x Dkim2Dsn<'x>,
        envelope: &Envelope<'x>,
        cache_txt: Option<&TXT>,
        now: u64,
    ) -> Result<Dkim2DsnOutput, Dkim2DsnFailure>
    where
        TXT: ResolverCache<Box<str>, Txt>,
    {
        if !is_dkim2_signed(&dsn.raw) {
            return Err(Dkim2DsnFailure::DsnNotSigned);
        } else if !is_dkim2_signed(&dsn.returned) {
            return Err(Dkim2DsnFailure::ReturnedNotSigned);
        }

        let dsn_output = self
            .verify_dkim2_(&dsn.raw, envelope, cache_txt, now, true)
            .await;
        let dsn_result = dsn_output.result;
        if !matches!(dsn_result, Dkim2Result::Pass) {
            return Err(Dkim2DsnFailure::DsnChainFailed);
        }

        let dsn_signing_domain = top_signature(&dsn.raw).map(|(d, _, _)| d);
        let returned_top = top_signature(&dsn.returned);
        let returned_envelope = returned_top
            .as_ref()
            .map(|(_, mail_from, rcpt_to)| (*mail_from, *rcpt_to))
            .unwrap_or_default();
        let returned_rcpts: Vec<&str> = returned_envelope.1.iter().map(|r| r.as_str()).collect();
        let returned_result = self
            .verify_dkim2_(
                &dsn.returned,
                &Envelope {
                    mail_from: returned_envelope.0,
                    rcpt_to: &returned_rcpts,
                },
                cache_txt,
                now,
                dsn.returned_full,
            )
            .await
            .result;
        if !matches!(returned_result, Dkim2Result::Pass) {
            return Err(Dkim2DsnFailure::ReturnedChainFailed);
        };

        let aligned = match (&dsn_signing_domain, &returned_top) {
            (Some(dsn_domain), Some((returned_domain, _, rcpt_to))) => {
                // 12.1.2(1): the DSN signer is aligned with the recipient
                // recorded in the rt= tag of the returned message's top signature.
                let recipient_aligned = rcpt_to
                    .iter()
                    .any(|rcpt| relaxed_domain_match(domain_of(rcpt), dsn_domain));

                // 12.1.2(2): the returned message's top signature was generated
                // by us, the system receiving the DSN.
                let returned_is_ours = envelope
                    .rcpt_to
                    .iter()
                    .any(|rcpt| relaxed_domain_match(domain_of(rcpt), returned_domain));

                recipient_aligned && returned_is_ours
            }
            _ => false,
        };

        if aligned {
            Ok(Dkim2DsnOutput {
                dsn: dsn_result,
                returned: returned_result,
            })
        } else {
            Err(Dkim2DsnFailure::NotAligned)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Dkim2Dsn, Dkim2DsnFailure, Dkim2DsnOutput, Signature};
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

    const RETURNED_PLAIN: &str = concat!(
        "From: sender@test1.dkim2.com\r\n",
        "To: user@test2.dkim2.com\r\n",
        "Subject: Hello\r\n",
        "Date: Sat, 01 Mar 2026 12:00:00 +0000\r\n",
        "Message-ID: <m@test1.dkim2.com>\r\n",
        "\r\n",
        "This is the original body.\r\n",
    );

    fn signed_returned() -> Vec<u8> {
        sign_full(
            load_key("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "ed25519",
            RETURNED_PLAIN.as_bytes(),
            &Hop::Real(Envelope {
                mail_from: "sender@test1.dkim2.com",
                rcpt_to: &["user@test2.dkim2.com"],
            }),
        )
    }

    fn headers_only(message: &[u8]) -> Vec<u8> {
        let end = message.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        message[..end].to_vec()
    }

    fn make_dsn(returned: &[u8], returned_ct: &str, dsn_signed: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: text/plain\r\n\r\n");
        body.extend_from_slice(b"Delivery to user@test2.dkim2.com failed.\r\n");
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: message/delivery-status\r\n\r\n");
        body.extend_from_slice(b"Reporting-MTA: dns; test2.dkim2.com\r\n\r\n");
        body.extend_from_slice(b"Final-Recipient: rfc822; user@test2.dkim2.com\r\n");
        body.extend_from_slice(b"Action: failed\r\nStatus: 5.1.1\r\n");
        body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: ");
        body.extend_from_slice(returned_ct.as_bytes());
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(returned);
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

        if dsn_signed {
            sign_full(
                load_key("test2.dkim2.com", "ed25519"),
                "test2.dkim2.com",
                "ed25519",
                &dsn_plain,
                &Hop::Real(Envelope {
                    mail_from: "<>",
                    rcpt_to: &["sender@test1.dkim2.com"],
                }),
            )
        } else {
            dsn_plain
        }
    }

    async fn verify(dsn_bytes: &[u8]) -> Result<Dkim2DsnOutput, Dkim2DsnFailure> {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let dsn = Dkim2Dsn::parse(dsn_bytes).expect("parse DSN");
        let params = caches.parameters(&dsn);
        let envelope = Envelope {
            mail_from: "<>",
            rcpt_to: &["sender@test1.dkim2.com"],
        };
        resolver
            .verify_dkim2_dsn_(&dsn, &envelope, params.cache_txt, NOW)
            .await
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
        let dsn_signed = make_dsn(&signed_returned(), "message/rfc822", true);
        assert!(Dkim2Dsn::parse(&dsn_signed).unwrap().returned_full);

        let output = verify(&dsn_signed).await;
        assert!(output.is_ok(), "{output:?}");
    }

    #[tokio::test]
    async fn verify_dsn_returned_headers_only() {
        let dsn_signed = make_dsn(
            &headers_only(&signed_returned()),
            "text/rfc822-headers",
            true,
        );
        assert!(!Dkim2Dsn::parse(&dsn_signed).unwrap().returned_full);

        let output = verify(&dsn_signed).await;
        assert!(output.is_ok(), "{output:?}");
    }

    #[tokio::test]
    async fn verify_dsn_returned_not_signed() {
        let dsn_signed = make_dsn(RETURNED_PLAIN.as_bytes(), "message/rfc822", true);

        let output = verify(&dsn_signed).await;
        assert_eq!(output, Err(Dkim2DsnFailure::ReturnedNotSigned));
    }

    #[tokio::test]
    async fn verify_dsn_not_signed() {
        let dsn_unsigned = make_dsn(&signed_returned(), "message/rfc822", false);

        let output = verify(&dsn_unsigned).await;
        assert_eq!(output, Err(Dkim2DsnFailure::DsnNotSigned));
    }
}
