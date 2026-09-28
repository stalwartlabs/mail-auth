/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Authentication of inbound DKIM2-signed delivery status notifications
//! (§12.1.2) through [`MessageAuthenticator::verify_dkim2_dsn`].

use super::{ChainBinding, Dkim2Result, Signature, sign::Envelope, verify::relaxed_domain_match};
use crate::dns::DnsCache;
use crate::{
    AuthenticatedMessage, MessageAuthenticator, Parameters, ResolverCache, TxtRecord,
    dkim2::sign::now, dns::NoCache,
};
use mail_parser::MessageParser;
use std::marker::PhantomData;

/// An inbound delivery status notification (DSN) and the message it returns.
///
/// Input of [`MessageAuthenticator::verify_dkim2_dsn`]. Build it with
/// [`Dkim2Dsn::parse`] from a raw `multipart/report` DSN, or with
/// [`Dkim2Dsn::new`] from messages parsed by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2Dsn<'x, R = AuthenticatedMessage<'x>, S = AuthenticatedMessage<'x>>
where
    R: AsRef<AuthenticatedMessage<'x>>,
    S: AsRef<AuthenticatedMessage<'x>>,
{
    /// The DSN message itself, including its own DKIM2 header fields.
    pub dsn: R,
    /// The returned message embedded in the DSN.
    pub returned: S,
    /// Whether `returned` includes the body (`message/rfc822`) or only the
    /// header fields (`text/rfc822-headers`). Without the body, body hashes
    /// are not checked.
    pub returned_full: bool,
    _marker: PhantomData<&'x ()>,
}

impl<'x, R, S> Dkim2Dsn<'x, R, S>
where
    R: AsRef<AuthenticatedMessage<'x>>,
    S: AsRef<AuthenticatedMessage<'x>>,
{
    /// Creates a `Dkim2Dsn` from the parsed DSN, the parsed returned message
    /// and whether the returned message includes its body.
    pub fn new(dsn: R, returned: S, returned_full: bool) -> Self {
        Dkim2Dsn {
            dsn,
            returned,
            returned_full,
            _marker: PhantomData,
        }
    }
}

impl<'x> Dkim2Dsn<'x> {
    /// Parses a `multipart/report` DSN and locates the embedded returned
    /// message, a `message/rfc822` or `text/rfc822-headers` part. If several
    /// parts qualify, the last one is used.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2DsnFailure::DsnUnparseable`] if `raw_message` is not a
    /// parseable multipart message, and
    /// [`Dkim2DsnFailure::ReturnedUnparseable`] if it has no returned message
    /// part or that part cannot be parsed.
    pub fn parse(raw_message: &'x [u8]) -> Result<Dkim2Dsn<'x>, Dkim2DsnFailure> {
        let message = MessageParser::new()
            .parse(raw_message)
            .ok_or(Dkim2DsnFailure::DsnUnparseable)?;
        let root = message.root_part();
        if !root.is_multipart() {
            return Err(Dkim2DsnFailure::DsnUnparseable);
        }

        let mut returned = None;
        for part in root.children() {
            let slice = raw_message
                .get(part.offset_body() as usize..part.offset_end() as usize)
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
            dsn: AuthenticatedMessage::parse(raw_message).ok_or(Dkim2DsnFailure::DsnUnparseable)?,
            returned: AuthenticatedMessage::parse(returned_slice)
                .ok_or(Dkim2DsnFailure::ReturnedUnparseable)?,
            returned_full,
            _marker: PhantomData,
        })
    }
}

/// Result of a successful
/// [`MessageAuthenticator::verify_dkim2_dsn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2DsnOutput {
    /// Verification result of the DSN's own DKIM2 chain.
    pub dsn: Dkim2Result,
    /// Verification result of the returned message's DKIM2 chain.
    pub returned: Dkim2Result,
}

/// Reason an inbound DSN failed parsing or authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dkim2DsnFailure {
    /// The DSN is not a parseable multipart message.
    DsnUnparseable,
    /// The DSN has no returned message part, or it cannot be parsed.
    ReturnedUnparseable,
    /// The DSN has no `DKIM2-Signature` header field, not even a malformed
    /// one.
    DsnNotSigned,
    /// The DSN's DKIM2 chain did not pass verification.
    DsnChainFailed,
    /// The returned message has no `DKIM2-Signature` header field.
    ReturnedNotSigned,
    /// The returned message's DKIM2 chain did not pass verification.
    ReturnedChainFailed,
    /// The DSN signer is not a recipient of the returned message, or the
    /// returned message was not last signed by the receiving system.
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
    message
        .dkim2_signatures
        .iter()
        .map(|h| &h.header)
        .max_by_key(|s| s.i)
        .map(|top| match &top.chain {
            ChainBinding::Envelope { mail_from, rcpt_to } => {
                (&top.d, mail_from.as_str(), rcpt_to.as_slice())
            }
            ChainBinding::NextDomain(_) => (&top.d, "", &[][..]),
        })
}

fn domain_of(address: &str) -> &str {
    let address = address.trim_start_matches('<').trim_end_matches('>');
    address.rsplit_once('@').map(|(_, d)| d).unwrap_or(address)
}

fn is_dkim2_signed(message: &AuthenticatedMessage<'_>) -> bool {
    !message.dkim2_signatures.is_empty() || message.has_dkim2_errors
}

impl AuthenticatedMessage<'_> {
    /// Returns the address a DSN about this message must be sent to.
    ///
    /// This is the `mf=` (`MAIL FROM`) of the signature with the highest
    /// `i=`, including angle brackets. Returns `None` if the message has no
    /// DKIM2 signature, if that signature uses `nd=`, or if its `MAIL FROM`
    /// is the null reverse-path `<>`. Signatures that failed to parse are
    /// not considered, so when [`has_dkim2_errors`](Self::has_dkim2_errors)
    /// is `true` the address may come from an older hop.
    pub fn dkim2_return_path(&self) -> Option<&str> {
        dsn_return_path(self.dkim2_signatures.iter().map(|header| &header.header))
    }
}

fn dsn_return_path<'x>(signatures: impl Iterator<Item = &'x Signature>) -> Option<&'x str> {
    signatures
        .max_by_key(|s| s.i)
        .and_then(|top| match &top.chain {
            ChainBinding::Envelope { mail_from, .. }
                if !mail_from.is_empty() && mail_from != "<>" =>
            {
                Some(mail_from.as_str())
            }
            _ => None,
        })
}

impl MessageAuthenticator {
    /// Authenticates an inbound DKIM2-signed delivery status notification
    /// (§12.1.2).
    ///
    /// `params` wraps the [`Dkim2Dsn`], optionally with a DNS cache (see
    /// [`Parameters`]). `envelope` is the SMTP envelope the DSN was received
    /// with, usually with a null `MAIL FROM` (`<>`).
    ///
    /// Both messages must be DKIM2 signed. The DSN is verified against
    /// `envelope` as with
    /// [`verify_dkim2`](MessageAuthenticator::verify_dkim2). The returned
    /// message is verified against the envelope recorded in its most recent
    /// signature; its body hashes are checked only when
    /// [`Dkim2Dsn::returned_full`] is true. Finally the DSN must be aligned
    /// with the returned message:
    ///
    /// 1. The DSN signing domain relaxed-matches the domain of an `rt=`
    ///    recipient in the returned message's most recent signature.
    /// 2. The `d=` of that signature relaxed-matches the domain of an
    ///    `envelope` `RCPT TO` address, which shows that the receiving system
    ///    made it.
    ///
    /// Each chain costs one DNS TXT lookup per `s=` entry of each signature,
    /// for the public key at `<selector>._domainkey.<d>`.
    ///
    /// On success both fields of [`Dkim2DsnOutput`] are
    /// [`Dkim2Result::Pass`].
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2DsnFailure::DsnNotSigned`] or
    /// [`Dkim2DsnFailure::ReturnedNotSigned`] if a message has no
    /// `DKIM2-Signature` header field, [`Dkim2DsnFailure::DsnChainFailed`] or
    /// [`Dkim2DsnFailure::ReturnedChainFailed`] if a chain does not pass
    /// (including temporary DNS failures), and
    /// [`Dkim2DsnFailure::NotAligned`] if the alignment checks fail.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{
    ///     MessageAuthenticator, Parameters,
    ///     dkim2::{Dkim2Dsn, Envelope},
    /// };
    ///
    /// # async fn run(raw_dsn: &[u8]) {
    /// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
    /// let dsn = Dkim2Dsn::parse(raw_dsn).unwrap();
    ///
    /// let envelope = Envelope::new("<>", ["sender@example.com"]);
    /// match authenticator
    ///     .verify_dkim2_dsn(Parameters::new(&dsn), envelope)
    ///     .await
    /// {
    ///     Ok(_) => println!("authentic DSN"),
    ///     Err(failure) => println!("DSN rejected: {failure}"),
    /// }
    /// # }
    /// ```
    pub async fn verify_dkim2_dsn<'x, R, S, C, A, RT>(
        &self,
        params: impl Into<Parameters<'x, &'x Dkim2Dsn<'x, R, S>, C>>,
        envelope: Envelope<A, RT>,
    ) -> Result<Dkim2DsnOutput, Dkim2DsnFailure>
    where
        R: AsRef<AuthenticatedMessage<'x>> + 'x,
        S: AsRef<AuthenticatedMessage<'x>> + 'x,
        C: DnsCache + 'x,
        A: AsRef<str> + Clone,
        RT: IntoIterator<Item: AsRef<str>> + Clone,
    {
        let params = params.into();
        self.verify_dkim2_dsn_(params.input, envelope, params.txt_cache(), now())
            .await
    }

    pub(crate) async fn verify_dkim2_dsn_<'x, R, S, TXT, A, RT>(
        &self,
        dsn: &'x Dkim2Dsn<'x, R, S>,
        envelope: Envelope<A, RT>,
        cache_txt: Option<&TXT>,
        now: u64,
    ) -> Result<Dkim2DsnOutput, Dkim2DsnFailure>
    where
        R: AsRef<AuthenticatedMessage<'x>> + 'x,
        S: AsRef<AuthenticatedMessage<'x>> + 'x,
        TXT: ResolverCache<Box<str>, TxtRecord>,
        A: AsRef<str> + Clone,
        RT: IntoIterator<Item: AsRef<str>> + Clone,
    {
        if !is_dkim2_signed(dsn.dsn.as_ref()) {
            return Err(Dkim2DsnFailure::DsnNotSigned);
        } else if !is_dkim2_signed(dsn.returned.as_ref()) {
            return Err(Dkim2DsnFailure::ReturnedNotSigned);
        }

        let dsn_output = self
            .verify_dkim2_(dsn.dsn.as_ref(), envelope.clone(), cache_txt, now, true)
            .await;
        let dsn_result = dsn_output.result;
        if !matches!(dsn_result, Dkim2Result::Pass) {
            return Err(Dkim2DsnFailure::DsnChainFailed);
        }

        let dsn_signing_domain = top_signature(dsn.dsn.as_ref()).map(|(d, _, _)| d);
        let returned_top = top_signature(dsn.returned.as_ref());
        let (returned_mail_from, returned_rcpt_to) = returned_top
            .as_ref()
            .map(|(_, mail_from, rcpt_to)| (*mail_from, *rcpt_to))
            .unwrap_or_default();
        let returned_result = self
            .verify_dkim2_(
                dsn.returned.as_ref(),
                Envelope::new(returned_mail_from, returned_rcpt_to),
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
                let recipient_aligned = rcpt_to
                    .iter()
                    .any(|rcpt| relaxed_domain_match(domain_of(rcpt), dsn_domain));

                let Envelope {
                    rcpt_to: envelope_rcpt_to,
                    ..
                } = envelope;
                let returned_is_ours = envelope_rcpt_to
                    .into_iter()
                    .any(|rcpt| relaxed_domain_match(domain_of(rcpt.as_ref()), returned_domain));

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

impl<'x, R, S> From<&'x Dkim2Dsn<'x, R, S>> for Parameters<'x, &'x Dkim2Dsn<'x, R, S>, NoCache>
where
    R: AsRef<AuthenticatedMessage<'x>>,
    S: AsRef<AuthenticatedMessage<'x>>,
{
    fn from(params: &'x Dkim2Dsn<'x, R, S>) -> Self {
        Parameters::new(params)
    }
}

#[cfg(test)]
mod test {
    use super::{Dkim2Dsn, Dkim2DsnFailure, Dkim2DsnOutput, Signature, dsn_return_path};
    use crate::{
        MessageAuthenticator,
        crypto::Ed25519Key,
        dkim::DomainKey,
        dkim2::{ChainBinding, Dkim2Signer, Envelope, Hop},
        dns::cache::test::DummyCaches,
        parse::TxtRecordParser,
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

    fn sign_full<A, R, I>(
        key: Ed25519Key,
        domain: &str,
        selector: &str,
        message: &[u8],
        hop: Hop<A, R, I>,
    ) -> Vec<u8>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
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
            Hop::real("sender@test1.dkim2.com", ["user@test2.dkim2.com"]),
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
                Hop::real("<>", ["sender@test1.dkim2.com"]),
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
        let envelope = Envelope::new("<>", ["sender@test1.dkim2.com"]);
        resolver
            .verify_dkim2_dsn_(&dsn, envelope, params.txt_cache(), NOW)
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
        assert_eq!(dsn_return_path(std::iter::once(&signature)), None);

        signature.chain = ChainBinding::Envelope {
            mail_from: "sender@test1.dkim2.com".to_string(),
            rcpt_to: vec!["recipient@example.com".to_string()],
        };
        assert_eq!(
            dsn_return_path(std::iter::once(&signature)),
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
