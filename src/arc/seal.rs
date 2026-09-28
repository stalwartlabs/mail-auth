/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcError, ArcSealer, ChainValidation, SealedSet, Signature};
use crate::SystemTime;
use crate::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimResult, Error,
    crypto::{HashAlgorithm, Sha256, SigningKey},
    dkim::{
        Canonicalization,
        canonicalize::{CanonicalHeaders, FoundHeaders},
    },
    headers::{Writable, Writer},
    signer::Ready,
};

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, Ready> {
    /// Seals `message`, producing the next ARC set (RFC 8617, Section 5.1).
    ///
    /// `results` holds the `Authentication-Results` of this host, copied into
    /// the new `ARC-Authentication-Results`. `arc_output` is the result of
    /// [`MessageAuthenticator::verify_arc`](crate::MessageAuthenticator::verify_arc)
    /// on the same message: it sets the new instance number (one above the
    /// newest set, or 1 for an empty chain) and the `cv=` tag (`none` for an
    /// empty chain, `pass` when the chain validated, `fail` otherwise), and
    /// its sets are covered by the new `ARC-Seal`.
    ///
    /// Write the returned [`SealedSet`] in front of the message with
    /// [`HeaderWriter`](crate::headers::HeaderWriter).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Arc`] with [`ArcError::InvalidChainValidation`] when
    /// [`ArcOutput::can_be_sealed`] is `false`, [`Error::NoHeadersFound`]
    /// when the list of headers to sign is empty, and a crypto error when
    /// signing fails.
    pub fn seal<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        results: &'x AuthenticationResults,
        arc_output: &ArcOutput,
    ) -> crate::Result<SealedSet<'x>> {
        if !arc_output.can_be_sealed() {
            return Err(Error::Arc(ArcError::InvalidChainValidation));
        }

        let mut set = SealedSet {
            signature: self.signature.clone(),
            seal: self.seal.clone(),
            results,
        };

        if arc_output.set.is_empty() {
            set.signature.i = 1;
            set.seal.i = 1;
            set.seal.cv = ChainValidation::None;
        } else {
            let i = arc_output.set.last().unwrap().seal.header.i + 1;
            set.signature.i = i;
            set.seal.i = i;
            set.seal.cv = match &arc_output.result {
                DkimResult::Pass => ChainValidation::Pass,
                _ => ChainValidation::Fail,
            };
        }

        let (canonical_headers, signed_headers) = set.signature.canonicalize_headers(message)?;
        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        if set.signature.l > 0 {
            set.signature.l = message.raw_message.len() as u64 - message.body_offset as u64;
        }
        let ha = HashAlgorithm::from(set.signature.a);
        set.signature.bh = match message
            .body_hashes
            .iter()
            .find(|(c, h, l, _)| c == &set.signature.cb && h == &ha && l == &set.signature.l)
        {
            Some((_, _, _, bh)) => bh.clone(),
            None => self
                .key
                .hash(
                    set.signature.cb.canonical_body(
                        message
                            .raw_message
                            .get(message.body_offset as usize..)
                            .unwrap_or_default(),
                        u64::MAX,
                    ),
                )
                .as_ref()
                .to_vec(),
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        set.signature.t = now;
        set.signature.x = if set.signature.x > 0 {
            now.saturating_add(set.signature.x)
        } else {
            0
        };
        set.signature.h = signed_headers;

        set.signature.b = self.key.sign(SignableSet {
            set: &set,
            headers: canonical_headers,
        })?;

        set.seal.b = self.key.sign(SignableChain {
            arc_output,
            set: &set,
        })?;

        Ok(set)
    }
}

struct SignableSet<'a> {
    set: &'a SealedSet<'a>,
    headers: CanonicalHeaders<'a>,
}

impl Writable for SignableSet<'_> {
    fn write(self, writer: &mut impl Writer) {
        self.headers.write(writer);
        self.set.signature.write(writer, false);
    }
}

struct SignableChain<'a> {
    arc_output: &'a ArcOutput<'a>,
    set: &'a SealedSet<'a>,
}

impl Writable for SignableChain<'_> {
    fn write(self, writer: &mut impl Writer) {
        if !self.arc_output.set.is_empty() {
            Canonicalization::Relaxed.canonicalize_headers(
                self.arc_output.set.iter().flat_map(|set| {
                    [
                        (set.results.name, set.results.value),
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                    ]
                }),
                writer,
            );
        }

        self.set.results.write(writer, self.set.seal.i, false);
        self.set.signature.write(writer, false);
        writer.write(b"\r\n");
        self.set.seal.write(writer, false);
    }
}

impl Signature {
    pub(crate) fn canonicalize_headers<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
    ) -> crate::Result<(CanonicalHeaders<'x>, Vec<String>)> {
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = FoundHeaders::default();
        let mut signed_headers = Vec::with_capacity(self.h.len());

        for (name, value) in &message.headers {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((*name, *value));
                found_headers.insert(pos);
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let canonical_headers = self.ch.canonical_headers(headers);

        signed_headers.reverse();
        for (pos, header) in self.h.iter().enumerate() {
            if !found_headers.contains(pos) {
                signed_headers.push(header.to_string());
            }
        }

        Ok((canonical_headers, signed_headers))
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use crate::{
        AuthenticatedMessage, AuthenticationResults, DkimResult, MessageAuthenticator,
        arc::ArcSealer,
        crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
        dkim::DkimSigner,
        dkim::DomainKey,
        dns::cache::test::DummyCaches,
        headers::HeaderWriter,
        parse::TxtRecordParser,
    };
    use encodify::base64;
    use mail_parser::MessageParser;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, pem::PemObject};
    use std::time::{Duration, Instant};

    const RSA_PRIVATE_KEY: &str = include_str!("../../resources/rsa-private.pem");

    const RSA_PUBLIC_KEY: &str = concat!(
        "v=DKIM1; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ",
        "8AMIIBCgKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm",
        "1agrbcnSk5oIaEfMZLUR/X8gPzoiNHZcfMZEVR6bAytxUh",
        "c5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIaUmSACj0dL2/K",
        "wW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bW",
        "PZNkT4NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0",
        "TqgXdtw6A4Sdsp97VXT9fkPW9rso3lrkpsl/9EQ1mR/DWK",
        "6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Aed4l9",
        "WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQAB",
    );

    const ED25519_PRIVATE_KEY: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const ED25519_PUBLIC_KEY: &str =
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    #[tokio::test]
    async fn arc_seal() {
        use crate::dns::cache::test::DummyCaches;

        let message = concat!(
            "From: queso@manchego.org\r\n",
            "To: affumicata@scamorza.org\r\n",
            "Subject: Say cheese\r\n",
            "\r\n",
            "We need to settle which one of us ",
            "is tastier.\r\n"
        );

        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new()
            .with_txt(
                "rsa._domainkey.manchego.org.".to_string(),
                DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            )
            .with_txt(
                "ed._domainkey.scamorza.org.".to_string(),
                DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );

        let pk_ed_public = base64::LENIENT
            .decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1)
            .unwrap();
        let pk_ed_private = base64::LENIENT.decode(ED25519_PRIVATE_KEY).unwrap();

        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        let mut raw_message = DkimSigner::from_key(pk_rsa)
            .domain("manchego.org")
            .selector("rsa")
            .headers(["From", "To", "Subject"])
            .sign(message.as_bytes())
            .unwrap()
            .to_header()
            + message;

        for _ in 0..25 {
            let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
                PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
            ))
            .unwrap();

            raw_message = arc_verify_and_seal(
                &resolver,
                &caches,
                &raw_message,
                "scamorza.org",
                "ed",
                Ed25519Key::from_seed_and_public_key(&pk_ed_private, &pk_ed_public).unwrap(),
            )
            .await;
            raw_message = arc_verify_and_seal(
                &resolver,
                &caches,
                &raw_message,
                "manchego.org",
                "rsa",
                pk_rsa,
            )
            .await;
        }
    }

    async fn arc_verify_and_seal(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        raw_message: &str,
        d: &str,
        s: &str,
        pk: impl SigningKey<Hasher = Sha256>,
    ) -> String {
        let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
        assert_eq!(
            message,
            AuthenticatedMessage::from_parsed(
                &MessageParser::new().parse(raw_message).unwrap(),
                raw_message.as_bytes(),
                true
            )
        );
        let dkim_result = resolver.verify_dkim(caches.parameters(&message)).await;
        let arc_result = resolver.verify_arc(caches.parameters(&message)).await;
        assert!(
            matches!(arc_result.result(), DkimResult::Pass | DkimResult::None),
            "ARC validation failed: {:?}",
            arc_result.result()
        );
        let auth_results = AuthenticationResults::new(d).with_dkim_results(&dkim_result, d);
        let arc = ArcSealer::from_key(pk)
            .domain(d)
            .selector(s)
            .headers(["From", "To", "Subject", "DKIM-Signature"])
            .seal(&message, &auth_results, &arc_result)
            .unwrap_or_else(|err| panic!("Got {err:?} for {raw_message}"));
        format!(
            "{}{}{}",
            arc.to_header(),
            auth_results.to_header(),
            raw_message
        )
    }
}
