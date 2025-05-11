/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::time::SystemTime;

use mail_builder::encoders::base64::base64_encode;

use crate::{
    common::{
        crypto::{HashAlgorithm, Sha256, SigningKey},
        headers::{Writable, Writer},
    },
    dkim::{canonicalize::CanonicalHeaders, Canonicalization, Done},
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimResult, Error,
};

use super::{ArcSealer, ArcSet, ChainValidation, Signature};

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, Done> {
    pub fn seal<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        results: &'x AuthenticationResults,
        arc_output: &ArcOutput,
    ) -> crate::Result<ArcSet<'x>> {
        if !arc_output.can_be_sealed() {
            return Err(Error::ArcInvalidCV);
        }

        // Create set
        let mut set = ArcSet {
            signature: self.signature.clone(),
            seal: self.seal.clone(),
            results,
        };

        // Set i= and cv=
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

        // Canonicalize headers
        let (canonical_headers, signed_headers) = set.signature.canonicalize_headers(message)?;
        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Canonicalize body
        if set.signature.l > 0 {
            set.signature.l = message.raw_message.len() as u64 - message.body_offset as u64;
        }
        let ha = HashAlgorithm::from(set.signature.a);
        if let Some((_, _, _, bh)) = message
            .body_hashes
            .iter()
            .find(|(c, h, l, _)| c == &set.signature.cb && h == &ha && l == &set.signature.l)
        {
            // Use cached hash
            set.signature.bh = base64_encode(bh)?;
        } else {
            let hash = self.key.hash(
                set.signature.cb.canonical_body(
                    message
                        .raw_message
                        .get(message.body_offset as usize..)
                        .unwrap_or_default(),
                    u64::MAX,
                ),
            );
            set.signature.bh = base64_encode(hash.as_ref())?;
        }

        // Create Signature
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        set.signature.t = now;
        set.signature.x = if set.signature.x > 0 {
            now + set.signature.x
        } else {
            0
        };
        set.signature.h = signed_headers;

        // Sign
        let b = self.key.sign(SignableSet {
            set: &set,
            headers: canonical_headers,
        })?;
        set.signature.b = base64_encode(&b)?;

        // Seal
        let b = self.key.sign(SignableChain {
            arc_output,
            set: &set,
        })?;
        set.seal.b = base64_encode(&b)?;

        Ok(set)
    }
}

struct SignableSet<'a> {
    set: &'a ArcSet<'a>,
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
    set: &'a ArcSet<'a>,
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
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        for (name, value) in &message.headers {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((*name, *value));
                found_headers[pos] = true;
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let canonical_headers = self.ch.canonical_headers(headers);

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string());
            }
        }

        Ok((canonical_headers, signed_headers))
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use std::time::{Duration, Instant};

    use mail_parser::{decoders::base64::base64_decode, MessageParser};

    use crate::{
        arc::ArcSealer,
        common::{
            cache::test::DummyCaches,
            crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
            headers::HeaderWriter,
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::DkimSigner,
        AuthenticatedMessage, AuthenticationResults, DkimResult, MessageAuthenticator,
    };

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

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[tokio::test]
    async fn arc_seal() {
        use crate::common::cache::test::DummyCaches;

        let message = concat!(
            "From: queso@manchego.org\r\n",
            "To: affumicata@scamorza.org\r\n",
            "Subject: Say cheese\r\n",
            "\r\n",
            "We need to settle which one of us ",
            "is tastier.\r\n"
        );

        // Crate resolver
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

        // Create private keys
        let pk_ed_public =
            base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap();
        let pk_ed_private = base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap();

        // Create DKIM-signed message
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        let mut raw_message = DkimSigner::from_key(pk_rsa)
            .domain("manchego.org")
            .selector("rsa")
            .headers(["From", "To", "Subject"])
            .sign(message.as_bytes())
            .unwrap()
            .to_header()
            + message;

        // Verify and seal the message 50 times
        for _ in 0..25 {
            #[cfg(feature = "rust-crypto")]
            let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
            #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
            let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

            raw_message = arc_verify_and_seal(
                &resolver,
                &caches,
                &raw_message,
                "scamorza.org",
                "ed",
                #[cfg(feature = "rust-crypto")]
                Ed25519Key::from_bytes(&pk_ed_private).unwrap(),
                #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
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

        //println!("{}", raw_message);
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
