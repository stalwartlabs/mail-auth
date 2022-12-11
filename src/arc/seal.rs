/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{borrow::Cow, io::Write, time::SystemTime};

use mail_builder::encoders::base64::base64_encode;
use sha2::{Digest, Sha256};

use crate::{
    common::crypto::SigningKey, dkim::Canonicalization, ArcOutput, AuthenticatedMessage,
    AuthenticationResults, DkimResult, Error,
};

use super::{ArcSet, ChainValidation, Seal, Signature};

impl<'x> ArcSet<'x> {
    pub fn new(results: &'x AuthenticationResults) -> Self {
        ArcSet {
            signature: Signature::default(),
            seal: Seal::default(),
            results,
        }
    }

    pub fn seal(
        mut self,
        message: &'x AuthenticatedMessage<'x>,
        arc_output: &ArcOutput,
        with_key: &impl SigningKey<Hasher = Sha256>,
    ) -> crate::Result<Self> {
        if !arc_output.can_be_sealed() {
            return Err(Error::ARCInvalidCV);
        }

        // Set a=
        self.signature.a = with_key.algorithm();
        self.seal.a = with_key.algorithm();

        // Set i= and cv=
        if arc_output.set.is_empty() {
            self.signature.i = 1;
            self.seal.i = 1;
            self.seal.cv = ChainValidation::None;
        } else {
            let i = arc_output.set.last().unwrap().seal.header.i + 1;
            self.signature.i = i;
            self.seal.i = i;
            self.seal.cv = match &arc_output.result {
                DkimResult::Pass => ChainValidation::Pass,
                _ => ChainValidation::Fail,
            };
        }

        // Create hashes
        let mut body_hasher = with_key.hasher();
        let mut header_hasher = with_key.hasher();

        // Canonicalize headers and body
        let (body_len, signed_headers) =
            self.signature
                .canonicalize(message, &mut header_hasher, &mut body_hasher)?;

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Create Signature
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.signature.bh = base64_encode(&body_hasher.finalize())?;
        self.signature.t = now;
        self.signature.x = if self.signature.x > 0 {
            now + self.signature.x
        } else {
            0
        };
        self.signature.h = signed_headers;
        if self.signature.l > 0 {
            self.signature.l = body_len as u64;
        }

        // Add signature to hash
        self.signature.write(&mut header_hasher, false)?;

        // Sign
        let b = with_key.sign(&header_hasher.finalize())?;
        self.signature.b = base64_encode(&b)?;

        // Hash ARC chain
        let mut header_hasher = Sha256::new();
        if !arc_output.set.is_empty() {
            Canonicalization::Relaxed.canonicalize_headers(
                &mut arc_output.set.iter().flat_map(|set| {
                    [
                        (set.results.name, set.results.value),
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                    ]
                }),
                &mut header_hasher,
            )?;
        }

        // Hash ARC headers for the current instance
        self.results.write(&mut header_hasher, self.seal.i, false)?;
        self.signature.write(&mut header_hasher, false)?;
        header_hasher.write_all(b"\r\n")?;
        self.seal.write(&mut header_hasher, false)?;

        // Seal
        let b = with_key.sign(&header_hasher.finalize())?;
        self.seal.b = base64_encode(&b)?;

        Ok(self)
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = impl Into<Cow<'x, str>>>) -> Self {
        self.signature.h = headers.into_iter().map(|h| h.into()).collect();
        self
    }

    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: &'x str) -> Self {
        self.signature.d = domain.into();
        self.seal.d = domain.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: &'x str) -> Self {
        self.signature.s = selector.into();
        self.seal.s = selector.into();
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.signature.x = expiration;
        self
    }

    /// Include the body length in the signature.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.signature.l = u64::from(body_length);
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.signature.ch = ch;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.signature.cb = cb;
        self
    }
}

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn canonicalize(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        header_hasher: impl Write,
        body_hasher: impl Write,
    ) -> crate::Result<(usize, Vec<Cow<'x, str>>)> {
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

        let body_len = message.body.len();
        self.ch
            .canonicalize_headers(&mut headers.into_iter().rev(), header_hasher)?;
        self.cb.canonicalize_body(message.body, body_hasher)?;

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string().into());
            }
        }

        Ok((body_len, signed_headers))
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use mail_parser::decoders::base64::base64_decode;
    use sha2::Sha256;

    use crate::{
        arc::ArcSet,
        common::{
            crypto::{Ed25519Key, RsaKey, SigningKey},
            headers::HeaderWriter,
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::Signature,
        AuthenticatedMessage, AuthenticationResults, DkimResult, Resolver,
    };

    const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

    const RSA_PUBLIC_KEY: &str = concat!(
        "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
        "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
        "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
        "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
        "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
    );

    const ED25519_PRIVATE_KEY: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
    const ED25519_PUBLIC_KEY: &str =
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    #[tokio::test]
    async fn arc_seal() {
        let message = concat!(
            "From: queso@manchego.org\r\n",
            "To: affumicata@scamorza.org\r\n",
            "Subject: Say cheese\r\n",
            "\r\n",
            "We need to settle which one of us ",
            "is tastier.\r\n"
        );

        // Crate resolver
        let resolver = Resolver::new_system_conf().unwrap();
        resolver.txt_add(
            "rsa._domainkey.manchego.org.".to_string(),
            DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        resolver.txt_add(
            "ed._domainkey.scamorza.org.".to_string(),
            DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );

        // Create private keys
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let pk_ed = Ed25519Key::from_bytes(
            &base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap(),
            &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();

        // Create DKIM-signed message
        let mut raw_message = Signature::new()
            .headers(["From", "To", "Subject"])
            .domain("manchego.org")
            .selector("rsa")
            .sign(message.as_bytes(), &pk_rsa)
            .unwrap()
            .to_header()
            + message;

        // Verify and seal the message 50 times
        for _ in 0..25 {
            raw_message =
                arc_verify_and_seal(&resolver, &raw_message, "scamorza.org", "ed", &pk_ed).await;
            raw_message =
                arc_verify_and_seal(&resolver, &raw_message, "manchego.org", "rsa", &pk_rsa).await;
        }

        //println!("{}", raw_message);
    }

    async fn arc_verify_and_seal(
        resolver: &Resolver,
        raw_message: &str,
        d: &str,
        s: &str,
        pk: &impl SigningKey<Hasher = Sha256>,
    ) -> String {
        let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
        let dkim_result = resolver.verify_dkim(&message).await;
        let arc_result = resolver.verify_arc(&message).await;
        assert!(
            matches!(arc_result.result(), DkimResult::Pass | DkimResult::None),
            "ARC validation failed: {:?}",
            arc_result.result()
        );
        let auth_results = AuthenticationResults::new(d).with_dkim_result(&dkim_result, d);
        let arc = ArcSet::new(&auth_results)
            .domain(d)
            .selector(s)
            .headers(["From", "To", "Subject", "DKIM-Signature"])
            .seal(&message, &arc_result, pk)
            .unwrap_or_else(|err| panic!("Got {:?} for {}", err, raw_message));
        format!(
            "{}{}{}",
            arc.to_header(),
            auth_results.to_header(),
            raw_message
        )
    }
}
