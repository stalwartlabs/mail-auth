/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::time::SystemTime;

use mail_builder::encoders::base64::base64_encode;

use crate::{
    common::{
        crypto::{HashAlgorithm, HashContext, Sha256, SigningKey},
        headers::Writer,
    },
    dkim::{Canonicalization, Done},
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
        let mut header_hasher = self.key.hasher();
        let signed_headers = set
            .signature
            .canonicalize_headers(message, &mut header_hasher)?;

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Canonicalize body
        if set.signature.l > 0 {
            set.signature.l = (message.raw_message.len() - message.body_offset) as u64;
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
            let mut body_hasher = self.key.hasher();
            set.signature.cb.canonicalize_body(
                message
                    .raw_message
                    .get(message.body_offset..)
                    .unwrap_or_default(),
                &mut body_hasher,
            );
            set.signature.bh = base64_encode(body_hasher.complete().as_ref())?;
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

        // Add signature to hash
        set.signature.write(&mut header_hasher, false);

        // Sign
        let b = self.key.sign(header_hasher.complete())?;
        set.signature.b = base64_encode(&b)?;

        // Hash ARC chain
        let mut header_hasher = self.key.hasher();
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
            );
        }

        // Hash ARC headers for the current instance
        set.results.write(&mut header_hasher, set.seal.i, false);
        set.signature.write(&mut header_hasher, false);
        header_hasher.write(b"\r\n");
        set.seal.write(&mut header_hasher, false);

        // Seal
        let b = self.key.sign(header_hasher.complete())?;
        set.seal.b = base64_encode(&b)?;

        Ok(set)
    }
}

impl Signature {
    pub(crate) fn canonicalize_headers<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        header_hasher: &mut impl Writer,
    ) -> crate::Result<Vec<String>> {
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

        self.ch
            .canonicalize_headers(&mut headers.into_iter().rev(), header_hasher);

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string());
            }
        }

        Ok(signed_headers)
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use std::time::{Duration, Instant};

    use mail_parser::decoders::base64::base64_decode;

    use crate::{
        arc::ArcSealer,
        common::{
            crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
            headers::HeaderWriter,
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::DkimSigner,
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
        #[cfg(feature = "test")]
        {
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
        }

        // Create private keys
        let pk_ed_public =
            base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap();
        let pk_ed_private = base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap();

        // Create DKIM-signed message
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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
            let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();

            raw_message = arc_verify_and_seal(
                &resolver,
                &raw_message,
                "scamorza.org",
                "ed",
                Ed25519Key::from_bytes(&pk_ed_public, &pk_ed_private).unwrap(),
            )
            .await;
            raw_message =
                arc_verify_and_seal(&resolver, &raw_message, "manchego.org", "rsa", pk_rsa).await;
        }

        //println!("{}", raw_message);
    }

    async fn arc_verify_and_seal(
        resolver: &Resolver,
        raw_message: &str,
        d: &str,
        s: &str,
        pk: impl SigningKey<Hasher = Sha256>,
    ) -> String {
        let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
        let dkim_result = resolver.verify_dkim(&message).await;
        let arc_result = resolver.verify_arc(&message).await;
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
            .unwrap_or_else(|err| panic!("Got {:?} for {}", err, raw_message));
        format!(
            "{}{}{}",
            arc.to_header(),
            auth_results.to_header(),
            raw_message
        )
    }
}
