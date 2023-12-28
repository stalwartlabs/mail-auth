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

use super::{canonicalize::CanonicalHeaders, DkimSigner, Done, Signature};

use crate::{
    common::{
        crypto::SigningKey,
        headers::{ChainedHeaderIterator, HeaderIterator, HeaderStream, Writable, Writer},
    },
    Error,
};

impl<T: SigningKey> DkimSigner<T, Done> {
    /// Signs a message.
    #[inline(always)]
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        self.sign_stream(
            HeaderIterator::new(message),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    #[inline(always)]
    /// Signs a chained message.
    pub fn sign_chained<'x>(
        &self,
        chunks: impl Iterator<Item = &'x [u8]>,
    ) -> crate::Result<Signature> {
        self.sign_stream(
            ChainedHeaderIterator::new(chunks),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    fn sign_stream<'x>(
        &self,
        message: impl HeaderStream<'x>,
        now: u64,
    ) -> crate::Result<Signature> {
        // Canonicalize headers and body
        let (body_len, canonical_headers, signed_headers, canonical_body) =
            self.template.canonicalize(message);

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Create Signature
        let mut signature = self.template.clone();
        let body_hash = self.key.hash(canonical_body);
        signature.bh = base64_encode(body_hash.as_ref())?;
        signature.t = now;
        signature.x = if signature.x > 0 {
            now + signature.x
        } else {
            0
        };
        signature.h = signed_headers;
        if signature.l > 0 {
            signature.l = body_len as u64;
        }

        // Sign
        let b = self.key.sign(SignableMessage {
            headers: canonical_headers,
            signature: &signature,
        })?;

        // Encode
        signature.b = base64_encode(&b)?;

        Ok(signature)
    }
}

pub(super) struct SignableMessage<'a> {
    headers: CanonicalHeaders<'a>,
    signature: &'a Signature,
}

impl<'a> Writable for SignableMessage<'a> {
    fn write(self, writer: &mut impl Writer) {
        self.headers.write(writer);
        self.signature.write(writer, false);
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use std::time::{Duration, Instant};

    use hickory_resolver::proto::op::ResponseCode;
    use mail_parser::decoders::base64::base64_decode;

    use crate::{
        common::{
            crypto::{Ed25519Key, RsaKey, Sha256},
            headers::HeaderIterator,
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::{Atps, Canonicalization, DkimSigner, DomainKeyReport, HashAlgorithm, Signature},
        AuthenticatedMessage, DkimOutput, DkimResult, Resolver,
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
    #[test]
    fn dkim_sign() {
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(feature = "rust-crypto")]
        let pk = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let signature = DkimSigner::from_key(pk)
            .domain("stalw.art")
            .selector("default")
            .headers(["From", "To", "Subject"])
            .sign_stream(
                HeaderIterator::new(
                    concat!(
                        "From: hello@stalw.art\r\n",
                        "To: dkim@stalw.art\r\n",
                        "Subject: Testing  DKIM!\r\n\r\n",
                        "Here goes the test\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                311923920,
            )
            .unwrap();

        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=rsa-sha256; s=default; d=stalw.art; ",
                "c=relaxed/relaxed; h=Subject:To:From; t=311923920; ",
                "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Yl m5s=; ",
                "b=B/p1FPSJ+Jl4A94381+DTZZnNO4c3fVqDnj0M0Vk5JuvnKb5",
                "dKSwaoIHPO8UUJsroqH z+R0/eWyW1Vlz+uMIZc2j7MVPJcGaY",
                "Ni85uCQbPd8VpDKWWab6m21ngXYIpagmzKOKYllyOeK3X qwDz",
                "Bo0T2DdNjGyMUOAWHxrKGU+fbcPHQYxTBCpfOxE/nc/uxxqh+i",
                "2uXrsxz7PdCEN01LZiYVV yOzcv0ER9A7aDReE2XPVHnFL8jxE",
                "2BD53HRv3hGkIDcC6wKOKG/lmID+U8tQk5CP0dLmprgjgTv Se",
                "bu6xNc6SSIgpvwryAAzJEVwmaBqvE8RNk3Vg10lBZEuNsj2Q==;",
            ),
            signature.to_string()
        );
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[tokio::test]
    async fn dkim_sign_verify() {
        let message = concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great.\r\n"
        );
        let empty_message = concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: Empty TPS Report\r\n",
            "\r\n",
            "\r\n"
        );
        let message_multiheader = concat!(
            "X-Duplicate-Header: 4\r\n",
            "From: bill@example.com\r\n",
            "X-Duplicate-Header: 3\r\n",
            "To: jdoe@example.com\r\n",
            "X-Duplicate-Header: 2\r\n",
            "Subject: TPS Report\r\n",
            "X-Duplicate-Header: 1\r\n",
            "To: jane@example.com\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great.\r\n"
        );

        // Create private keys
        #[cfg(feature = "rust-crypto")]
        let pk_ed = Ed25519Key::from_bytes(&base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap())
            .unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_ed = Ed25519Key::from_seed_and_public_key(
            &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
            &base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap(),
        )
        .unwrap();

        // Create resolver
        let resolver = Resolver::new_system_conf().unwrap();
        #[cfg(any(test, feature = "test"))]
        {
            resolver.txt_add(
                "default._domainkey.example.com.".to_string(),
                DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
            resolver.txt_add(
                "ed._domainkey.example.com.".to_string(),
                DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
            resolver.txt_add(
                "_report._domainkey.example.com.".to_string(),
                DomainKeyReport::parse("ra=dkim-failures; rp=100; rr=x".as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
        }

        dbg!("Test RSA-SHA256 relaxed/relaxed");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        dbg!("Test ED25519-SHA256 relaxed/relaxed");
        verify(
            &resolver,
            DkimSigner::from_key(pk_ed)
                .domain("example.com")
                .selector("ed")
                .headers(["From", "To", "Subject"])
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        dbg!("Test RSA-SHA256 relaxed/relaxed with an empty message");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(empty_message.as_bytes())
                .unwrap(),
            empty_message,
            Ok(()),
        )
        .await;

        dbg!("Test RSA-SHA256 simple/simple with an empty message");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .header_canonicalization(Canonicalization::Simple)
                .body_canonicalization(Canonicalization::Simple)
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(empty_message.as_bytes())
                .unwrap(),
            empty_message,
            Ok(()),
        )
        .await;

        dbg!("Test RSA-SHA256 simple/simple with duplicated headers");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers([
                    "From",
                    "To",
                    "Subject",
                    "X-Duplicate-Header",
                    "X-Does-Not-Exist",
                ])
                .header_canonicalization(Canonicalization::Simple)
                .body_canonicalization(Canonicalization::Simple)
                .sign(message_multiheader.as_bytes())
                .unwrap(),
            message_multiheader,
            Ok(()),
        )
        .await;

        dbg!("Test RSA-SHA256 simple/relaxed with fixed body length");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .header_canonicalization(Canonicalization::Simple)
                .body_length(true)
                .sign(message.as_bytes())
                .unwrap(),
            &(message.to_string() + "\r\n----- Mailing list"),
            Ok(()),
        )
        .await;

        dbg!("Test AUID not matching domains");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .agent_user_identifier("@wrongdomain.com")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Err(super::Error::FailedAuidMatch),
        )
        .await;

        dbg!("Test expired signature and reporting");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        let r = verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .expiration(12345)
                .reporting(true)
                .sign_stream(HeaderIterator::new(message.as_bytes()), 12345)
                .unwrap(),
            message,
            Err(super::Error::SignatureExpired),
        )
        .await
        .pop()
        .unwrap()
        .report;
        assert_eq!(r.as_deref(), Some("dkim-failures@example.com"));

        dbg!("Verify ATPS (failure)");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_stream(HeaderIterator::new(message.as_bytes()), 12345)
                .unwrap(),
            message,
            Err(super::Error::DnsRecordNotFound(ResponseCode::NXDomain)),
        )
        .await;

        dbg!("Verify ATPS (success)");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(any(test, feature = "test"))]
        resolver.txt_add(
            "UN42N5XOV642KXRXRQIYANHCOUPGQL5LT4WTBKYT2IJFLBWODFDQ._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_stream(HeaderIterator::new(message.as_bytes()), 12345)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        dbg!("Verify ATPS (success - no hash)");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(any(test, feature = "test"))]
        resolver.txt_add(
            "example.com._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .atps("example.com")
                .sign_stream(HeaderIterator::new(message.as_bytes()), 12345)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;
    }

    async fn verify<'x>(
        resolver: &Resolver,
        signature: Signature,
        message_: &'x str,
        expect: Result<(), super::Error>,
    ) -> Vec<DkimOutput<'x>> {
        let mut message = Vec::with_capacity(message_.len() + 100);
        signature.write(&mut message, true);
        message.extend_from_slice(message_.as_bytes());

        let message = AuthenticatedMessage::parse(&message).unwrap();
        let dkim = resolver.verify_dkim(&message).await;

        match (dkim.last().unwrap().result(), &expect) {
            (DkimResult::Pass, Ok(_)) => (),
            (
                DkimResult::Fail(hdr) | DkimResult::PermError(hdr) | DkimResult::Neutral(hdr),
                Err(err),
            ) if hdr == err => (),
            (result, expect) => panic!("Expected {expect:?} but got {result:?}."),
        }

        dkim.into_iter()
            .map(|d| DkimOutput {
                result: d.result,
                signature: None,
                report: d.report,
                is_atps: d.is_atps,
            })
            .collect()
    }
}
