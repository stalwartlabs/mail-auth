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

use super::{DkimSigner, Done, Signature};
use crate::{
    common::{
        crypto::{HashContext, SigningKey},
        headers::{ChainedHeaderIterator, HeaderIterator, HeaderStream},
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
        let mut body_hasher = self.key.hasher();
        let mut header_hasher = self.key.hasher();

        // Canonicalize headers and body
        let (body_len, signed_headers) =
            self.template
                .canonicalize(message, &mut header_hasher, &mut body_hasher);

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Create Signature
        let mut signature = self.template.clone();
        signature.bh = base64_encode(body_hasher.complete().as_ref())?;
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

        // Add signature to hash
        signature.write(&mut header_hasher, false);

        // Sign
        let b = self.key.sign(header_hasher.complete())?;

        // Encode
        signature.b = base64_encode(&b)?;

        Ok(signature)
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use mail_parser::decoders::base64::base64_decode;
    use trust_dns_resolver::proto::op::ResponseCode;

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

    #[test]
    fn dkim_sign() {
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
                "b=F5fBuwEyirUQRZwpEP1fKGil5rNqxL2e5kExeyGdByAvS2lp5",
                "M5CqGNzoJ9Pj8sGuGG rdD18uL0xOduqYN7uxifmD4u0BuTzaUSBQ",
                "hONWZxFq/BZ8rn6ylZCBS3NDuxFcRkcBtMAuZtGKO wito563yyb+",
                "Ujgtpc0DOZtntjyQGc=;",
            ),
            signature.to_string()
        );
    }

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
        let pk_ed = Ed25519Key::from_bytes(
            &base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap(),
            &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();

        // Create resolver
        let resolver = Resolver::new_system_conf().unwrap();
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

        // Test RSA-SHA256 relaxed/relaxed
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Test ED25519-SHA256 relaxed/relaxed
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

        // Test RSA-SHA256 simple/simple with duplicated headers
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Test RSA-SHA256 simple/relaxed with fixed body length
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Test AUID not matching domain
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Test expired signature and reporting
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Verify ATPS (failure)
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Verify ATPS (success)
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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

        // Verify ATPS (success - no hash)
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
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
            (result, expect) => panic!("Expected {:?} but got {:?}.", expect, result),
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
