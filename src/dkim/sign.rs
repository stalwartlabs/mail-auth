/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{borrow::Cow, time::SystemTime};

use ed25519_dalek::Signer;
use mail_builder::encoders::base64::base64_encode;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::AssociatedOid, PaddingScheme, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{Error, PrivateKey};

use super::{Algorithm, Canonicalization, HashAlgorithm, Signature};

impl PrivateKey {
    /// Creates a new RSA private key from a PKCS1 PEM string.
    pub fn from_rsa_pkcs1_pem(private_key_pem: &str) -> crate::Result<Self> {
        Ok(PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_pem(private_key_pem)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn from_rsa_pkcs1_der(private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_der(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates an Ed25519 private key
    pub fn from_ed25519(public_key_bytes: &[u8], private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(PrivateKey::Ed25519(ed25519_dalek::Keypair {
            public: ed25519_dalek::PublicKey::from_bytes(public_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            secret: ed25519_dalek::SecretKey::from_bytes(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        }))
    }
}

impl<'x> Signature<'x> {
    /// Creates a new DKIM signature.
    pub fn new() -> Self {
        Signature {
            v: 1,
            ..Default::default()
        }
    }

    /// Signs a message.
    #[inline(always)]
    pub fn sign(mut self, message: &'x [u8], with_key: &PrivateKey) -> crate::Result<Self> {
        if !self.d.is_empty() && !self.s.is_empty() && !self.h.is_empty() {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match (self.a, with_key) {
                (Algorithm::RsaSha256, PrivateKey::Rsa(_)) => {
                    self.sign_::<Sha256>(message, with_key, now)
                }
                (Algorithm::RsaSha1, PrivateKey::Rsa(_)) => {
                    self.sign_::<Sha1>(message, with_key, now)
                }
                (_, PrivateKey::Ed25519(_)) => {
                    self.a = Algorithm::Ed25519Sha256;
                    self.sign_::<Sha256>(message, with_key, now)
                }
                (_, PrivateKey::Rsa(_)) => {
                    self.a = Algorithm::RsaSha256;
                    self.sign_::<Sha256>(message, with_key, now)
                }
                _ => Err(Error::IncompatibleAlgorithms),
            }
        } else {
            Err(Error::MissingParameters)
        }
    }

    fn sign_<T>(mut self, message: &'x [u8], with_key: &PrivateKey, now: u64) -> crate::Result<Self>
    where
        T: Digest + AssociatedOid + std::io::Write,
    {
        let mut body_hasher = T::new();
        let mut header_hasher = T::new();

        // Canonicalize headers and body
        let (body_len, signed_headers) =
            self.canonicalize(message, &mut header_hasher, &mut body_hasher)?;

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Create Signature
        self.bh = base64_encode(&body_hasher.finalize())?;
        self.t = now;
        self.x = if self.x > 0 { now + self.x } else { 0 };
        self.h = signed_headers;
        if self.l > 0 {
            self.l = body_len as u64;
        }

        // Add signature to hash
        self.write(&mut header_hasher, false)?;

        // Sign
        let b = match with_key {
            PrivateKey::Rsa(private_key) => private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign::<T>(),
                    &header_hasher.finalize(),
                )
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            PrivateKey::Ed25519(key_pair) => {
                key_pair.sign(&header_hasher.finalize()).to_bytes().to_vec()
            }
            PrivateKey::None => return Err(Error::MissingParameters),
        };

        // Encode
        self.b = base64_encode(&b)?;

        Ok(self)
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = impl Into<Cow<'x, str>>>) -> Self {
        self.h = headers.into_iter().map(|h| h.into()).collect();
        self
    }

    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: impl Into<Cow<'x, str>>) -> Self {
        self.d = domain.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<Cow<'x, str>>) -> Self {
        self.s = selector.into();
        self
    }

    /// Sets the third party signature.
    pub fn atps(mut self, atps: impl Into<Cow<'x, str>>) -> Self {
        self.atps = Some(atps.into());
        self
    }

    /// Sets the third-party signature hashing algorithm.
    pub fn atpsh(mut self, atpsh: HashAlgorithm) -> Self {
        self.atpsh = atpsh.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn agent_user_identifier(mut self, auid: impl Into<Cow<'x, str>>) -> Self {
        self.i = auid.into();
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.x = expiration;
        self
    }

    /// Sets the algorithm to use (must be compatible with the private key provided).
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.a = algorithm;
        self
    }

    /// Include the body length in the signature.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.l = u64::from(body_length);
        self
    }

    /// Request reports.
    pub fn reporting(mut self, reporting: bool) -> Self {
        self.r = reporting;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.ch = ch;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.cb = cb;
        self
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use mail_parser::decoders::base64::base64_decode;
    use sha2::Sha256;
    use trust_dns_resolver::proto::op::ResponseCode;

    use crate::{
        common::parse::TxtRecordParser,
        dkim::{Atps, Canonicalization, DomainKey, DomainKeyReport, HashAlgorithm, Signature},
        AuthenticatedMessage, DKIMOutput, DKIMResult, PrivateKey, Resolver,
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
        let pk = PrivateKey::from_rsa_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let signature = Signature::new()
            .headers(["From", "To", "Subject"])
            .domain("stalw.art")
            .selector("default")
            .sign_::<Sha256>(
                concat!(
                    "From: hello@stalw.art\r\n",
                    "To: dkim@stalw.art\r\n",
                    "Subject: Testing  DKIM!\r\n\r\n",
                    "Here goes the test\r\n\r\n"
                )
                .as_bytes(),
                &pk,
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
        let pk_rsa = PrivateKey::from_rsa_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let pk_ed = PrivateKey::from_ed25519(
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
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(message.as_bytes(), &pk_rsa)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        // Test ED25519-SHA256 relaxed/relaxed
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("ed")
                .sign(message.as_bytes(), &pk_ed)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        // Test RSA-SHA256 simple/simple with duplicated headers
        verify(
            &resolver,
            Signature::new()
                .headers([
                    "From",
                    "To",
                    "Subject",
                    "X-Duplicate-Header",
                    "X-Does-Not-Exist",
                ])
                .domain("example.com")
                .selector("default")
                .header_canonicalization(Canonicalization::Simple)
                .body_canonicalization(Canonicalization::Simple)
                .sign(message_multiheader.as_bytes(), &pk_rsa)
                .unwrap(),
            message_multiheader,
            Ok(()),
        )
        .await;

        // Test RSA-SHA256 simple/relaxed with fixed body length
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .header_canonicalization(Canonicalization::Simple)
                .body_length(true)
                .sign(message.as_bytes(), &pk_rsa)
                .unwrap(),
            &(message.to_string() + "\r\n----- Mailing list"),
            Ok(()),
        )
        .await;

        // Test AUID not matching domain
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .agent_user_identifier("@wrongdomain.com")
                .sign(message.as_bytes(), &pk_rsa)
                .unwrap(),
            message,
            Err(super::Error::FailedAUIDMatch),
        )
        .await;

        // Test expired signature and reporting
        let r = verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .expiration(12345)
                .reporting(true)
                .sign_::<Sha256>(message.as_bytes(), &pk_rsa, 12345)
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
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_::<Sha256>(message.as_bytes(), &pk_rsa, 12345)
                .unwrap(),
            message,
            Err(super::Error::DNSRecordNotFound(ResponseCode::NXDomain)),
        )
        .await;

        // Verify ATPS (success)
        resolver.txt_add(
            "UN42N5XOV642KXRXRQIYANHCOUPGQL5LT4WTBKYT2IJFLBWODFDQ._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_::<Sha256>(message.as_bytes(), &pk_rsa, 12345)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        // Verify ATPS (success - no hash)
        resolver.txt_add(
            "example.com._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            Signature::new()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .sign_::<Sha256>(message.as_bytes(), &pk_rsa, 12345)
                .unwrap(),
            message,
            Ok(()),
        )
        .await;
    }

    async fn verify<'x>(
        resolver: &Resolver,
        signature: Signature<'x>,
        message_: &'x str,
        expect: Result<(), super::Error>,
    ) -> Vec<DKIMOutput<'x>> {
        let mut message = Vec::with_capacity(message_.len() + 100);
        signature.write(&mut message, true).unwrap();
        message.extend_from_slice(message_.as_bytes());

        let message = AuthenticatedMessage::parse(&message).unwrap();
        let dkim = resolver.verify_dkim(&message).await;

        match (dkim.last().unwrap().result(), &expect) {
            (DKIMResult::Pass, Ok(_)) => (),
            (
                DKIMResult::Fail(hdr) | DKIMResult::PermError(hdr) | DKIMResult::Neutral(hdr),
                Err(err),
            ) if hdr == err => (),
            (result, expect) => panic!("Expected {:?} but got {:?}.", expect, result),
        }

        dkim.into_iter()
            .map(|d| DKIMOutput {
                result: d.result,
                signature: None,
                report: d.report,
                is_atps: d.is_atps,
            })
            .collect()
    }
}
