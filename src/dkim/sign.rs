/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    io::Write,
    time::SystemTime,
};

use ed25519_dalek::Signer;
use mail_builder::encoders::base64::base64_encode;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::AssociatedOid, PaddingScheme, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::Error;

use super::{Algorithm, Canonicalization, DKIMSigner, HashAlgorithm, PrivateKey, Signature};

impl<'x> DKIMSigner<'x> {
    /// Creates a new DKIM signer from an RsaPrivateKey.
    pub fn new() -> Self {
        DKIMSigner {
            a: Algorithm::RsaSha256,
            private_key: PrivateKey::None,
            sign_headers: Vec::with_capacity(0),
            cb: Canonicalization::Relaxed,
            ch: Canonicalization::Relaxed,
            d: "".into(),
            s: "".into(),
            i: "".into(),
            l: false,
            x: 0,
            atps: None,
            atpsh: None,
        }
    }

    /// Creates a new RSA private key from a PKCS1 PEM string.
    pub fn rsa_pem(mut self, private_key_pem: &str) -> crate::Result<Self> {
        self.private_key = PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_pem(private_key_pem)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        );
        Ok(self)
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn rsa(mut self, private_key_bytes: &[u8]) -> crate::Result<Self> {
        self.private_key = PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_der(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        );
        Ok(self)
    }

    /// Creates an Ed25519 private key
    pub fn ed25519(
        mut self,
        public_key_bytes: &[u8],
        private_key_bytes: &[u8],
    ) -> crate::Result<Self> {
        self.private_key = PrivateKey::Ed25519(ed25519_dalek::Keypair {
            public: ed25519_dalek::PublicKey::from_bytes(public_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            secret: ed25519_dalek::SecretKey::from_bytes(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        });
        self.a = Algorithm::Ed25519Sha256;
        Ok(self)
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = &'x str>) -> Self {
        self.sign_headers = headers.into_iter().map(Cow::Borrowed).collect();
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

    /// Sets the selector to use for signing.
    pub fn atps(mut self, atps: impl Into<Cow<'x, str>>) -> Self {
        self.atps = Some(atps.into());
        self
    }

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
        self.l = body_length;
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

    /// Signs a message.
    #[inline(always)]
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        if !self.d.is_empty() && !self.s.is_empty() {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match self.a {
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                    self.sign_::<Sha256>(message, now)
                }
                Algorithm::RsaSha1 => self.sign_::<Sha1>(message, now),
            }
        } else {
            Err(Error::MissingParameters)
        }
    }

    fn sign_<T>(&self, message: &[u8], now: u64) -> crate::Result<Signature>
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
        let mut signature = Signature {
            d: self.d.as_ref().into(),
            s: self.s.as_ref().into(),
            i: self.i.as_ref().into(),
            b: Vec::new(),
            bh: base64_encode(&body_hasher.finalize())?,
            h: signed_headers,
            t: now,
            x: if self.x > 0 { now + self.x } else { 0 },
            cb: self.cb,
            ch: self.ch,
            v: 1,
            a: self.a,
            z: Vec::new(),
            l: if self.l { body_len as u64 } else { 0 },
            r: false,
            atps: self.atps.as_ref().map(|a| a.as_ref().into()),
            atpsh: self.atpsh,
        };

        // Add signature to hash
        signature.write(&mut header_hasher, false)?;

        // Sign
        let b = match &self.private_key {
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
        signature.b = base64_encode(&b)?;

        Ok(signature)
    }
}

impl Signature {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"dkim-signature:"[..], &b" "[..]),
            _ => (&b"DKIM-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write_all(header)?;
        writer.write_all(b"v=1; a=")?;
        writer.write_all(match self.a {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::RsaSha1 => b"rsa-sha1",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        })?;
        for (tag, value) in [(&b"; s="[..], &self.s), (&b"; d="[..], &self.d)] {
            writer.write_all(tag)?;
            writer.write_all(value.as_bytes())?;
        }
        writer.write_all(b"; c=")?;
        self.ch.serialize_name(&mut writer)?;
        writer.write_all(b"/")?;
        self.cb.serialize_name(&mut writer)?;

        if let Some(atps) = &self.atps {
            writer.write_all(b"; atps=")?;
            writer.write_all(atps.as_bytes())?;
            writer.write_all(b"; atpsh=")?;
            writer.write_all(match self.atpsh {
                Some(HashAlgorithm::Sha256) => b"sha256",
                Some(HashAlgorithm::Sha1) => b"sha1",
                _ => b"none",
            })?;
        }
        if self.r {
            writer.write_all(b"; r=y")?;
        }

        writer.write_all(b";")?;
        writer.write_all(new_line)?;

        let mut bw = 1;
        for (num, h) in self.h.iter().enumerate() {
            if bw + h.len() + 1 >= 76 {
                writer.write_all(new_line)?;
                bw = 1;
            }
            if num > 0 {
                bw += writer.write(b":")?;
            } else {
                bw += writer.write(b"h=")?;
            }
            bw += writer.write(h.as_bytes())?;
        }

        if !self.i.is_empty() {
            if bw + self.i.len() + 3 >= 76 {
                writer.write_all(b";")?;
                writer.write_all(new_line)?;
                bw = 1;
            } else {
                bw += writer.write(b"; ")?;
            }
            bw += writer.write(b"i=")?;

            for &ch in self.i.as_bytes().iter() {
                match ch {
                    0..=0x20 | b';' | 0x7f..=u8::MAX => {
                        bw += writer.write(format!("={:02X}", ch).as_bytes())?;
                    }
                    _ => {
                        bw += writer.write(&[ch])?;
                    }
                }
                if bw >= 76 {
                    writer.write_all(new_line)?;
                    bw = 1;
                }
            }
        }

        for (tag, value) in [
            (&b"t="[..], self.t),
            (&b"x="[..], self.x),
            (&b"l="[..], self.l),
        ] {
            if value > 0 {
                let value = value.to_string();
                bw += writer.write(b";")?;
                if bw + tag.len() + value.len() >= 76 {
                    writer.write_all(new_line)?;
                    bw = 1;
                } else {
                    bw += writer.write(b" ")?;
                }

                bw += writer.write(tag)?;
                bw += writer.write(value.as_bytes())?;
            }
        }

        for (tag, value) in [(&b"; bh="[..], &self.bh), (&b"; b="[..], &self.b)] {
            bw += writer.write(tag)?;
            for &byte in value {
                bw += writer.write(&[byte])?;
                if bw >= 76 {
                    writer.write_all(new_line)?;
                    bw = 1;
                }
            }
        }

        writer.write_all(b";")?;
        if as_header {
            writer.write_all(b"\r\n")?;
        }
        Ok(())
    }

    pub fn write_header(&self, writer: impl Write) -> std::io::Result<()> {
        self.write(writer, true)
    }

    pub fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write(&mut buf, true).unwrap();
        String::from_utf8(buf).unwrap()
    }
}

impl<'x> Default for DKIMSigner<'x> {
    fn default() -> Self {
        DKIMSigner::new()
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write(&mut buf, false).map_err(|_| std::fmt::Error)?;
        f.write_str(&String::from_utf8(buf).map_err(|_| std::fmt::Error)?)
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
        dkim::{Atps, Canonicalization, DomainKey, HashAlgorithm, Signature},
        DKIMResult, Resolver,
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
        let dkim = super::DKIMSigner::new()
            .rsa_pem(RSA_PRIVATE_KEY)
            .unwrap()
            .headers(["From", "To", "Subject"])
            .domain("stalw.art")
            .selector("default");
        let signature = dkim
            .sign_::<Sha256>(
                concat!(
                    "From: hello@stalw.art\r\n",
                    "To: dkim@stalw.art\r\n",
                    "Subject: Testing  DKIM!\r\n\r\n",
                    "Here goes the test\r\n\r\n"
                )
                .as_bytes(),
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

        // Test RSA-SHA256 relaxed/relaxed
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "",
            Ok(()),
        )
        .await;

        // Test ED25519-SHA256 relaxed/relaxed
        verify(
            super::DKIMSigner::new()
                .ed25519(
                    &base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes())
                        .unwrap(),
                    &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
                )
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            ED25519_PUBLIC_KEY,
            "",
            Ok(()),
        )
        .await;

        // Test RSA-SHA256 simple/simple with duplicated headers
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
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
                .sign(message_multiheader.as_bytes())
                .unwrap(),
            message_multiheader,
            RSA_PUBLIC_KEY,
            "",
            Ok(()),
        )
        .await;

        // Test RSA-SHA256 simple/relaxed with fixed body length
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .header_canonicalization(Canonicalization::Simple)
                .body_length(true)
                .sign(message.as_bytes())
                .unwrap(),
            &(message.to_string() + "\r\n----- Mailing list"),
            RSA_PUBLIC_KEY,
            "",
            Ok(()),
        )
        .await;

        // Test AUID not matching domain
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .agent_user_identifier("@wrongdomain.com")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "",
            Err(super::Error::FailedAUIDMatch),
        )
        .await;

        // Test expired signature
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .expiration(12345)
                .sign_::<Sha256>(message.as_bytes(), 12345)
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "",
            Err(super::Error::SignatureExpired),
        )
        .await;

        // Verify ATPS (failure)
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_::<Sha256>(message.as_bytes(), 12345)
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "",
            Err(super::Error::DNSRecordNotFound(ResponseCode::NXDomain)),
        )
        .await;

        // Verify ATPS (success)
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .atpsh(HashAlgorithm::Sha256)
                .sign_::<Sha256>(message.as_bytes(), 12345)
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "UN42N5XOV642KXRXRQIYANHCOUPGQL5LT4WTBKYT2IJFLBWODFDQ._atps.example.com.",
            Ok(()),
        )
        .await;

        // Verify ATPS (success - no hash)
        verify(
            super::DKIMSigner::new()
                .rsa_pem(RSA_PRIVATE_KEY)
                .unwrap()
                .headers(["From", "To", "Subject"])
                .domain("example.com")
                .selector("default")
                .atps("example.com")
                .sign_::<Sha256>(message.as_bytes(), 12345)
                .unwrap(),
            message,
            RSA_PUBLIC_KEY,
            "example.com._atps.example.com.",
            Ok(()),
        )
        .await;
    }

    async fn verify(
        signature: Signature,
        message_: &str,
        public_key: &str,
        atps: &str,
        expect: Result<(), super::Error>,
    ) {
        let mut message = Vec::with_capacity(message_.len() + 100);
        signature.write(&mut message, true).unwrap();
        message.extend_from_slice(message_.as_bytes());
        //println!("[{}]", String::from_utf8_lossy(&message));

        let resolver = Resolver::new_system_conf().unwrap();
        resolver.txt_add(
            "default._domainkey.example.com.".to_string(),
            DomainKey::parse(public_key.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        if !atps.is_empty() {
            resolver.txt_add(
                atps.to_string(),
                Atps::parse(b"v=ATPS1;").unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
        }
        let message = resolver.verify_dkim(&message).await.unwrap();

        match (message.dkim_output().last().unwrap().result(), &expect) {
            (DKIMResult::Pass, Ok(_)) => (),
            (
                DKIMResult::Fail(hdr) | DKIMResult::PermError(hdr) | DKIMResult::Neutral(hdr),
                Err(err),
            ) if hdr == err => (),
            (result, expect) => panic!("Expected {:?} but got {:?}.", expect, result),
        }
    }
}
