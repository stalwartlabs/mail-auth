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
    path::Path,
    time::SystemTime,
};

use mail_builder::encoders::base64::base64_encode;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::AssociatedOid, PaddingScheme, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::{Algorithm, Canonicalization, DKIMSigner, Error, Signature};

impl<'x> DKIMSigner<'x> {
    /// Creates a new DKIM signer from a PKCS1 PEM file.
    pub fn from_pkcs1_pem_file(path: &str) -> super::Result<Self> {
        DKIMSigner::from_rsa_pkey(
            RsaPrivateKey::read_pkcs1_pem_file(Path::new(path)).map_err(Error::PKCS)?,
        )
    }

    /// Creates a new DKIM signer from a PKCS1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> super::Result<Self> {
        DKIMSigner::from_rsa_pkey(RsaPrivateKey::from_pkcs1_pem(pem).map_err(Error::PKCS)?)
    }

    /// Creates a new DKIM signer from a PKCS1 binary file.
    pub fn from_pkcs1_der_file(path: &str) -> super::Result<Self> {
        DKIMSigner::from_rsa_pkey(
            RsaPrivateKey::read_pkcs1_der_file(Path::new(path)).map_err(Error::PKCS)?,
        )
    }

    /// Creates a new DKIM signer from a PKCS1 binary slice.
    pub fn from_pkcs1_der(bytes: &[u8]) -> super::Result<Self> {
        DKIMSigner::from_rsa_pkey(RsaPrivateKey::from_pkcs1_der(bytes).map_err(Error::PKCS)?)
    }

    /// Creates a new DKIM signer from an RsaPrivateKey.
    pub fn from_rsa_pkey(private_key: RsaPrivateKey) -> super::Result<Self> {
        Ok(DKIMSigner {
            private_key,
            sign_headers: Vec::with_capacity(0),
            cb: Canonicalization::Relaxed,
            ch: Canonicalization::Relaxed,
            a: Algorithm::Sha256,
            d: (b""[..]).into(),
            s: (b""[..]).into(),
            i: (b""[..]).into(),
            l: false,
            x: 0,
        })
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = &'x str>) -> Self {
        self.sign_headers = headers
            .into_iter()
            .map(|h| Cow::Borrowed(h.as_bytes()))
            .collect();
        self
    }

    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: impl Into<Cow<'x, str>>) -> Self {
        self.d = match domain.into() {
            Cow::Borrowed(v) => v.as_bytes().into(),
            Cow::Owned(v) => v.into_bytes().into(),
        };
        self
    }

    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<Cow<'x, str>>) -> Self {
        self.s = match selector.into() {
            Cow::Borrowed(v) => v.as_bytes().into(),
            Cow::Owned(v) => v.into_bytes().into(),
        };
        self
    }

    /// Sets the selector to use for signing.
    pub fn agent_user_identifier(mut self, auid: impl Into<Cow<'x, str>>) -> Self {
        self.i = match auid.into() {
            Cow::Borrowed(v) => v.as_bytes().into(),
            Cow::Owned(v) => v.into_bytes().into(),
        };
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.x = expiration;
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
    pub fn sign(&self, message: &[u8]) -> super::Result<Signature> {
        if !self.d.is_empty() && !self.s.is_empty() {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match self.a {
                Algorithm::Sha256 => self.sign_::<Sha256>(message, now),
                Algorithm::Sha1 => self.sign_::<Sha1>(message, now),
            }
        } else {
            Err(Error::MissingParameters)
        }
    }

    fn sign_<T>(&self, message: &[u8], now: u64) -> super::Result<Signature>
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
        };

        // Add signature to hash
        header_hasher.write_all(b"dkim-signature:")?;
        signature.write(&mut header_hasher, false)?;

        // RSA Sign
        signature.b = base64_encode(
            &self
                .private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign::<T>(),
                    &header_hasher.finalize(),
                )
                .map_err(Error::RSA)?,
        )?;

        Ok(signature)
    }
}

impl<'x> Signature<'x> {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        if as_header {
            writer.write_all(b"DKIM-Signature: ")?;
        };
        writer.write_all(b"v=1; a=")?;
        writer.write_all(match self.a {
            Algorithm::Sha256 => b"rsa-sha256",
            Algorithm::Sha1 => b"rsa-sha1",
        })?;
        writer.write_all(b"; s=")?;
        writer.write_all(&self.s)?;
        writer.write_all(b"; d=")?;
        writer.write_all(&self.d)?;
        writer.write_all(b"; c=")?;

        self.ch.serialize_name(&mut writer)?;
        writer.write_all(b"/")?;
        self.cb.serialize_name(&mut writer)?;

        writer.write_all(b"; h=")?;
        for (num, h) in self.h.iter().enumerate() {
            if num > 0 {
                writer.write_all(b":")?;
            }
            writer.write_all(h)?;
        }
        writer.write_all(b"; t=")?;
        writer.write_all(self.t.to_string().as_bytes())?;
        if self.x > 0 {
            writer.write_all(b"; x=")?;
            writer.write_all(self.x.to_string().as_bytes())?;
        }
        writer.write_all(b"; bh=")?;
        writer.write_all(&self.bh)?;
        writer.write_all(b"; b=")?;
        writer.write_all(&self.b)?;
        if !self.i.is_empty() {
            writer.write_all(b"; i=")?;
            for &ch in self.i.iter() {
                match ch {
                    0..=0x20 | b';' | 0x7f..=u8::MAX => {
                        writer.write_all(format!("={:02X}", ch).as_bytes())?;
                    }
                    _ => {
                        writer.write_all(&[ch])?;
                    }
                }
            }
        }
        if self.l > 0 {
            writer.write_all(b"; l=")?;
            writer.write_all(self.l.to_string().as_bytes())?;
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

impl<'x> Display for Signature<'x> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write(&mut buf, false).map_err(|_| std::fmt::Error)?;
        f.write_str(&String::from_utf8(buf).map_err(|_| std::fmt::Error)?)
    }
}

#[cfg(test)]
mod test {
    use sha2::Sha256;

    const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
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

    #[test]
    fn dkim_sign() {
        let dkim = super::DKIMSigner::from_pkcs1_pem(TEST_KEY)
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
                "v=1; a=rsa-sha256; s=default; d=stalw.art; c=relaxed/relaxed; ",
                "h=Subject:To:From; t=311923920; ",
                "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Ylm5s=; ",
                "b=Du0rvdzNodI6b5bhlUaZZ+gpXJi0VwjY/3qL7lS0wzKutNVCbvdJuZObGdAcv",
                "eVI/RNQh2gxW4H2ynMS3B+Unse1YLJQwdjuGxsCEKBqReKlsEKT8JlO/7b2AvxR",
                "9Q+M2aHD5kn9dbNIKnN/PKouutaXmm18QwL5EPEN9DHXSqQ=;",
            ),
            signature.to_string()
        );
    }
}
