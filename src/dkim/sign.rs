/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::time::SystemTime;

use mail_builder::encoders::base64::base64_encode;

use super::{
    canonicalize::{BodyHasher, CanonicalHeaders},
    DkimSigner, Done, Signature,
};

use crate::{
    Error,
    common::{
        crypto::{HashContext, HashImpl, SigningKey},
        headers::{ChainedHeaderIterator, HeaderIterator, HeaderStream, Writable, Writer},
    },
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

impl Writable for SignableMessage<'_> {
    fn write(self, writer: &mut impl Writer) {
        self.headers.write(writer);
        self.signature.write(writer, false);
    }
}

/// A streaming DKIM signer that allows signing messages in chunks.
///
/// This is useful when you want to avoid loading the entire message into
/// memory before signing. Headers are buffered internally until the
/// header/body boundary is detected, then body content is streamed through
/// the hasher.
///
/// # Example
///
/// ```ignore
/// let signer = DkimSigner::from_key(key)
///     .domain("example.com")
///     .selector("default")
///     .headers(["From", "To", "Subject"]);
///
/// let mut stream = signer.sign_streaming();
/// stream.write(b"From: sender@example.com\r\n");
/// stream.write(b"To: recipient@example.com\r\n");
/// stream.write(b"Subject: Test\r\n");
/// stream.write(b"\r\n");
/// stream.write(b"Body content here...");
///
/// let signature = stream.finish()?;
/// ```
pub struct DkimSigningStream<'a, T: SigningKey> {
    template: Signature,
    key: &'a T,
    state: SigningState<<<T as SigningKey>::Hasher as HashImpl>::Context>,
}

enum SigningState<H> {
    /// Accumulating headers until \r\n\r\n is found
    ReadingHeaders { buffer: Vec<u8> },
    /// Headers parsed, now hashing body
    HashingBody {
        parsed_headers: Vec<(Vec<u8>, Vec<u8>)>,
        body_hasher: BodyHasher<H>,
    },
    /// Finished or consumed
    Done,
}

impl<T: SigningKey> DkimSigner<T, Done> {
    /// Creates a streaming DKIM signer.
    ///
    /// Feed raw message data via [`DkimSigningStream::write`], then call
    /// [`DkimSigningStream::finish`] to get the signature.
    ///
    /// Headers are buffered internally until the header/body boundary (`\r\n\r\n`)
    /// is detected. After that, body content is streamed through the hasher
    /// without additional buffering.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut stream = signer.sign_streaming();
    /// for chunk in message_chunks {
    ///     stream.write(chunk);
    /// }
    /// let signature = stream.finish()?;
    /// ```
    pub fn sign_streaming(&self) -> DkimSigningStream<'_, T> {
        DkimSigningStream {
            template: self.template.clone(),
            key: &self.key,
            state: SigningState::ReadingHeaders {
                buffer: Vec::with_capacity(8192),
            },
        }
    }
}

impl<T: SigningKey> DkimSigningStream<'_, T> {
    /// Feed a chunk of raw message data to the signer.
    ///
    /// Data should be provided in order, starting with headers. The header/body
    /// boundary (`\r\n\r\n`) is automatically detected.
    ///
    /// While reading headers, all data is buffered. Once the header/body boundary
    /// is detected, subsequent body data is streamed directly to the hasher.
    pub fn write(&mut self, chunk: &[u8]) {
        match &mut self.state {
            SigningState::ReadingHeaders { buffer } => {
                buffer.extend_from_slice(chunk);

                // Check for header/body boundary
                if let Some(boundary_pos) = find_header_boundary(buffer) {
                    // Parse headers from buffer[..boundary_pos - 4] (exclude the \r\n\r\n)
                    let header_section = &buffer[..boundary_pos - 4];
                    let parsed_headers = parse_headers(header_section);

                    // Create body hasher
                    let body_hasher = BodyHasher::new(
                        <T::Hasher as HashImpl>::hasher(),
                        self.template.cb,
                        if self.template.l > 0 { u64::MAX } else { 0 },
                    );

                    // Get any body data that was in the buffer after the boundary
                    let remaining_body = buffer[boundary_pos..].to_vec();

                    // Transition state
                    self.state = SigningState::HashingBody {
                        parsed_headers,
                        body_hasher,
                    };

                    // Hash any body data that was in the buffer
                    if !remaining_body.is_empty()
                        && let SigningState::HashingBody { body_hasher, .. } = &mut self.state
                    {
                        body_hasher.write(&remaining_body);
                    }
                }
            }
            SigningState::HashingBody { body_hasher, .. } => {
                body_hasher.write(chunk);
            }
            SigningState::Done => {
                // Ignore writes after finish
            }
        }
    }

    /// Finalize the signature.
    ///
    /// Consumes the stream and returns the DKIM signature. The current system
    /// time is used for the `t=` timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No headers matching the signer's header list were found
    /// - The cryptographic signing operation fails
    /// - `finish()` was already called
    pub fn finish(mut self) -> crate::Result<Signature>
    where
        <<T as SigningKey>::Hasher as HashImpl>::Context: HashContext,
    {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match std::mem::replace(&mut self.state, SigningState::Done) {
            SigningState::ReadingHeaders { buffer } => {
                // Never saw body boundary - check if we have any headers at all
                // This handles the edge case of a message with no body
                let (header_section, body_section) =
                    if let Some(boundary_pos) = find_header_boundary(&buffer) {
                        (
                            &buffer[..boundary_pos - 4],
                            &buffer[boundary_pos..],
                        )
                    } else {
                        // No boundary found - treat entire buffer as headers with empty body
                        (buffer.as_slice(), &[][..])
                    };

                let parsed_headers = parse_headers(header_section);

                // Hash the body (may be empty)
                let mut body_hasher = BodyHasher::new(
                    <T::Hasher as HashImpl>::hasher(),
                    self.template.cb,
                    if self.template.l > 0 { u64::MAX } else { 0 },
                );
                body_hasher.write(body_section);
                let (hasher, body_len) = body_hasher.finish();
                let body_hash = hasher.complete();

                self.finish_with_parsed_data(parsed_headers, body_hash, body_len, now)
            }
            SigningState::HashingBody {
                parsed_headers,
                body_hasher,
            } => {
                let (hasher, body_len) = body_hasher.finish();
                let body_hash = hasher.complete();
                self.finish_with_parsed_data(parsed_headers, body_hash, body_len, now)
            }
            SigningState::Done => Err(Error::NoHeadersFound),
        }
    }

    fn finish_with_parsed_data(
        &self,
        parsed_headers: Vec<(Vec<u8>, Vec<u8>)>,
        body_hash: crate::common::crypto::HashOutput,
        body_len: u64,
        now: u64,
    ) -> crate::Result<Signature> {
        // Filter headers to only those in template.h and build signed_headers list
        let mut headers = Vec::with_capacity(self.template.h.len());
        let mut found_headers = vec![false; self.template.h.len()];
        let mut signed_headers = Vec::with_capacity(self.template.h.len());

        for (name, value) in &parsed_headers {
            if let Some(pos) = self
                .template
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((name.as_slice(), value.as_slice()));
                found_headers[pos] = true;
                signed_headers.push(
                    std::str::from_utf8(name)
                        .unwrap_or_default()
                        .to_string(),
                );
            }
        }

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Add any missing headers (in reverse order as per DKIM spec)
        signed_headers.reverse();
        for (header, found) in self.template.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string());
            }
        }

        // Build canonical headers
        let canonical_headers = self.template.ch.canonical_headers(headers);

        // Create Signature
        let mut signature = self.template.clone();
        signature.bh = base64_encode(body_hash.as_ref())?;
        signature.t = now;
        signature.x = if signature.x > 0 {
            now + signature.x
        } else {
            0
        };
        signature.h = signed_headers;
        if signature.l > 0 {
            signature.l = body_len;
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

/// Find the header/body boundary (\r\n\r\n) and return the position after it
fn find_header_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Parse raw header bytes into (name, value) pairs
/// Uses the same HeaderIterator as the regular sign() method to ensure consistency
fn parse_headers(header_section: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Add a fake body separator so HeaderIterator works correctly
    let mut with_separator = header_section.to_vec();
    with_separator.extend_from_slice(b"\r\n");
    
    HeaderIterator::new(&with_separator)
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect()
}

#[cfg(test)]
#[allow(unused)]
pub mod test {
    use crate::{
        AuthenticatedMessage, DkimOutput, DkimResult, MessageAuthenticator,
        common::{
            cache::test::DummyCaches,
            crypto::{Ed25519Key, RsaKey, Sha256},
            headers::HeaderIterator,
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::{Atps, Canonicalization, DkimSigner, DomainKeyReport, HashAlgorithm, Signature},
    };
    use core::str;
    use hickory_resolver::proto::op::ResponseCode;
    use mail_parser::{MessageParser, decoders::base64::base64_decode};
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

    #[cfg(any(feature = "rust-crypto", feature = "ring"))]
    #[test]
    fn dkim_sign() {
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
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

    #[cfg(any(feature = "rust-crypto", feature = "ring"))]
    #[tokio::test]
    async fn dkim_sign_verify() {
        use crate::common::cache::test::DummyCaches;

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
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new()
            .with_txt(
                "default._domainkey.example.com.".to_string(),
                DomainKey::parse(RSA_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            )
            .with_txt(
                "ed._domainkey.example.com.".to_string(),
                DomainKey::parse(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            )
            .with_txt(
                "_report._domainkey.example.com.".to_string(),
                DomainKeyReport::parse("ra=dkim-failures; rp=100; rr=x".as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );

        dbg!("Test RSA-SHA256 relaxed/relaxed");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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

        dbg!("Test RSA-SHA256 simple/relaxed with fixed body length (relaxed)");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify_with_opts(
            &resolver,
            &caches,
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
            false,
        )
        .await;

        dbg!("Test RSA-SHA256 simple/relaxed with fixed body length (strict)");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify_with_opts(
            &resolver,
            &caches,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .header_canonicalization(Canonicalization::Simple)
                .body_length(true)
                .sign(message.as_bytes())
                .unwrap(),
            &(message.to_string() + "\r\n----- Mailing list"),
            Err(super::Error::SignatureLength),
            true,
        )
        .await;

        dbg!("Test AUID not matching domains");
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        let r = verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        caches.txt_add(
            "UN42N5XOV642KXRXRQIYANHCOUPGQL5LT4WTBKYT2IJFLBWODFDQ._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            &caches,
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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();
        caches.txt_add(
            "example.com._atps.example.com.".to_string(),
            Atps::parse(b"v=ATPS1;").unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        verify(
            &resolver,
            &caches,
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

    pub(crate) async fn verify_with_opts<'x>(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        signature: Signature,
        message_: &'x str,
        expect: Result<(), super::Error>,
        strict: bool,
    ) -> Vec<DkimOutput<'x>> {
        let mut raw_message = Vec::with_capacity(message_.len() + 100);
        signature.write(&mut raw_message, true);
        raw_message.extend_from_slice(message_.as_bytes());

        let message = AuthenticatedMessage::parse_with_opts(&raw_message, strict).unwrap();
        assert_eq!(
            message,
            AuthenticatedMessage::from_parsed(
                &MessageParser::new().parse(&raw_message).unwrap(),
                strict
            )
        );
        let dkim = resolver.verify_dkim(caches.parameters(&message)).await;

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

    pub(crate) async fn verify<'x>(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        signature: Signature,
        message_: &'x str,
        expect: Result<(), super::Error>,
    ) -> Vec<DkimOutput<'x>> {
        verify_with_opts(resolver, caches, signature, message_, expect, true).await
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_matches_regular_sign() {
        // Test that sign_streaming() produces same body hash as sign()
        let message = concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great.\r\n"
        );

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "To", "Subject"]);

        // Regular sign
        let sig1 = signer.sign(message.as_bytes()).unwrap();

        // Streaming sign - single chunk
        let mut stream = signer.sign_streaming();
        stream.write(message.as_bytes());
        let sig2 = stream.finish().unwrap();

        // Body hashes should match
        assert_eq!(sig1.bh, sig2.bh, "Body hashes should match");
        // Signed headers should match
        assert_eq!(sig1.h, sig2.h, "Signed headers should match");
        // Signature should match (same key, same content, same body hash = same signature)
        assert_eq!(sig1.b, sig2.b, "Signatures should match");
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_multiple_chunks() {
        let header = "From: bill@example.com\r\nTo: jdoe@example.com\r\nSubject: Test\r\n\r\n";
        let body = "Hello World! This is the body.\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "To", "Subject"]);

        // Reference: single chunk
        let full_message = format!("{}{}", header, body);
        let reference_sig = signer.sign(full_message.as_bytes()).unwrap();

        // Streaming: multiple chunks
        let mut stream = signer.sign_streaming();
        stream.write(header.as_bytes());
        stream.write(body.as_bytes());
        let streamed_sig = stream.finish().unwrap();

        assert_eq!(reference_sig.bh, streamed_sig.bh, "Body hashes should match");
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_chunked_body() {
        let message = concat!(
            "From: test@example.com\r\n",
            "Subject: Chunked Test\r\n",
            "\r\n",
            "Line 1\r\n",
            "Line 2\r\n",
            "Line 3\r\n",
        );

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"]);

        // Reference
        let reference_sig = signer.sign(message.as_bytes()).unwrap();

        // Chunked at various sizes
        for chunk_size in [1, 2, 5, 10, 20] {
            let mut stream = signer.sign_streaming();
            for chunk in message.as_bytes().chunks(chunk_size) {
                stream.write(chunk);
            }
            let streamed_sig = stream.finish().unwrap();

            assert_eq!(
                reference_sig.bh, streamed_sig.bh,
                "Body hash mismatch at chunk_size={}",
                chunk_size
            );
        }
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_split_header_boundary() {
        // Test where \r\n\r\n is split across chunks
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"]);

        // Reference
        let message = "From: test@example.com\r\nSubject: Test\r\n\r\nBody";
        let reference_sig = signer.sign(message.as_bytes()).unwrap();

        // Split right at the boundary
        let mut stream = signer.sign_streaming();
        stream.write(b"From: test@example.com\r\n");
        stream.write(b"Subject: Test\r\n");
        stream.write(b"\r\n"); // The second \r\n completing the boundary
        stream.write(b"Body");
        let streamed_sig = stream.finish().unwrap();

        assert_eq!(reference_sig.bh, streamed_sig.bh);
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_empty_body() {
        let message = "From: test@example.com\r\nSubject: Empty\r\n\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"]);

        let reference_sig = signer.sign(message.as_bytes()).unwrap();

        let mut stream = signer.sign_streaming();
        stream.write(message.as_bytes());
        let streamed_sig = stream.finish().unwrap();

        assert_eq!(reference_sig.bh, streamed_sig.bh);
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_simple_canonicalization() {
        let message = concat!(
            "From: test@example.com\r\n",
            "Subject: Simple Canon Test\r\n",
            "\r\n",
            "Body with   spaces\r\n",
        );

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"])
            .header_canonicalization(Canonicalization::Simple)
            .body_canonicalization(Canonicalization::Simple);

        let reference_sig = signer.sign(message.as_bytes()).unwrap();

        let mut stream = signer.sign_streaming();
        stream.write(message.as_bytes());
        let streamed_sig = stream.finish().unwrap();

        assert_eq!(reference_sig.bh, streamed_sig.bh);
        assert_eq!(reference_sig.b, streamed_sig.b);
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_folded_headers() {
        // Test with folded (multi-line) headers
        let message = concat!(
            "From: test@example.com\r\n",
            "Subject: This is a very long subject line that\r\n",
            " continues on the next line\r\n",
            "\r\n",
            "Body\r\n",
        );

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"]);

        let reference_sig = signer.sign(message.as_bytes()).unwrap();

        let mut stream = signer.sign_streaming();
        stream.write(message.as_bytes());
        let streamed_sig = stream.finish().unwrap();

        assert_eq!(reference_sig.bh, streamed_sig.bh);
    }

    #[cfg(any(
        feature = "rust-crypto",
        all(feature = "ring", feature = "rustls-pemfile")
    ))]
    #[test]
    fn streaming_sign_no_matching_headers_error() {
        let message = "X-Custom: value\r\n\r\nBody\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

        let signer = DkimSigner::from_key(pk_rsa)
            .domain("example.com")
            .selector("default")
            .headers(["From", "Subject"]); // These headers don't exist in message

        let mut stream = signer.sign_streaming();
        stream.write(message.as_bytes());
        let result = stream.finish();

        assert!(matches!(result, Err(crate::Error::NoHeadersFound)));
    }
}
