/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Streaming DKIM signing API for reduced memory usage with large emails.

use std::time::SystemTime;

use mail_builder::encoders::base64::base64_encode;

use super::{DkimSigner, Done, Signature, canonicalize::BodyHasher, sign::SignableMessage};

use crate::{
    Error,
    common::{
        crypto::{HashContext, HashImpl, SigningKey},
        headers::HeaderIterator,
    },
};

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
                        (&buffer[..boundary_pos - 4], &buffer[boundary_pos..])
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
                signed_headers.push(std::str::from_utf8(name).unwrap_or_default().to_string());
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
mod test {
    use crate::{
        common::crypto::{RsaKey, Sha256},
        dkim::{Canonicalization, DkimSigner},
    };
    #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, pem::PemObject};

    const RSA_PRIVATE_KEY: &str = include_str!("../../resources/rsa-private.pem");

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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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

    #[test]
    fn streaming_sign_multiple_chunks() {
        let header = "From: bill@example.com\r\nTo: jdoe@example.com\r\nSubject: Test\r\n\r\n";
        let body = "Hello World! This is the body.\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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

        assert_eq!(
            reference_sig.bh, streamed_sig.bh,
            "Body hashes should match"
        );
    }

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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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

    #[test]
    fn streaming_sign_split_header_boundary() {
        // Test where \r\n\r\n is split across chunks
        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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

    #[test]
    fn streaming_sign_empty_body() {
        let message = "From: test@example.com\r\nSubject: Empty\r\n\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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

    #[test]
    fn streaming_sign_no_matching_headers_error() {
        let message = "X-Custom: value\r\n\r\nBody\r\n";

        #[cfg(feature = "rust-crypto")]
        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
        ))
        .unwrap();

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
