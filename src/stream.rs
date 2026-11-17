/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Streaming message parsing.
//!
//! A [`MessageStream`] is fed a message in chunks. It buffers the header
//! section and reduces the body to the hashes that DKIM, ARC and DKIM2 need,
//! so a large message can be verified, sealed and signed without holding
//! its body in memory.
//!
//! ```rust,no_run
//! use mail_auth::{MessageAuthenticator, stream::MessageStream};
//!
//! # async fn run(chunks: Vec<Vec<u8>>) -> mail_auth::Result<()> {
//! let mut stream = MessageStream::new();
//! for chunk in &chunks {
//!     stream.write(chunk);
//! }
//! let streamed = stream.finish()?;
//! let message = streamed.message();
//!
//! let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
//! let dkim = authenticator.verify_dkim(&message).await;
//! # Ok(())
//! # }
//! ```
//!
//! The stream computes the body hashes named by the header fields of the
//! message. A hash needed for a signature added later (an ARC seal, a new
//! DKIM2 `Message-Instance`) is declared before the body arrives, with
//! [`MessageStream::also_hash`] or [`MessageStream::also_hash_dkim2`]. An
//! operation that needs a hash the stream did not compute, or the body
//! itself, fails with an error: nothing hashes the missing body.

use crate::{
    AuthenticatedMessage, Error,
    crypto::{HashAlgorithm, HashContext, HashImpl, HashOutput, Sha1, Sha256, Sha512},
    dkim::{Canonicalization, canonicalize::BodyHasher, streaming::find_header_boundary},
    dkim2::{Dkim2Hash, recipe::BodyRecipe, streaming::BodyDigests},
    headers::Writer,
    message::StreamedBody,
};

type BodyHash = (Canonicalization, HashAlgorithm, u64, Vec<u8>);

/// Parses a message fed in chunks, yielding a [`StreamedMessage`].
pub struct MessageStream {
    buffer: Vec<u8>,
    scanned: usize,
    strict: bool,
    extra: Vec<(Canonicalization, HashAlgorithm)>,
    extra_dkim2: Vec<Dkim2Hash>,
    body: Option<BodyState>,
    valid: bool,
    needs_body: bool,
}

struct BodyState {
    hashers: Vec<(Canonicalization, HashAlgorithm, u64, BodyHasher<AnyHash>)>,
    dkim2: Option<BodyHasher<BodyDigests>>,
    len: u64,
}

enum AnyHash {
    Sha1(<Sha1 as HashImpl>::Context),
    Sha256(<Sha256 as HashImpl>::Context),
    Sha512(<Sha512 as HashImpl>::Context),
}

impl Writer for AnyHash {
    fn write(&mut self, buf: &[u8]) {
        match self {
            AnyHash::Sha1(hasher) => hasher.write(buf),
            AnyHash::Sha256(hasher) => hasher.write(buf),
            AnyHash::Sha512(hasher) => hasher.write(buf),
        }
    }
}

impl AnyHash {
    fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha1 => AnyHash::Sha1(Sha1::hasher()),
            HashAlgorithm::Sha256 => AnyHash::Sha256(Sha256::hasher()),
            HashAlgorithm::Sha512 => AnyHash::Sha512(Sha512::hasher()),
        }
    }

    fn complete(self) -> HashOutput {
        match self {
            AnyHash::Sha1(hasher) => hasher.complete(),
            AnyHash::Sha256(hasher) => hasher.complete(),
            AnyHash::Sha512(hasher) => hasher.complete(),
        }
    }
}

impl Default for MessageStream {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageStream {
    /// Creates a stream that parses in strict mode, as
    /// [`AuthenticatedMessage::parse`] does.
    pub fn new() -> Self {
        MessageStream {
            buffer: Vec::with_capacity(8192),
            scanned: 0,
            strict: true,
            extra: Vec::new(),
            extra_dkim2: Vec::new(),
            body: None,
            valid: false,
            needs_body: false,
        }
    }

    /// Sets strict parsing, as the `strict` argument of
    /// [`AuthenticatedMessage::parse_with_opts`].
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Also computes this DKIM or ARC body hash, for a signature added later
    /// (an ARC seal, or a `DKIM-Signature` passed to
    /// [`StreamedMessage::message_with_headers`]). Has no effect once the
    /// body has started.
    pub fn also_hash(mut self, canonicalization: Canonicalization, hash: HashAlgorithm) -> Self {
        self.extra.push((canonicalization, hash));
        self
    }

    /// Also computes this DKIM2 body hash, for a `Message-Instance` added
    /// later by a [`Dkim2Signer`](crate::dkim2::Dkim2Signer) that uses it.
    /// Has no effect once the body has started.
    pub fn also_hash_dkim2(mut self, hash: Dkim2Hash) -> Self {
        self.extra_dkim2.push(hash);
        self
    }

    /// Feeds the next chunk of raw message data.
    pub fn write(&mut self, chunk: &[u8]) {
        if let Some(body) = &mut self.body {
            body.write(chunk);
            return;
        }

        self.buffer.extend_from_slice(chunk);
        match self
            .buffer
            .get(self.scanned..)
            .and_then(find_header_boundary)
        {
            Some(pos) => self.start_body(self.scanned + pos),
            None => self.scanned = self.buffer.len().saturating_sub(3),
        }
    }

    fn start_body(&mut self, header_end: usize) {
        let header_section = self.buffer.get(..header_end).unwrap_or_default();
        let parsed = AuthenticatedMessage::parse_with_opts(header_section, None, self.strict);
        let instances = parsed
            .iter()
            .flat_map(|message| &message.dkim2_instances)
            .map(|header| &header.header);

        let mut wanted: Vec<(Canonicalization, HashAlgorithm, u64)> = parsed
            .iter()
            .flat_map(|message| &message.body_hashes)
            .map(|(cb, ha, l, _)| (*cb, *ha, *l))
            .collect();
        for (cb, ha) in &self.extra {
            if !wanted.contains(&(*cb, *ha, 0)) {
                wanted.push((*cb, *ha, 0));
            }
        }
        let dkim2: Vec<Dkim2Hash> = instances
            .clone()
            .flat_map(|instance| &instance.hashes)
            .filter_map(|hash| hash.name.known())
            .chain(self.extra_dkim2.iter().copied())
            .collect();
        self.needs_body = instances.clone().any(|instance| {
            instance.m > 1
                && instance
                    .recipe
                    .as_ref()
                    .is_some_and(|recipe| matches!(recipe.body, BodyRecipe::Steps(_)))
        });
        self.valid = parsed.is_some();
        let body_offset = parsed.map_or(header_end, |message| message.body_offset());

        let mut body = BodyState {
            hashers: wanted
                .into_iter()
                .map(|(cb, ha, l)| (cb, ha, l, BodyHasher::new(AnyHash::new(ha), cb, l)))
                .collect(),
            dkim2: (!dkim2.is_empty()).then(|| BodyDigests::hasher_for(dkim2)),
            len: 0,
        };
        body.write(self.buffer.get(body_offset..).unwrap_or_default());
        self.buffer.truncate(body_offset);
        self.body = Some(body);
    }

    /// Ends the message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when no header field could be parsed.
    pub fn finish(mut self) -> crate::Result<StreamedMessage> {
        if self.body.is_none() {
            self.start_body(self.buffer.len());
        }
        let body = self
            .body
            .take()
            .filter(|_| self.valid)
            .ok_or(Error::Parse)?;

        Ok(StreamedMessage {
            headers: self.buffer,
            strict: self.strict,
            needs_body: self.needs_body,
            hashes: body
                .hashers
                .into_iter()
                .map(|(cb, ha, l, hasher)| {
                    (cb, ha, l, hasher.finish().0.complete().as_ref().to_vec())
                })
                .collect(),
            body: StreamedBody {
                len: body.len,
                dkim2: body
                    .dkim2
                    .map(|hasher| hasher.finish().0.complete())
                    .unwrap_or_default(),
            },
        })
    }
}

impl BodyState {
    fn write(&mut self, chunk: &[u8]) {
        self.len += chunk.len() as u64;
        for (_, _, _, hasher) in &mut self.hashers {
            hasher.write(chunk);
        }
        if let Some(hasher) = &mut self.dkim2 {
            hasher.write(chunk);
        }
    }
}

/// The header section of a streamed message and the hashes of its body.
/// Holds no body bytes.
pub struct StreamedMessage {
    headers: Vec<u8>,
    strict: bool,
    needs_body: bool,
    hashes: Vec<BodyHash>,
    pub(crate) body: StreamedBody,
}

impl StreamedMessage {
    /// The message, for the `verify_*` methods, ARC sealing and DKIM2
    /// signing. Its [`raw_body`](AuthenticatedMessage::raw_body) is empty.
    pub fn message(&self) -> AuthenticatedMessage<'_> {
        AuthenticatedMessage::parse_streamed(
            &self.headers,
            None,
            self.strict,
            &self.hashes,
            self.body.clone(),
        )
        .unwrap_or_default()
    }

    /// The message with the header fields in `prepend` added in front of
    /// it, for signing a message that is sent with new header fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BodyNotAvailable`] when a signature in `prepend`
    /// names a body hash the stream did not compute (see
    /// [`MessageStream::also_hash`]).
    pub fn message_with_headers<'x>(
        &'x self,
        prepend: &'x [u8],
    ) -> crate::Result<AuthenticatedMessage<'x>> {
        AuthenticatedMessage::parse_streamed(
            &self.headers,
            Some(prepend),
            self.strict,
            &self.hashes,
            self.body.clone(),
        )
    }

    /// Returns `true` when fully verifying the DKIM2 chain needs the body
    /// itself: an earlier hop changed the body and recorded how in a recipe.
    /// Such a message has to be buffered and parsed with
    /// [`AuthenticatedMessage::parse`].
    pub fn needs_body(&self) -> bool {
        self.needs_body
    }
}

#[cfg(all(test, feature = "arc"))]
mod test {
    use super::{MessageStream, StreamedMessage};
    use crate::{
        AuthenticatedMessage, AuthenticationResults, DkimResult, Error, MessageAuthenticator,
        arc::ArcSealer,
        crypto::{HashAlgorithm, RsaKey, Sha256},
        dkim::{Canonicalization, DkimSigner, verify::test::new_cache},
        headers::HeaderWriter,
    };
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, pem::PemObject};
    use std::{fs, path::PathBuf};

    const RSA_PRIVATE_KEY: &str = include_str!("../resources/rsa-private.pem");
    const CHUNKS: &[usize] = &[1, 2, 3, 5, 7, 13, 64, 8192, usize::MAX];

    fn stream(raw: &[u8], chunk: usize, seal: bool) -> StreamedMessage {
        let mut stream = MessageStream::new();
        if seal {
            stream = stream
                .also_hash(Canonicalization::Relaxed, HashAlgorithm::Sha256)
                .also_hash(Canonicalization::Simple, HashAlgorithm::Sha256);
        }
        for chunk in raw.chunks(chunk.min(raw.len().max(1))) {
            stream.write(chunk);
        }
        stream.finish().unwrap()
    }

    fn sealer() -> ArcSealer<RsaKey<Sha256>, crate::signer::Ready> {
        ArcSealer::from_key(
            RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
                PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
            ))
            .unwrap(),
        )
        .domain("manchego.org")
        .selector("rsa")
        .headers(["From", "To", "Subject", "DKIM-Signature"])
    }

    // Streamed DKIM, ARC and seal results equal the buffered ones on every fixture.
    #[tokio::test]
    async fn dkim_and_arc_match_buffered() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let mut fixtures = 0;
        for dir in ["dkim", "arc"] {
            let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            test_dir.push("resources");
            test_dir.push(dir);
            for file_name in fs::read_dir(&test_dir).unwrap() {
                let file_name = file_name.unwrap().path();
                let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
                let (dns_records, raw_message) = test.split_once("\n\n").unwrap();
                let caches = new_cache(dns_records);
                let raw_message = raw_message.replace('\n', "\r\n");
                let raw = raw_message.as_bytes();
                fixtures += 1;

                let buffered = AuthenticatedMessage::parse(raw).unwrap();
                let dkim = resolver
                    .verify_dkim_(caches.parameters(&buffered), 1667843664)
                    .await;
                let arc = resolver.verify_arc(caches.parameters(&buffered)).await;
                assert!(dkim.iter().any(|o| o.result() == &DkimResult::Pass));
                let results = AuthenticationResults::new("manchego.org")
                    .with_dkim_results(&dkim, "manchego.org");
                let seal = arc
                    .can_be_sealed()
                    .then(|| sealer().seal(&buffered, &results, &arc).unwrap());

                for &chunk in CHUNKS {
                    let what = format!("{} chunk {chunk}", file_name.display());
                    let streamed = stream(raw, chunk, true);
                    let message = streamed.message();
                    assert!(message.raw_body().is_empty(), "{what}");
                    assert_eq!(message.headers(), buffered.headers(), "{what}");
                    for expected in &buffered.body_hashes {
                        assert!(message.body_hashes.contains(expected), "{what}");
                    }

                    let s_dkim = resolver
                        .verify_dkim_(caches.parameters(&message), 1667843664)
                        .await;
                    assert_eq!(
                        s_dkim.iter().map(|o| o.result()).collect::<Vec<_>>(),
                        dkim.iter().map(|o| o.result()).collect::<Vec<_>>(),
                        "{what}"
                    );
                    let s_arc = resolver.verify_arc(caches.parameters(&message)).await;
                    assert_eq!(s_arc.result(), arc.result(), "{what}");

                    if let Some(seal) = &seal {
                        let s_seal = sealer().seal(&message, &results, &s_arc).unwrap();
                        assert_eq!(s_seal.signature.bh, seal.signature.bh, "{what}");
                        assert_eq!(s_seal.signature.h, seal.signature.h, "{what}");
                    }

                    let mut tampered = raw.to_vec();
                    tampered.extend_from_slice(b"extra\r\n");
                    let t_buffered = AuthenticatedMessage::parse(&tampered).unwrap();
                    let t_streamed = stream(&tampered, chunk, false);
                    let t_message = t_streamed.message();
                    assert_eq!(
                        resolver
                            .verify_dkim_(caches.parameters(&t_message), 1667843664)
                            .await
                            .iter()
                            .map(|o| o.result().clone())
                            .collect::<Vec<_>>(),
                        resolver
                            .verify_dkim_(caches.parameters(&t_buffered), 1667843664)
                            .await
                            .iter()
                            .map(|o| o.result().clone())
                            .collect::<Vec<_>>(),
                        "{what}"
                    );
                }
            }
        }
        assert!(fixtures >= 8, "{fixtures}");
    }

    // Sealing without the declared body hash fails instead of hashing an empty body.
    #[tokio::test]
    async fn seal_without_declared_hash_is_an_error() {
        let raw = b"From: a@manchego.org\r\nTo: b@example.org\r\nSubject: x\r\n\r\nbody\r\n";
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = new_cache("");
        let results = AuthenticationResults::new("manchego.org");

        let undeclared = stream(raw, 5, false);
        let message = undeclared.message();
        let arc = resolver.verify_arc(caches.parameters(&message)).await;
        assert_eq!(
            sealer().seal(&message, &results, &arc).unwrap_err(),
            Error::BodyNotAvailable
        );

        let declared = stream(raw, 5, true);
        let message = declared.message();
        let buffered = AuthenticatedMessage::parse(raw).unwrap();
        assert_eq!(
            sealer()
                .seal(&message, &results, &arc)
                .unwrap()
                .signature
                .bh,
            sealer()
                .seal(&buffered, &results, &arc)
                .unwrap()
                .signature
                .bh
        );
    }

    // Body length tags hash the first l= bytes; undeclared prepended hashes are refused.
    #[test]
    fn body_length_and_undeclared_signature() {
        let raw = b"From: a@manchego.org\r\nTo: b@example.org\r\nSubject: x\r\n\r\nline one\r\nline two\r\n";
        let signer = |relaxed: bool| {
            let canonicalization = if relaxed {
                Canonicalization::Relaxed
            } else {
                Canonicalization::Simple
            };
            DkimSigner::from_key(
                RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
                    PrivatePkcs1KeyDer::from_pem_slice(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
                ))
                .unwrap(),
            )
            .domain("manchego.org")
            .selector("rsa")
            .headers(["From", "To", "Subject"])
            .body_canonicalization(canonicalization)
            .body_length(true)
        };
        let signature = signer(true).sign(raw).unwrap().to_header();
        let mut signed = [signature.as_bytes(), raw].concat();
        signed.extend_from_slice(b"appended\r\n");

        let buffered = AuthenticatedMessage::parse_with_opts(&signed, None, false).unwrap();
        assert_eq!(buffered.body_hashes.len(), 1);
        assert_ne!(buffered.body_hashes[0].2, 0);
        for &chunk in CHUNKS {
            let mut stream = MessageStream::new().strict(false);
            for chunk in signed.chunks(chunk.min(signed.len())) {
                stream.write(chunk);
            }
            let streamed = stream.finish().unwrap();
            assert_eq!(streamed.body.len, (raw.len() - 55 + 10) as u64);
            assert_eq!(
                streamed.message().body_hashes,
                buffered.body_hashes,
                "chunk {chunk}"
            );

            let other = signer(false)
                .body_length(false)
                .sign(raw)
                .unwrap()
                .to_header();
            assert_eq!(
                streamed.message_with_headers(other.as_bytes()).unwrap_err(),
                Error::BodyNotAvailable
            );
        }
    }
}
