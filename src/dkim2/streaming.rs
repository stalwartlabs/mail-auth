/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Streaming DKIM2 signing: the message is fed in chunks and only the header
//! section is buffered, which keeps memory usage low for large messages.

use super::{
    Dkim2Hash, Dkim2Output, Dkim2Signed, Dkim2Signer, MessageInstance, canonicalize::Digests,
    sign::Hop,
};
use crate::{
    AuthenticatedMessage, Error,
    crypto::{HashContext, HashImpl, Sha256, Sha512},
    dkim::{Canonicalization, canonicalize::BodyHasher, streaming::find_header_boundary},
    headers::{HeaderIterator, Writer},
    signer::Ready,
};

/// A streaming DKIM2 signer, created by [`Dkim2Signer::sign_streaming`].
///
/// Avoids loading the entire message into memory before signing. Headers are
/// buffered until the header/body boundary (`\r\n\r\n`) is found; the body is
/// then hashed (§6.1) as it arrives and never stored. Everything else DKIM2
/// signing needs (the `From` check, the existing DKIM2 header fields, the
/// header hash and the signature input) comes from the header section alone.
///
/// [`finish`](Self::finish) returns the same [`Dkim2Signed`] that
/// [`Dkim2Signer::sign`] returns for the same message, hop and signing time.
/// The boundary is only recognised with CRLF line endings, as messages have
/// on the wire (§17); a message without one is buffered whole and signed as
/// `sign` would sign it.
///
/// Signing a changed message ([`Dkim2Signer::sign_revised`]) needs both
/// versions of the message and is not available while streaming.
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{crypto::Ed25519Key, dkim2::{Dkim2Signer, Hop}};
///
/// # fn main() -> mail_auth::Result<()> {
/// # let pkcs8_der: Vec<u8> = Vec::new();
/// # let message_chunks: Vec<&[u8]> = Vec::new();
/// let signer = Dkim2Signer::from_key(Ed25519Key::from_pkcs8_der(&pkcs8_der)?)
///     .domain("example.com")
///     .selector("ed25519");
/// let mut stream = signer.sign_streaming();
/// for chunk in message_chunks {
///     stream.write(chunk);
/// }
/// let signed = stream.finish(
///     Hop::real("sender@example.com", ["recipient@example.org"]),
///     None,
/// )?;
/// let headers = signed.to_header();
/// # Ok(())
/// # }
/// ```
pub struct Dkim2SigningStream<'a> {
    signer: &'a Dkim2Signer<Ready>,
    /// The header section, including the empty line, once the boundary has
    /// been found; until then, everything written so far.
    buffer: Vec<u8>,
    /// Length of the prefix of `buffer` already searched for the boundary.
    scanned: usize,
    /// Hashes the body, once the boundary has been found.
    body: Option<BodyHasher<BodyDigests>>,
}

impl Dkim2Signer<Ready> {
    /// Creates a streaming signer that borrows this signer and its keys.
    ///
    /// Feed the raw message, including any DKIM2 header fields added by
    /// earlier hops, with [`Dkim2SigningStream::write`], then call
    /// [`Dkim2SigningStream::finish`] to obtain the header fields to prepend.
    pub fn sign_streaming(&self) -> Dkim2SigningStream<'_> {
        Dkim2SigningStream {
            signer: self,
            buffer: Vec::with_capacity(8192),
            scanned: 0,
            body: None,
        }
    }
}

impl Dkim2SigningStream<'_> {
    /// Feeds the next chunk of raw message data to the signer.
    ///
    /// Data must be provided in order, starting with the headers. Chunks may
    /// split lines, and the header/body boundary, anywhere.
    pub fn write(&mut self, chunk: &[u8]) {
        if let Some(body) = &mut self.body {
            body.write(chunk);
            return;
        }

        self.buffer.extend_from_slice(chunk);
        match find_header_boundary(&self.buffer[self.scanned..]) {
            Some(pos) => {
                let boundary = self.scanned + pos;
                let mut body = BodyDigests::hasher(self.signer, &self.buffer[..boundary]);
                body.write(&self.buffer[boundary..]);
                self.buffer.truncate(boundary);
                self.body = Some(body);
            }
            None => self.scanned = self.buffer.len().saturating_sub(3),
        }
    }

    /// Consumes the stream and signs the message for `hop`.
    ///
    /// `hop` and `verified` are as in [`Dkim2Signer::sign`]. The current
    /// system time is used for `t=`. A stream that never saw the header/body
    /// boundary holds the whole message, which is then signed as
    /// [`Dkim2Signer::sign`] signs it.
    ///
    /// # Errors
    ///
    /// Same as [`Dkim2Signer::sign`].
    pub fn finish<A, R, I>(
        self,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
    ) -> crate::Result<Dkim2Signed>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.finish_at(hop, verified, super::sign::now())
    }

    pub(crate) fn finish_at<A, R, I>(
        self,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        let message = AuthenticatedMessage::parse(&self.buffer).ok_or(Error::Parse)?;
        let body = self.body.unwrap_or_else(|| {
            // No `\r\n\r\n` boundary was seen, so the whole message is
            // buffered: hash its body as `sign` does.
            let mut body = BodyDigests::hasher(self.signer, message.raw_headers());
            body.write(message.raw_body());
            body
        });
        let body = body.finish().0.complete();

        let new_instance = MessageInstance::from_recipe_with_body(
            &message,
            None,
            &self.signer.hashes,
            Some(body.clone()),
        );
        self.signer
            .sign_internal(
                &message,
                hop,
                new_instance.as_ref(),
                verified,
                now,
                Some(body),
            )
            .map(|signature| Dkim2Signed {
                message_instance: new_instance,
                signature,
            })
    }
}

/// Receives the canonicalized body (§6.1) and computes each DKIM2 body hash
/// that signing needs.
struct BodyDigests {
    sha256: Option<<Sha256 as HashImpl>::Context>,
    sha512: Option<<Sha512 as HashImpl>::Context>,
}

impl BodyDigests {
    /// Starts hashing the body of a message with this header section.
    ///
    /// A new `Message-Instance` uses the signer's hashes. A message that
    /// already has one may be checked against its most recent instance
    /// instead, which can use any hash, so it gets all of them.
    fn hasher(signer: &Dkim2Signer<Ready>, header_section: &[u8]) -> BodyHasher<Self> {
        let has_instance = HeaderIterator::new(header_section)
            .any(|(name, _)| name.trim_ascii().eq_ignore_ascii_case(b"Message-Instance"));
        let wanted = |hash| has_instance || signer.hashes.contains(&hash);

        // DKIM1 "simple" canonicalization with no length limit.
        BodyHasher::new(
            BodyDigests {
                sha256: wanted(Dkim2Hash::Sha256).then(Sha256::hasher),
                sha512: wanted(Dkim2Hash::Sha512).then(Sha512::hasher),
            },
            Canonicalization::Simple,
            0,
        )
    }

    fn complete(self) -> Digests {
        let mut digests = Digests::default();
        digests[Dkim2Hash::Sha256.index()] = self.sha256.map(HashContext::complete);
        digests[Dkim2Hash::Sha512.index()] = self.sha512.map(HashContext::complete);
        digests
    }
}

impl Writer for BodyDigests {
    fn write(&mut self, buf: &[u8]) {
        if let Some(hasher) = &mut self.sha256 {
            hasher.write(buf);
        }
        if let Some(hasher) = &mut self.sha512 {
            hasher.write(buf);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        dkim2::{
            Dkim2Error, Dkim2Hash, Dkim2Signed, Dkim2Signer, Hop,
            sign::{
                test::{TIMESTAMP, load_ed25519, load_rsa, normalize_crlf, resource},
                test_authentic_from::LenientFrom,
            },
        },
        signer::Ready,
    };

    const CHUNK_SIZES: &[usize] = &[1, 2, 3, 4, 5, 7, 13, 64, 8192, usize::MAX];

    type TestHop = Hop<&'static str, [&'static str; 1], String>;

    fn signers() -> Vec<(&'static str, Dkim2Signer<Ready>)> {
        let ed25519 = || {
            Dkim2Signer::from_key(load_ed25519("test1.dkim2.com", "ed25519"))
                .domain("test1.dkim2.com")
                .selector("ed25519")
        };
        vec![
            ("ed25519/sha256", ed25519()),
            ("ed25519/sha512", ed25519().hashes([Dkim2Hash::Sha512])),
            (
                "ed25519/sha256+sha512",
                ed25519().hashes([Dkim2Hash::Sha256, Dkim2Hash::Sha512]),
            ),
            (
                "rsa+ed25519",
                Dkim2Signer::from_key(load_rsa("test1.dkim2.com", "sel1"))
                    .domain("test1.dkim2.com")
                    .selector("sel1")
                    .additional_key(load_ed25519("test1.dkim2.com", "ed25519"), "ed25519"),
            ),
        ]
    }

    fn originator_hop() -> TestHop {
        Hop::real("sender@test1.dkim2.com", ["recipient@example.com"])
    }

    /// Streams `message` in chunks of every size, asserts that each result
    /// equals what `sign` returns, and returns that.
    fn assert_streams_as_signed(
        signer: &Dkim2Signer<Ready>,
        message: &[u8],
        hop: TestHop,
        what: &str,
    ) -> crate::Result<Dkim2Signed> {
        let expected = signer.sign_at(message, hop.clone(), None, TIMESTAMP);
        for &size in CHUNK_SIZES {
            let mut stream = signer.sign_streaming();
            for chunk in message.chunks(size) {
                stream.write(chunk);
            }
            assert_eq!(
                stream.finish_at(hop.clone(), None, TIMESTAMP),
                expected,
                "{what}, chunk size {size}"
            );
        }
        expected
    }

    // Every fixture, and body canonicalization (§6.1) and truncation edge
    // cases, signed by every signer in chunks of any size.
    #[test]
    fn streaming_matches_sign() {
        let _lenient = LenientFrom::new();
        let mut messages = std::fs::read_dir(resource(&["emails"]))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let message = std::fs::read(&path).unwrap();
                (
                    path.display().to_string(),
                    normalize_crlf(&message).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        messages.sort();
        assert!(!messages.is_empty());

        let headers = "From: sender@test1.dkim2.com\r\nSubject: x\r\n";
        for body in [
            "".to_string(),
            "\r\n".to_string(),
            "\r\n\r\n\r\n".to_string(),
            "\r\nbody".to_string(),
            "\r\nbody\r\n\r\n\r\n\r\n".to_string(),
            "\r\n \r\n\t\r\n".to_string(),
            "\r\nline one \r\n\r\nline three\t\r\n\r\n".to_string(),
            "\r\n.dot first\r\n..double\r\n".to_string(),
            "\r".to_string(),
            format!("\r\n{}\r\n", "x".repeat(20_000)),
            format!("\r\n{}", "line\r\n\r\n".repeat(5_000)),
        ] {
            let message = format!("{headers}{body}");
            let what = format!("{:?}", &message[..message.len().min(60)]);
            messages.push((what, message.into_bytes()));
        }
        for message in [
            "From: sender@test1.dkim2.com\r\nSubject: x",
            "From: sender@test1.dkim2.com\r\nSubject: x\r",
            "From: sender@test1.dkim2.com\nSubject: x\n\nLF only\n\n",
        ] {
            messages.push((format!("{message:?}"), message.as_bytes().to_vec()));
        }

        for (name, signer) in signers() {
            for (what, message) in &messages {
                let what = format!("{what} with {name}");
                let signed = assert_streams_as_signed(&signer, message, originator_hop(), &what);
                assert!(signed.is_ok(), "{what}: {signed:?}");
            }
            // Input `sign` cannot parse either.
            for message in ["", "From: sender@test1.dkim2.com"] {
                let what = format!("{message:?} with {name}");
                let signed =
                    assert_streams_as_signed(&signer, message.as_bytes(), originator_hop(), &what);
                assert!(signed.is_err(), "{what}");
            }
        }
    }

    // A forwarder that does not change the message checks it against the
    // most recent Message-Instance (§12.1). The streamed body digests must be
    // used for that check, including a hash the forwarder itself does not
    // use, and a changed body must still be rejected.
    #[test]
    fn streaming_forwarder_checks_body_against_instance() {
        let message = normalize_crlf(&std::fs::read(resource(&["emails", "simple.eml"])).unwrap())
            .into_owned();
        let forwarder = Dkim2Signer::from_key(load_ed25519("test2.dkim2.com", "ed25519"))
            .domain("example.com")
            .selector("ed25519")
            .out_of_band_arrangement();
        let next_hop = || Hop::real("forwarder@example.com", ["final@example.net"]);

        for (name, originator) in signers() {
            let mut forwarded = Vec::new();
            originator
                .sign_at(message.as_slice(), originator_hop(), None, TIMESTAMP)
                .unwrap()
                .write(&mut forwarded);
            forwarded.extend_from_slice(&message);

            let signed =
                assert_streams_as_signed(&forwarder, &forwarded, next_hop(), name).unwrap();
            assert!(signed.message_instance.is_none(), "{name}");
            assert_eq!((signed.signature.i, signed.signature.m), (2, 1), "{name}");

            let pos = forwarded
                .windows(6)
                .rposition(|window| window == b"simple")
                .unwrap();
            forwarded[pos] = b'S';
            assert!(
                matches!(
                    assert_streams_as_signed(&forwarder, &forwarded, next_hop(), name),
                    Err(crate::Error::Dkim2(Dkim2Error::BodyHashMismatch {
                        m: 1,
                        ..
                    }))
                ),
                "{name}"
            );
        }
    }
}
