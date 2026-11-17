/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    AuthenticatedMessage,
    crypto::{HashAlgorithm, HashContext, HashImpl, Sha256},
    dkim::{Canonicalization, canonicalize::BodyHasher},
    dkim2::{Dkim2Hash, canonicalize::body_digests},
    headers::{Writable, Writer},
    stream::MessageStream,
};

#[inline]
pub fn write_canonical_body(
    canonicalization: Canonicalization,
    body: &[u8],
    limit: u64,
    writer: &mut impl Writer,
) {
    canonicalization.canonical_body(body, limit).write(writer);
}

pub fn whole_body_digest(canonicalization: Canonicalization, body: &[u8], limit: u64) -> Vec<u8> {
    let mut hasher = Sha256::hasher();
    canonicalization
        .canonical_body(body, limit)
        .write(&mut hasher);
    hasher.complete().as_ref().to_vec()
}

pub fn chunked_body_digest(
    canonicalization: Canonicalization,
    body: &[u8],
    limit: u64,
    chunk: usize,
) -> (Vec<u8>, u64) {
    let mut hasher = BodyHasher::new(Sha256::hasher(), canonicalization, limit);
    for piece in body.chunks(chunk) {
        hasher.write(piece);
    }
    let (hasher, hashed) = hasher.finish();
    (hasher.complete().as_ref().to_vec(), hashed)
}

#[inline]
pub fn canonicalize_headers<'x>(
    canonicalization: Canonicalization,
    headers: impl Iterator<Item = (&'x [u8], &'x [u8])>,
    out: &mut Vec<u8>,
) {
    canonicalization.canonicalize_headers(headers, out);
}

/// Asserts that `message` fed to a [`MessageStream`] in pieces of `chunk`
/// bytes yields the header fields and body hashes of the buffered parse.
pub fn assert_stream_matches_buffered(message: &[u8], chunk: usize) {
    let extra = [
        (Canonicalization::Relaxed, HashAlgorithm::Sha256),
        (Canonicalization::Simple, HashAlgorithm::Sha256),
    ];
    let mut stream = MessageStream::new()
        .strict(false)
        .also_hash_dkim2(Dkim2Hash::Sha256)
        .also_hash_dkim2(Dkim2Hash::Sha512);
    for (canonicalization, hash) in extra {
        stream = stream.also_hash(canonicalization, hash);
    }
    for piece in message.chunks(chunk.max(1)) {
        stream.write(piece);
    }
    let streamed = stream.finish();
    let Some(buffered) = AuthenticatedMessage::parse_with_opts(message, None, false) else {
        assert!(streamed.is_err(), "streamed a message that does not parse");
        return;
    };
    let streamed = streamed.expect("stream failed on a message that parses");
    let parsed = streamed.message();
    let body = buffered.raw_body();

    assert!(parsed.is_streamed() && parsed.raw_body().is_empty());
    assert_eq!(parsed.headers, buffered.headers);
    assert_eq!(streamed.body.len, body.len() as u64);
    for expected in &buffered.body_hashes {
        assert!(parsed.body_hashes.contains(expected), "{expected:?}");
    }
    for (canonicalization, hash) in extra {
        let digest = hash.hash(canonicalization.canonical_body(body, 0));
        assert!(parsed.body_hashes.contains(&(
            canonicalization,
            hash,
            0,
            digest.as_ref().to_vec()
        )));
    }
    let digests = &parsed.streamed_body.as_ref().expect("streamed").dkim2;
    for (streamed, whole) in digests
        .iter()
        .zip(body_digests(body, [true; Dkim2Hash::COUNT]))
    {
        assert_eq!(
            streamed.as_ref().map(AsRef::as_ref),
            whole.as_ref().map(AsRef::as_ref)
        );
    }
}
