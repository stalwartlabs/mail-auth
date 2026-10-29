/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM2 message hashes (§6) and header field canonicalization for the
//! signature input (§12.8).

use super::Dkim2Hash;
use crate::{
    crypto::{HashContext, HashImpl, HashOutput, Sha256, Sha512},
    dkim::{
        Canonicalization,
        canonicalize::{SpacedTokens, write_relaxed_name},
    },
    headers::{Writable, Writer},
};
use std::cmp::Ordering;

#[cfg(test)]
impl crate::crypto::HashAlgorithm {
    /// Computes the DKIM2 header fields hash (§6.2).
    pub(crate) fn headers_hash<'x>(
        &self,
        headers: impl IntoIterator<Item = (&'x [u8], &'x [u8])>,
    ) -> HashOutput {
        let headers = headers.into_iter();
        let mut signed: Vec<(&[u8], &[u8])> = Vec::with_capacity(headers.size_hint().0);
        signed.extend(headers.filter(|(name, _)| !is_non_signed_header(name)));
        signed.reverse();
        signed.sort_by(|(a, _), (b, _)| cmp_ignore_ascii_case(a.trim_ascii(), b.trim_ascii()));
        self.hash(RelaxedHeaders(&signed))
    }

    /// Computes the DKIM2 body hash (§6.1).
    pub(crate) fn body_hash(&self, body: &[u8]) -> HashOutput {
        self.hash(Canonicalization::Simple.canonical_body(body, u64::MAX))
    }
}

pub(crate) type Digests = [Option<HashOutput>; Dkim2Hash::COUNT];

impl Dkim2Hash {
    pub(crate) const COUNT: usize = 2;

    pub(crate) fn index(self) -> usize {
        match self {
            Dkim2Hash::Sha256 => 0,
            Dkim2Hash::Sha512 => 1,
        }
    }
}

pub(crate) fn header_digests<'x>(
    headers: impl IntoIterator<Item = (&'x [u8], &'x [u8])>,
    wanted: [bool; Dkim2Hash::COUNT],
) -> Digests {
    if wanted == [false; Dkim2Hash::COUNT] {
        return Default::default();
    }
    let headers = headers.into_iter();
    let mut signed: Vec<(&[u8], &[u8])> = Vec::with_capacity(headers.size_hint().0);
    signed.extend(headers.filter(|(name, _)| !is_non_signed_header(name)));
    signed.reverse();
    signed.sort_by(|(a, _), (b, _)| cmp_ignore_ascii_case(a.trim_ascii(), b.trim_ascii()));
    digests(RelaxedHeaders(&signed), wanted)
}

pub(crate) fn body_digests(body: &[u8], wanted: [bool; Dkim2Hash::COUNT]) -> Digests {
    digests(
        Canonicalization::Simple.canonical_body(body, u64::MAX),
        wanted,
    )
}

fn digests(data: impl Writable, wanted: [bool; Dkim2Hash::COUNT]) -> Digests {
    match wanted {
        [true, true] => {
            let mut both = Tee(Sha256::hasher(), Sha512::hasher());
            data.write(&mut both);
            [Some(both.0.complete()), Some(both.1.complete())]
        }
        [true, false] => [Some(Sha256::digest(data)), None],
        [false, true] => [None, Some(Sha512::digest(data))],
        [false, false] => [None, None],
    }
}

struct Tee<A, B>(A, B);

impl<A: Writer, B: Writer> Writer for Tee<A, B> {
    fn write(&mut self, buf: &[u8]) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

struct RelaxedHeaders<'a, 'x>(&'a [(&'x [u8], &'x [u8])]);

impl Writable for RelaxedHeaders<'_, '_> {
    fn write(self, writer: &mut impl Writer) {
        Canonicalization::Relaxed.canonicalize_headers(self.0.iter().copied(), writer);
    }
}

pub(crate) struct CanonicalizedHeaderWriter<'x, W: Writer> {
    inner: &'x mut W,
}

impl<'x, W: Writer> CanonicalizedHeaderWriter<'x, W> {
    pub fn new(inner: &'x mut W, field: &[u8]) -> Self {
        write_relaxed_name(field, inner);

        Self { inner }
    }

    pub fn finalize(self) {
        self.inner.write(b"\r\n");
    }
}

impl<'x, W: Writer> Writer for CanonicalizedHeaderWriter<'x, W> {
    fn write(&mut self, buf: &[u8]) {
        for token in SpacedTokens::new(buf) {
            self.inner.write(token.token);
        }
    }
}

pub(crate) fn cmp_ignore_ascii_case(a: &[u8], b: &[u8]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            let (x, y) = (x.to_ascii_lowercase(), y.to_ascii_lowercase());
            if x != y {
                return x.cmp(&y);
            }
        }
    }

    a.len().cmp(&b.len())
}

pub(super) fn is_non_signed_header(name: &[u8]) -> bool {
    let name = name.trim_ascii();
    hashify::set_ignore_case!(
        name,
        b"apparently-to",
        b"arc-authentication-results",
        b"arc-message-signature",
        b"arc-seal",
        b"authentication-results",
        b"auto-submitted",
        b"delivered-to",
        b"dkim-signature",
        b"dkim2-signature",
        b"dl-expansion-history",
        b"message-instance",
        b"original-recipient",
        b"received",
        b"return-path",
        b"sio-label-history",
        b"vbr-info",
        b"x400-received",
        b"x400-trace",
    ) || matches!(name, [b'x' | b'X', b'-', ..])
        || name
            .get(..RECEIVED_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RECEIVED_PREFIX))
}

const RECEIVED_PREFIX: &[u8] = b"received-";

#[cfg(test)]
mod test {
    use super::is_non_signed_header;
    use crate::crypto::HashAlgorithm;

    #[test]
    fn excluded_headers_are_classified() {
        for name in [
            "received",
            "Received",
            "return-path",
            "delivered-to",
            "Delivered-To",
            "authentication-results",
            "dkim-signature",
            "DKIM-Signature",
            "message-instance",
            "dkim2-signature",
            "arc-seal",
            "arc-message-signature",
            "arc-authentication-results",
            "x-spam-score",
            "X-Anything",
            "Received-SPF",
            "received-dkim2",
            "Apparently-To",
            "auto-submitted",
            "DL-Expansion-History",
            "Original-Recipient",
            "SIO-Label-History",
            "VBR-Info",
            "X400-Received",
            "x400-trace",
        ] {
            assert!(
                is_non_signed_header(name.as_bytes()),
                "{name} must be ignored"
            );
        }
        for name in [
            "from",
            "to",
            "subject",
            "date",
            "message-id",
            "list-unsubscribe",
            "receivedx",
            "x400",
            "x",
        ] {
            assert!(
                !is_non_signed_header(name.as_bytes()),
                "{name} must be signed"
            );
        }
    }

    // The single-pass digests equal the per-algorithm hashes.
    #[test]
    fn digests_match_single_hashes() {
        use super::{Dkim2Hash, body_digests, header_digests};

        let headers: &[(&[u8], &[u8])] = &[
            (b"Subject", b" one \r\n"),
            (b"From", b" a@example.com\r\n"),
            (b"Received", b" x\r\n"),
            (b"subject", b" two\r\n"),
        ];
        let body = b"line one\r\nline  two\r\n\r\n\r\n";
        for wanted in [[true, true], [true, false], [false, true]] {
            let header = header_digests(headers.iter().copied(), wanted);
            let body_hashes = body_digests(body, wanted);
            for (hash, enabled) in [Dkim2Hash::Sha256, Dkim2Hash::Sha512]
                .into_iter()
                .zip(wanted)
            {
                let expected_header =
                    enabled.then(|| hash.algorithm().headers_hash(headers.iter().copied()));
                let expected_body = enabled.then(|| hash.algorithm().body_hash(body));
                assert_eq!(header.get(hash.index()).cloned().flatten(), expected_header);
                assert_eq!(
                    body_hashes.get(hash.index()).cloned().flatten(),
                    expected_body
                );
            }
        }
        assert_eq!(
            header_digests(headers.iter().copied(), [false, false]),
            [None, None]
        );
    }

    #[test]
    fn body_hash_ignores_trailing_blank_lines() {
        let none = HashAlgorithm::Sha256.body_hash(b"Hello, world.");
        let one = HashAlgorithm::Sha256.body_hash(b"Hello, world.\r\n");
        let many = HashAlgorithm::Sha256.body_hash(b"Hello, world.\r\n\r\n\r\n");
        assert_eq!(none, one);
        assert_eq!(one, many);
    }

    #[test]
    fn empty_body_hashes_as_single_crlf() {
        assert_eq!(
            HashAlgorithm::Sha256.body_hash(b""),
            HashAlgorithm::Sha256.body_hash(b"\r\n\r\n")
        );
    }
}
