/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    common::{
        crypto::{HashContext, HashImpl, HashOutput, Sha1, Sha256},
        headers::Writer,
    },
    dkim::Canonicalization,
};
use std::cmp::Ordering;

impl crate::common::crypto::HashAlgorithm {
    /// Computes the DKIM2 header-fields hash
    pub fn header_fields_hash<'x>(
        &self,
        headers: impl IntoIterator<Item = (&'x [u8], &'x [u8])>,
    ) -> HashOutput {
        let mut signed: Vec<(&[u8], &[u8])> = headers
            .into_iter()
            .filter(|(name, _)| !is_non_signed_header(name))
            .collect();
        signed.reverse();
        signed.sort_by(|(a, _), (b, _)| cmp_ignore_ascii_case(a, b));

        match self {
            Self::Sha256 => {
                let mut hasher = Sha256::hasher();
                Canonicalization::Relaxed.canonicalize_headers(signed.into_iter(), &mut hasher);
                hasher.complete()
            }
            Self::Sha1 => {
                let mut hasher = Sha1::hasher();
                Canonicalization::Relaxed.canonicalize_headers(signed.into_iter(), &mut hasher);
                hasher.complete()
            }
        }
    }

    /// Computes the DKIM2 body hash
    pub fn body_hash(&self, body: &[u8]) -> HashOutput {
        self.hash(Canonicalization::Simple.canonical_body(body, u64::MAX))
    }
}

pub(crate) struct CanonicalizedFieldWriter<'x, W: Writer> {
    inner: &'x mut W,
}

impl<'x, W: Writer> CanonicalizedFieldWriter<'x, W> {
    pub fn new(inner: &'x mut W, field: &[u8]) -> Self {
        for &ch in field {
            if !ch.is_ascii_whitespace() {
                inner.write(&[ch.to_ascii_lowercase()]);
            }
        }
        inner.write(b":");

        Self { inner }
    }

    pub fn finalize(self) {
        self.inner.write(b"\r\n");
    }
}

impl<'x, W: Writer> Writer for CanonicalizedFieldWriter<'x, W> {
    fn write(&mut self, buf: &[u8]) {
        for &ch in buf {
            if !ch.is_ascii_whitespace() {
                self.inner.write(&[ch]);
            }
        }
    }
}

pub(crate) fn cmp_ignore_ascii_case(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

pub(super) fn is_non_signed_header(name: &[u8]) -> bool {
    let name = name.trim_ascii();
    hashify::tiny_map_ignore_case!(name,
        b"received" => true,
        b"return-path" => true,
        b"delivered-to" => true,
        b"authentication-results" => true,
        b"dkim-signature" => true,
        b"message-instance" => true,
        b"dkim2-signature" => true,
        b"arc-authentication-results" => true,
        b"arc-message-signature" => true,
        b"arc-seal" => true
    )
    .unwrap_or_else(|| {
        matches!(name.get(1), Some(&b'-')) && matches!(name.first(), Some(&b'x' | &b'X'))
    })
}

#[cfg(test)]
mod test {
    use super::is_non_signed_header;
    use crate::common::crypto::HashAlgorithm;

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
        ] {
            assert!(
                !is_non_signed_header(name.as_bytes()),
                "{name} must be signed"
            );
        }
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
