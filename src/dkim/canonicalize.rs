/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Canonicalization, Signature};
use crate::common::{
    crypto::HashContext,
    headers::{HeaderStream, Writable, Writer},
};

/// Incremental body hasher for streaming DKIM signing.
///
/// This struct allows body content to be fed in chunks while maintaining
/// the canonicalization state between calls.
pub struct BodyHasher<H> {
    hasher: H,
    canonicalization: Canonicalization,
    body_length_limit: u64,
    bytes_hashed: u64,
    // Canonicalization state
    crlf_seq: usize,
    last_ch: u8,
    is_empty: bool,
    done: bool,
}

impl<H: Writer> BodyHasher<H> {
    /// Creates a new incremental body hasher.
    ///
    /// # Arguments
    /// * `hasher` - The hash context to write canonicalized body to
    /// * `canonicalization` - The body canonicalization algorithm to use
    /// * `body_length_limit` - Maximum bytes to hash (0 = unlimited)
    pub fn new(hasher: H, canonicalization: Canonicalization, body_length_limit: u64) -> Self {
        Self {
            hasher,
            canonicalization,
            body_length_limit,
            bytes_hashed: 0,
            crlf_seq: 0,
            last_ch: 0,
            is_empty: true,
            done: false,
        }
    }

    /// Feed a chunk of body data to the hasher.
    ///
    /// Data is canonicalized according to the configured algorithm and
    /// written to the underlying hash context.
    pub fn write(&mut self, chunk: &[u8]) {
        if self.done {
            return;
        }

        // Apply body length limit if set
        let chunk = if self.body_length_limit > 0 {
            let remaining = self.body_length_limit.saturating_sub(self.bytes_hashed);
            if remaining == 0 {
                return;
            }
            let limit = std::cmp::min(remaining as usize, chunk.len());
            &chunk[..limit]
        } else {
            chunk
        };

        self.bytes_hashed += chunk.len() as u64;

        match self.canonicalization {
            Canonicalization::Relaxed => {
                for &ch in chunk {
                    match ch {
                        b' ' | b'\t' => {
                            while self.crlf_seq > 0 {
                                self.hasher.write(b"\r\n");
                                self.crlf_seq -= 1;
                            }
                            self.is_empty = false;
                        }
                        b'\n' => {
                            self.crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while self.crlf_seq > 0 {
                                self.hasher.write(b"\r\n");
                                self.crlf_seq -= 1;
                            }

                            if self.last_ch == b' ' || self.last_ch == b'\t' {
                                self.hasher.write(b" ");
                            }

                            self.hasher.write(&[ch]);
                            self.is_empty = false;
                        }
                    }
                    self.last_ch = ch;
                }
            }
            Canonicalization::Simple => {
                for &ch in chunk {
                    match ch {
                        b'\n' => {
                            self.crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while self.crlf_seq > 0 {
                                self.hasher.write(b"\r\n");
                                self.crlf_seq -= 1;
                            }
                            self.hasher.write(&[ch]);
                            self.is_empty = false;
                        }
                    }
                }
            }
        }
    }

    /// Finalize the body hash.
    ///
    /// Applies the final canonicalization rules (trailing CRLF handling)
    /// and returns the completed hash context along with the number of
    /// body bytes that were processed.
    pub fn finish(mut self) -> (H, u64)
    where
        H: HashContext,
    {
        if !self.done {
            self.done = true;
            match self.canonicalization {
                Canonicalization::Relaxed => {
                    if !self.is_empty {
                        self.hasher.write(b"\r\n");
                    }
                }
                Canonicalization::Simple => {
                    self.hasher.write(b"\r\n");
                }
            }
        }
        (self.hasher, self.bytes_hashed)
    }
}

pub struct CanonicalBody<'a> {
    canonicalization: Canonicalization,
    body: &'a [u8],
}

impl Writable for CanonicalBody<'_> {
    fn write(self, hasher: &mut impl Writer) {
        let mut crlf_seq = 0;

        match self.canonicalization {
            Canonicalization::Relaxed => {
                let mut last_ch = 0;
                let mut is_empty = true;

                for &ch in self.body {
                    match ch {
                        b' ' | b'\t' => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            is_empty = false;
                        }
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }

                            if last_ch == b' ' || last_ch == b'\t' {
                                hasher.write(b" ");
                            }

                            hasher.write(&[ch]);
                            is_empty = false;
                        }
                    }

                    last_ch = ch;
                }

                if !is_empty {
                    hasher.write(b"\r\n");
                }
            }
            Canonicalization::Simple => {
                for &ch in self.body {
                    match ch {
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            hasher.write(&[ch]);
                        }
                    }
                }

                hasher.write(b"\r\n");
            }
        }
    }
}

impl Canonicalization {
    pub fn canonicalize_headers<'a>(
        &self,
        headers: impl Iterator<Item = (&'a [u8], &'a [u8])>,
        hasher: &mut impl Writer,
    ) {
        match self {
            Canonicalization::Relaxed => {
                for (name, value) in headers {
                    for &ch in name {
                        if !ch.is_ascii_whitespace() {
                            hasher.write(&[ch.to_ascii_lowercase()]);
                        }
                    }

                    hasher.write(b":");
                    let mut bw = 0;
                    let mut last_ch = 0;

                    for &ch in value {
                        if !ch.is_ascii_whitespace() {
                            if [b' ', b'\t'].contains(&last_ch) && bw > 0 {
                                hasher.write_len(b" ", &mut bw);
                            }
                            hasher.write_len(&[ch], &mut bw);
                        }
                        last_ch = ch;
                    }

                    if last_ch == b'\n' {
                        hasher.write(b"\r\n");
                    }
                }
            }
            Canonicalization::Simple => {
                for (name, value) in headers {
                    hasher.write(name);
                    hasher.write(b":");
                    hasher.write(value);
                }
            }
        }
    }

    pub fn canonical_headers<'a>(
        &self,
        headers: Vec<(&'a [u8], &'a [u8])>,
    ) -> CanonicalHeaders<'a> {
        CanonicalHeaders {
            canonicalization: *self,
            headers,
        }
    }

    pub fn canonical_body<'a>(&self, body: &'a [u8], l: u64) -> CanonicalBody<'a> {
        CanonicalBody {
            canonicalization: *self,
            body: if l == 0 || body.is_empty() {
                body
            } else {
                &body[..std::cmp::min(l as usize, body.len())]
            },
        }
    }

    pub fn serialize_name(&self, writer: &mut impl Writer) {
        writer.write(match self {
            Canonicalization::Relaxed => b"relaxed",
            Canonicalization::Simple => b"simple",
        });
    }
}

impl Signature {
    pub fn canonicalize<'x>(
        &self,
        mut message: impl HeaderStream<'x>,
    ) -> (usize, CanonicalHeaders<'x>, Vec<String>, CanonicalBody<'x>) {
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        while let Some((name, value)) = message.next_header() {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((name, value));
                found_headers[pos] = true;
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let body = message.body();
        let body_len = body.len();
        let canonical_headers = self.ch.canonical_headers(headers);
        let canonical_body = self.ch.canonical_body(body, u64::MAX);

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string());
            }
        }

        (body_len, canonical_headers, signed_headers, canonical_body)
    }
}

pub struct CanonicalHeaders<'a> {
    canonicalization: Canonicalization,
    headers: Vec<(&'a [u8], &'a [u8])>,
}

impl Writable for CanonicalHeaders<'_> {
    fn write(self, writer: &mut impl Writer) {
        self.canonicalization
            .canonicalize_headers(self.headers.into_iter().rev(), writer)
    }
}

#[cfg(test)]
mod test {
    use mail_builder::encoders::base64::base64_encode;

    use super::{BodyHasher, CanonicalBody, CanonicalHeaders};
    use crate::{
        common::{
            crypto::{HashContext, HashImpl, Sha256},
            headers::{HeaderIterator, Writable},
        },
        dkim::Canonicalization,
    };

    #[test]
    #[allow(clippy::needless_collect)]
    fn dkim_canonicalize() {
        for (message, (relaxed_headers, relaxed_body), (simple_headers, simple_body)) in [
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                ),
                (
                    concat!("a:X\r\n", "b:Y Z\r\n",),
                    concat!(" C\r\n", "D E\r\n"),
                ),
                ("A: X\r\nB : Y\t\r\n\tZ  \r\n", " C \r\nD \t E\r\n"),
            ),
            (
                concat!(
                    "  From : John\tdoe <jdoe@domain.com>\t\r\n",
                    "SUB JECT:\ttest  \t  \r\n\r\n",
                    " body \t   \r\n",
                    "\r\n",
                    "\r\n",
                ),
                (
                    concat!("from:John doe <jdoe@domain.com>\r\n", "subject:test\r\n"),
                    " body\r\n",
                ),
                (
                    concat!(
                        "  From : John\tdoe <jdoe@domain.com>\t\r\n",
                        "SUB JECT:\ttest  \t  \r\n"
                    ),
                    " body \t   \r\n",
                ),
            ),
            (
                "H: value\t\r\n\r\n",
                ("h:value\r\n", ""),
                ("H: value\t\r\n", "\r\n"),
            ),
            (
                "\tx\t: \t\t\tz\r\n\r\nabc",
                ("x:z\r\n", "abc\r\n"),
                ("\tx\t: \t\t\tz\r\n", "abc\r\n"),
            ),
            (
                "Subject: hello\r\n\r\n\r\n",
                ("subject:hello\r\n", ""),
                ("Subject: hello\r\n", "\r\n"),
            ),
        ] {
            let mut header_iterator = HeaderIterator::new(message.as_bytes());
            let parsed_headers = (&mut header_iterator).collect::<Vec<_>>();
            let raw_body = header_iterator
                .body_offset()
                .map(|pos| &message.as_bytes()[pos..])
                .unwrap_or_default();

            for (canonicalization, expected_headers, expected_body) in [
                (Canonicalization::Relaxed, relaxed_headers, relaxed_body),
                (Canonicalization::Simple, simple_headers, simple_body),
            ] {
                let mut headers = Vec::new();
                CanonicalHeaders {
                    canonicalization,
                    headers: parsed_headers.iter().cloned().rev().collect(),
                }
                .write(&mut headers);
                assert_eq!(expected_headers, String::from_utf8(headers).unwrap());

                let mut body = Vec::new();
                CanonicalBody {
                    canonicalization,
                    body: raw_body,
                }
                .write(&mut body);
                assert_eq!(expected_body, String::from_utf8(body).unwrap());
            }
        }

        // Test empty body hashes
        for (canonicalization, hash) in [
            (
                Canonicalization::Relaxed,
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            ),
            (
                Canonicalization::Simple,
                "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=",
            ),
        ] {
            for body in ["\r\n", ""] {
                let mut hasher = Sha256::hasher();
                CanonicalBody {
                    canonicalization,
                    body: body.as_bytes(),
                }
                .write(&mut hasher);

                #[cfg(feature = "sha1")]
                {
                    use sha1::Digest;
                    assert_eq!(
                        String::from_utf8(base64_encode(hasher.finalize().as_ref()).unwrap())
                            .unwrap(),
                        hash,
                    );
                }

                #[cfg(all(feature = "ring", not(feature = "sha1")))]
                assert_eq!(
                    String::from_utf8(base64_encode(hasher.finish().as_ref()).unwrap()).unwrap(),
                    hash,
                );
            }
        }
    }

    #[test]
    fn body_hasher_matches_canonical_body() {
        // Test that BodyHasher produces identical results to CanonicalBody
        for (body, canonicalization) in [
            (" C \r\nD \t E\r\n", Canonicalization::Relaxed),
            (" C \r\nD \t E\r\n", Canonicalization::Simple),
            (" body \t   \r\n\r\n\r\n", Canonicalization::Relaxed),
            (" body \t   \r\n\r\n\r\n", Canonicalization::Simple),
            ("", Canonicalization::Relaxed),
            ("", Canonicalization::Simple),
            ("\r\n", Canonicalization::Relaxed),
            ("\r\n", Canonicalization::Simple),
            ("abc", Canonicalization::Relaxed),
            ("abc", Canonicalization::Simple),
            ("hello world\r\n", Canonicalization::Relaxed),
            ("hello world\r\n", Canonicalization::Simple),
        ] {
            // Hash using CanonicalBody
            let mut expected_hasher = Sha256::hasher();
            CanonicalBody {
                canonicalization,
                body: body.as_bytes(),
            }
            .write(&mut expected_hasher);
            let expected_hash = expected_hasher.complete();

            // Hash using BodyHasher (single chunk)
            let mut body_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 0);
            body_hasher.write(body.as_bytes());
            let (actual_hasher, _) = body_hasher.finish();
            let actual_hash = actual_hasher.complete();

            assert_eq!(
                expected_hash.as_ref(),
                actual_hash.as_ref(),
                "BodyHasher (single chunk) mismatch for body {:?} with {:?} canonicalization",
                body,
                canonicalization
            );
        }
    }

    #[test]
    fn body_hasher_chunked_matches_single() {
        // Test that chunked input produces same result as single input
        let body = " C \r\nD \t E\r\nMore content here\r\n\r\n";

        for canonicalization in [Canonicalization::Relaxed, Canonicalization::Simple] {
            // Single chunk
            let mut single_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 0);
            single_hasher.write(body.as_bytes());
            let (single_result, single_len) = single_hasher.finish();
            let single_hash = single_result.complete();

            // Multiple chunks - split at various points
            for chunk_size in [1, 2, 3, 5, 7, 10] {
                let mut chunked_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 0);
                for chunk in body.as_bytes().chunks(chunk_size) {
                    chunked_hasher.write(chunk);
                }
                let (chunked_result, chunked_len) = chunked_hasher.finish();
                let chunked_hash = chunked_result.complete();

                assert_eq!(
                    single_hash.as_ref(),
                    chunked_hash.as_ref(),
                    "Chunked (size {}) mismatch for {:?} canonicalization",
                    chunk_size,
                    canonicalization
                );
                assert_eq!(single_len, chunked_len);
            }
        }
    }

    #[test]
    fn body_hasher_length_limit() {
        let body = "Hello World! This is a test body.\r\n";

        for canonicalization in [Canonicalization::Relaxed, Canonicalization::Simple] {
            // Hash with limit of 10 bytes
            let mut limited_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 10);
            limited_hasher.write(body.as_bytes());
            let (limited_result, limited_len) = limited_hasher.finish();
            let limited_hash = limited_result.complete();

            // Hash the first 10 bytes using CanonicalBody
            let mut expected_hasher = Sha256::hasher();
            CanonicalBody {
                canonicalization,
                body: &body.as_bytes()[..10],
            }
            .write(&mut expected_hasher);
            let expected_hash = expected_hasher.complete();

            assert_eq!(
                expected_hash.as_ref(),
                limited_hash.as_ref(),
                "Body length limit mismatch for {:?} canonicalization",
                canonicalization
            );
            assert_eq!(limited_len, 10);
        }
    }

    #[test]
    fn body_hasher_split_crlf() {
        // Test that CRLF split across chunks is handled correctly
        let body = "Line1\r\nLine2\r\n";

        for canonicalization in [Canonicalization::Relaxed, Canonicalization::Simple] {
            // Single chunk reference
            let mut single_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 0);
            single_hasher.write(body.as_bytes());
            let (single_result, _) = single_hasher.finish();
            let single_hash = single_result.complete();

            // Split right in the middle of \r\n
            let mut split_hasher = BodyHasher::new(Sha256::hasher(), canonicalization, 0);
            split_hasher.write(b"Line1\r");
            split_hasher.write(b"\nLine2\r");
            split_hasher.write(b"\n");
            let (split_result, _) = split_hasher.finish();
            let split_hash = split_result.complete();

            assert_eq!(
                single_hash.as_ref(),
                split_hash.as_ref(),
                "Split CRLF mismatch for {:?} canonicalization",
                canonicalization
            );
        }
    }
}
