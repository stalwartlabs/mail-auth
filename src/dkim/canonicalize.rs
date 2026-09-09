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
    state: CanonicalState,
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
            state: CanonicalState::new(),
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
            &chunk[..remaining.min(chunk.len() as u64) as usize]
        } else {
            chunk
        };

        self.bytes_hashed += chunk.len() as u64;
        self.state
            .write(self.canonicalization, chunk, &mut self.hasher);
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
            self.state.finish(self.canonicalization, &mut self.hasher);
        }
        (self.hasher, self.bytes_hashed)
    }
}

const CRLF_RUN_MAX: usize = 32;
const CRLF_RUN: [u8; CRLF_RUN_MAX * 2] = {
    let mut run = [b'\r'; CRLF_RUN_MAX * 2];
    let mut pos = 1;
    while pos < run.len() {
        run[pos] = b'\n';
        pos += 2;
    }
    run
};
const SWAR_ONES: u64 = 0x0101_0101_0101_0101;
const SWAR_HIGH: u64 = 0x8080_8080_8080_8080;
const MEMCHR_MIN_LEN: usize = 16;

#[inline(always)]
fn write_crlf_run(writer: &mut impl Writer, count: usize) {
    if count == 1 {
        writer.write(b"\r\n");
    } else if count > 1 {
        let mut left = count;
        while left != 0 {
            let take = left.min(CRLF_RUN_MAX);
            writer.write(&CRLF_RUN[..take * 2]);
            left -= take;
        }
    }
}

#[inline(always)]
fn find_line_break(haystack: &[u8]) -> Option<usize> {
    use memchr::memchr2;

    if haystack.len() >= MEMCHR_MIN_LEN {
        memchr2(b'\r', b'\n', haystack)
    } else {
        haystack.iter().position(|&ch| ch == b'\r' || ch == b'\n')
    }
}

#[inline(always)]
fn find_wsp_or_break(haystack: &[u8]) -> Option<usize> {
    let (words, tail) = haystack.as_chunks::<8>();

    for (index, word) in words.iter().enumerate() {
        let value = u64::from_le_bytes(*word);
        let found = value.wrapping_sub(SWAR_ONES * 0x21) & !value & SWAR_HIGH;
        if found != 0 {
            return Some(index * 8 + (found.trailing_zeros() / 8) as usize);
        }
    }

    tail.iter()
        .position(|&ch| ch <= b' ')
        .map(|pos| words.len() * 8 + pos)
}

fn simple_run_end(chunk: &[u8]) -> usize {
    let mut offset = 0;

    while let Some(pos) = find_line_break(&chunk[offset..]) {
        let start = offset + pos;
        match &chunk[start..] {
            [b'\r', b'\n', next, ..] if *next != b'\r' && *next != b'\n' => offset = start + 2,
            _ => return start,
        }
    }

    chunk.len()
}

fn relaxed_run_end(chunk: &[u8]) -> usize {
    let mut offset = 0;

    while let Some(pos) = find_wsp_or_break(&chunk[offset..]) {
        let start = offset + pos;
        match &chunk[start..] {
            [b' ', next, ..] if start != 0 && *next > b' ' => offset = start + 2,
            [b'\r', b'\n', next, ..] if start != 0 && *next > b' ' => offset = start + 2,
            [b'\t' | b'\n' | b'\r' | b' ', ..] => return start,
            _ => offset = start + 1,
        }
    }

    chunk.len()
}

struct CanonicalState {
    crlf_seq: usize,
    last_ch: u8,
    is_empty: bool,
}

impl CanonicalState {
    fn new() -> Self {
        CanonicalState {
            crlf_seq: 0,
            last_ch: 0,
            is_empty: true,
        }
    }

    fn write(
        &mut self,
        canonicalization: Canonicalization,
        chunk: &[u8],
        writer: &mut impl Writer,
    ) {
        match canonicalization {
            Canonicalization::Relaxed => self.write_relaxed(chunk, writer),
            Canonicalization::Simple => self.write_simple(chunk, writer),
        }
    }

    fn finish(&mut self, canonicalization: Canonicalization, writer: &mut impl Writer) {
        match canonicalization {
            Canonicalization::Relaxed => {
                if !self.is_empty {
                    writer.write(b"\r\n");
                }
            }
            Canonicalization::Simple => {
                writer.write(b"\r\n");
            }
        }
    }

    #[inline(always)]
    fn flush_breaks(&mut self, writer: &mut impl Writer) {
        if self.crlf_seq != 0 {
            write_crlf_run(writer, self.crlf_seq);
            self.crlf_seq = 0;
        }
    }

    fn write_simple(&mut self, chunk: &[u8], writer: &mut impl Writer) {
        let mut rest = chunk;

        while !rest.is_empty() {
            let (run, tail) = rest.split_at(simple_run_end(rest));

            if !run.is_empty() {
                self.flush_breaks(writer);
                writer.write(run);
                self.is_empty = false;
            }

            let mut consumed = 0;
            let mut breaks = self.crlf_seq;

            for &ch in tail {
                match ch {
                    b'\n' => breaks += 1,
                    b'\r' => {}
                    _ => break,
                }
                consumed += 1;
            }

            self.crlf_seq = breaks;
            rest = &tail[consumed..];
        }
    }

    fn write_relaxed(&mut self, chunk: &[u8], writer: &mut impl Writer) {
        let mut rest = chunk;

        while !rest.is_empty() {
            let (run, tail) = rest.split_at(relaxed_run_end(rest));

            if let Some(&last_ch) = run.last() {
                self.flush_breaks(writer);
                if self.last_ch == b' ' || self.last_ch == b'\t' {
                    writer.write(b" ");
                }
                writer.write(run);
                self.is_empty = false;
                self.last_ch = last_ch;
            }

            let mut consumed = 0;
            let mut last_ch = self.last_ch;
            let mut breaks = self.crlf_seq;
            let mut pending = 0;
            let mut has_wsp = false;

            for &ch in tail {
                match ch {
                    b'\n' => pending += 1,
                    b' ' | b'\t' => {
                        breaks += pending;
                        pending = 0;
                        has_wsp = true;
                    }
                    b'\r' => {}
                    _ => break,
                }
                consumed += 1;
                last_ch = ch;
            }

            if consumed != 0 {
                if has_wsp {
                    write_crlf_run(writer, breaks);
                    self.crlf_seq = pending;
                    self.is_empty = false;
                } else {
                    self.crlf_seq = breaks + pending;
                }
                self.last_ch = last_ch;
            }

            rest = &tail[consumed..];
        }
    }
}

pub struct CanonicalBody<'a> {
    canonicalization: Canonicalization,
    body: &'a [u8],
}

impl Writable for CanonicalBody<'_> {
    fn write(self, hasher: &mut impl Writer) {
        let mut state = CanonicalState::new();
        state.write(self.canonicalization, self.body, hasher);
        state.finish(self.canonicalization, hasher);
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
                    write_relaxed_name(name, hasher);
                    write_relaxed_value(value, hasher);
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
            body: if l == 0 {
                body
            } else {
                &body[..l.min(body.len() as u64) as usize]
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
        let mut found_headers = FoundHeaders::default();
        let mut signed_headers = Vec::with_capacity(self.h.len());

        while let Some((name, value)) = message.next_header() {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((name, value));
                found_headers.insert(pos);
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let body = message.body();
        let body_len = body.len();
        let canonical_headers = self.ch.canonical_headers(headers);
        let canonical_body = self.cb.canonical_body(body, u64::MAX);

        // Add any missing headers
        signed_headers.reverse();
        for (pos, header) in self.h.iter().enumerate() {
            if !found_headers.contains(pos) {
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

const LANE_ONES: u64 = 0x0101_0101_0101_0101;
const LANE_HIGH: u64 = 0x8080_8080_8080_8080;
const NAME_BUF_LEN: usize = 64;

#[inline(always)]
const fn zero_lanes(word: u64) -> u64 {
    word.wrapping_sub(LANE_ONES) & !word & LANE_HIGH
}

#[inline(always)]
const fn whitespace_lanes(word: u64) -> u64 {
    zero_lanes(word ^ (LANE_ONES * 0x09))
        | zero_lanes(word ^ (LANE_ONES * 0x0a))
        | zero_lanes(word ^ (LANE_ONES * 0x0c))
        | zero_lanes(word ^ (LANE_ONES * 0x0d))
        | zero_lanes(word ^ (LANE_ONES * 0x20))
}

#[inline(always)]
pub(crate) fn find_whitespace(bytes: &[u8]) -> Option<usize> {
    let (words, tail) = bytes.as_chunks::<8>();
    for (index, word) in words.iter().enumerate() {
        let lanes = whitespace_lanes(u64::from_le_bytes(*word));
        if lanes != 0 {
            return Some(index * 8 + (lanes.trailing_zeros() / 8) as usize);
        }
    }

    tail.iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| words.len() * 8 + offset)
}

pub(crate) struct SpacedToken<'a> {
    pub spaces: &'a [u8],
    pub token: &'a [u8],
    pub spaces_and_token: &'a [u8],
}

pub(crate) struct SpacedTokens<'a> {
    rest: &'a [u8],
}

impl<'a> SpacedTokens<'a> {
    #[inline(always)]
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
}

impl<'a> Iterator for SpacedTokens<'a> {
    type Item = SpacedToken<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.rest.iter().position(|ch| !ch.is_ascii_whitespace())?;
        let end = find_whitespace(&self.rest[start..]).map_or(self.rest.len(), |len| start + len);
        let (spaces_and_token, rest) = self.rest.split_at_checked(end)?;
        let (spaces, token) = spaces_and_token.split_at_checked(start)?;
        self.rest = rest;

        Some(SpacedToken {
            spaces,
            token,
            spaces_and_token,
        })
    }
}

#[inline(always)]
fn fill_lowercase(buf: &mut [u8; NAME_BUF_LEN], name: &[u8]) -> usize {
    let mut len = 0;
    for (slot, ch) in buf
        .iter_mut()
        .zip(name.iter().filter(|ch| !ch.is_ascii_whitespace()))
    {
        *slot = ch.to_ascii_lowercase();
        len += 1;
    }
    len
}

pub(crate) fn write_relaxed_name(name: &[u8], writer: &mut impl Writer) {
    let mut buf = [0u8; NAME_BUF_LEN];
    let mut rest = name;

    while rest.len() >= NAME_BUF_LEN {
        let (chunk, tail) = rest.split_at(NAME_BUF_LEN - 1);
        let len = fill_lowercase(&mut buf, chunk);
        writer.write(buf.get(..len).unwrap_or_default());
        rest = tail;
    }

    let len = fill_lowercase(&mut buf, rest);
    if let Some(slot) = buf.get_mut(len) {
        *slot = b':';
    }
    writer.write(buf.get(..len + 1).unwrap_or_default());
}

fn write_relaxed_value(value: &[u8], writer: &mut impl Writer) {
    let mut tokens = SpacedTokens::new(value);

    if let Some(first) = tokens.next() {
        writer.write(first.token);

        for token in tokens {
            if token.spaces == b" " {
                writer.write(token.spaces_and_token);
            } else {
                if matches!(token.spaces.last(), Some(b' ' | b'\t')) {
                    writer.write(b" ");
                }
                writer.write(token.token);
            }
        }
    }

    if value.last() == Some(&b'\n') {
        writer.write(b"\r\n");
    }
}

#[derive(Default)]
pub(crate) struct FoundHeaders {
    inline: u64,
    spilled: Vec<u64>,
}

impl FoundHeaders {
    pub(crate) fn insert(&mut self, position: usize) {
        match position.checked_sub(u64::BITS as usize) {
            None => self.inline |= 1 << position,
            Some(offset) => {
                let word = offset / u64::BITS as usize;
                if self.spilled.len() <= word {
                    self.spilled.resize(word + 1, 0);
                }
                if let Some(slot) = self.spilled.get_mut(word) {
                    *slot |= 1 << (offset % u64::BITS as usize);
                }
            }
        }
    }

    pub(crate) fn contains(&self, position: usize) -> bool {
        match position.checked_sub(u64::BITS as usize) {
            None => self.inline & (1 << position) != 0,
            Some(offset) => self
                .spilled
                .get(offset / u64::BITS as usize)
                .is_some_and(|word| word & (1 << (offset % u64::BITS as usize)) != 0),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{BodyHasher, CanonicalBody, CanonicalHeaders};
    use crate::{
        common::{
            crypto::{HashContext, HashImpl, Sha256},
            headers::{HeaderIterator, Writable},
        },
        dkim::Canonicalization,
    };
    use mail_builder::encoders::Base64Encoder;

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

                assert_eq!(
                    String::from_utf8(
                        Base64Encoder::new()
                            .encode(hasher.complete().as_ref())
                            .unwrap()
                    )
                    .unwrap(),
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
