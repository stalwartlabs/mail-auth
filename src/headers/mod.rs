/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Header field types and output traits shared by every protocol module.
//!
//! - [`Header`] pairs a parsed authentication header with its raw name and
//!   value (RFC 5322 Section 2.2).
//! - [`HeaderWriter`] is implemented by every header this crate generates
//!   (`DKIM-Signature`, `ARC-Seal` and friends, `DKIM2-Signature`,
//!   `Message-Instance`, `Authentication-Results`, `Received-SPF`).
//! - [`Writer`] and [`Writable`] are the byte sink and source used for
//!   header output, canonicalization and hashing.
//! - [`HeaderFolder`] folds long header lines (RFC 5322 Section 2.2.3).

use encodify::{Fold, base64};

mod parse;

pub(crate) use parse::{AuthenticatedHeader, ChainedHeaderIterator, HeaderIterator, HeaderParser};

impl<'x, T> Header<'x, T> {
    /// Creates a header from its raw name, raw value and parsed form.
    pub fn new(name: &'x [u8], value: &'x [u8], header: T) -> Self {
        Header {
            name,
            value,
            header,
        }
    }
}

pub(crate) trait HeaderStream<'x> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])>;
    fn body(&mut self) -> &'x [u8];
}

pub(crate) const MAX_HEADER_LINE_LEN: usize = 76;
const MEMCHR_MIN_LEN: usize = 16;
const BASE64_GROUP_LEN: usize = 4;
const BASE64_FOLD: Fold<'static> =
    Fold::new(MAX_HEADER_LINE_LEN - 1, b"\r\n\t", 0).with_granularity(BASE64_GROUP_LEN);

/// A [`Writer`] adapter that folds header lines (RFC 5322 Section 2.2.3).
///
/// Written data is split after each `;`, and a fold (`CRLF` followed by a
/// tab) is inserted before a piece that would push the line past 76
/// characters. Base64 data written with [`Writer::write_base64`] is folded
/// on four-character boundaries. Pieces longer than a line are split.
pub struct HeaderFolder<'x, W: Writer> {
    writer: &'x mut W,
    bytes_left: usize,
}

impl<'x, W: Writer> HeaderFolder<'x, W> {
    /// Wraps `writer`, starting at the beginning of a line.
    pub fn new(writer: &'x mut W) -> Self {
        HeaderFolder {
            writer,
            bytes_left: MAX_HEADER_LINE_LEN,
        }
    }

    #[inline(always)]
    fn write_chunk(&mut self, chunk: &[u8]) {
        if chunk == b"\r\n" {
            self.writer.write(chunk);
            self.bytes_left = MAX_HEADER_LINE_LEN;
        } else if chunk.len() < self.bytes_left {
            self.writer.write(chunk);
            self.bytes_left -= chunk.len();
        } else if chunk.len() >= MAX_HEADER_LINE_LEN {
            let mut add_new_line = self.bytes_left != MAX_HEADER_LINE_LEN;
            let mut last_piece_len = MAX_HEADER_LINE_LEN;
            for chunk in chunk.chunks(MAX_HEADER_LINE_LEN) {
                if add_new_line {
                    self.writer.write(b"\r\n\t");
                }
                add_new_line = true;
                self.writer.write(chunk);
                last_piece_len = chunk.len();
            }
            self.bytes_left = MAX_HEADER_LINE_LEN - last_piece_len;
        } else {
            self.writer.write(b"\r\n\t");
            self.writer.write(chunk);
            self.bytes_left = MAX_HEADER_LINE_LEN - chunk.len();
        }
    }
}

#[inline(always)]
fn find_semicolon(buf: &[u8]) -> Option<usize> {
    if buf.len() >= MEMCHR_MIN_LEN {
        memchr::memchr(b';', buf)
    } else {
        buf.iter().position(|ch| *ch == b';')
    }
}

impl<'x, W: Writer> Writer for HeaderFolder<'x, W> {
    fn write(&mut self, buf: &[u8]) {
        let mut rest = buf;
        while !rest.is_empty() {
            let (chunk, tail) = match find_semicolon(rest) {
                Some(pos) => rest.split_at(pos + 1),
                None => (rest, Default::default()),
            };
            self.write_chunk(chunk);
            rest = tail;
        }
    }

    fn write_base64(&mut self, bytes: &[u8]) {
        let mut column = MAX_HEADER_LINE_LEN.saturating_sub(self.bytes_left);
        base64::STANDARD.encode_folded(bytes, &mut column, BASE64_FOLD, |piece| {
            self.writer.write(piece)
        });
        self.bytes_left = MAX_HEADER_LINE_LEN.saturating_sub(column);
    }
}

/// An authentication header found in a message, as returned by
/// [`AuthenticatedMessage`](crate::AuthenticatedMessage) accessors such as
/// `dkim_signatures()` and `errors()`.
///
/// `T` is the parsed form (for example a DKIM
/// [`Signature`](crate::dkim::Signature)) or, for headers that failed to
/// parse, the [`Error`](crate::Error) explaining why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'x, T> {
    /// The raw field name, without the colon.
    pub name: &'x [u8],
    /// The raw field value, after the colon, including folding and the
    /// trailing line ending.
    pub value: &'x [u8],
    /// The parsed header, or the parse error.
    pub header: T,
}

pub(crate) const HEADER_CAPACITY: usize = 512;

/// A header that can be written to a message.
pub trait HeaderWriter: Sized {
    /// Writes the complete header field, including the field name and the
    /// trailing CRLF, to `writer`.
    fn write_header(&self, writer: &mut impl Writer);
    /// Returns the complete header field as a string, including the field name
    /// and the trailing CRLF. Invalid UTF-8 is replaced with U+FFFD.
    fn to_header(&self) -> String {
        let mut buf = Vec::with_capacity(HEADER_CAPACITY);
        self.write_header(&mut buf);
        String::from_utf8(buf)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

/// A source of bytes that can be streamed into a [`Writer`].
///
/// Used as the input of signing and hashing so that data can be produced
/// without first collecting it into a buffer.
pub trait Writable {
    /// Writes all bytes to `writer`.
    fn write(self, writer: &mut impl Writer);
}

impl Writable for &[u8] {
    fn write(self, writer: &mut impl Writer) {
        writer.write(self);
    }
}

/// A byte sink: a buffer, a hash context or a [`HeaderFolder`].
pub trait Writer {
    /// Appends `buf`.
    fn write(&mut self, buf: &[u8]);

    /// Appends `buf` and adds its length to `len`.
    fn write_len(&mut self, buf: &[u8], len: &mut usize) {
        self.write(buf);
        *len += buf.len();
    }

    /// Appends `bytes` encoded as standard Base64 with padding (RFC 4648
    /// Section 4).
    fn write_base64(&mut self, bytes: &[u8]) {
        base64::STANDARD.encode_chunks(bytes, |chunk| self.write(chunk));
    }
}

impl Writer for Vec<u8> {
    fn write(&mut self, buf: &[u8]) {
        self.extend(buf);
    }
}

impl Writer for &mut Vec<u8> {
    fn write(&mut self, buf: &[u8]) {
        self.extend(buf);
    }
}

const MAX_U64_DIGITS: usize = 20;

pub(crate) struct IntegerBuffer([u8; MAX_U64_DIGITS]);

impl IntegerBuffer {
    pub(crate) const fn new() -> Self {
        IntegerBuffer([0; MAX_U64_DIGITS])
    }

    pub(crate) fn digits(&mut self, value: u64) -> &[u8] {
        let mut value = value;
        let mut pos = MAX_U64_DIGITS;
        loop {
            pos -= 1;
            if let Some(digit) = self.0.get_mut(pos) {
                *digit = b'0' + (value % 10) as u8;
            }
            value /= 10;
            if value == 0 || pos == 0 {
                break;
            }
        }
        self.0.get(pos..).unwrap_or_default()
    }

    pub(crate) fn text(&mut self, value: u64) -> &str {
        std::str::from_utf8(self.digits(value)).unwrap_or_default()
    }
}

pub(crate) fn write_integer(writer: &mut impl Writer, value: u64) {
    let mut buffer = IntegerBuffer::new();
    writer.write(buffer.digits(value));
}

#[cfg(test)]
mod tests;
