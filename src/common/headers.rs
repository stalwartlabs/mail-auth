/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use memchr::{memchr, memchr2};

impl<'x, T> Header<'x, T> {
    pub fn new(name: &'x [u8], value: &'x [u8], header: T) -> Self {
        Header {
            name,
            value,
            header,
        }
    }
}

pub trait HeaderStream<'x> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])>;
    fn body(&mut self) -> &'x [u8];
}

pub(crate) const MAX_HEADER_LINE_LEN: usize = 76;
const MEMCHR_MIN_LEN: usize = 16;

pub struct HeaderFolder<'x, W: Writer> {
    writer: &'x mut W,
    bytes_left: usize,
}

impl<'x, W: Writer> HeaderFolder<'x, W> {
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

    fn write_chunked(&mut self, buf: &[u8], chunk_len: usize) {
        if !(3..MAX_HEADER_LINE_LEN).contains(&chunk_len) || find_semicolon(buf).is_some() {
            for chunk in buf.chunks(chunk_len.max(1)) {
                self.write(chunk);
            }
            return;
        }

        let mut rest = buf;
        while rest.len() >= chunk_len {
            let whole_chunks = self.bytes_left.saturating_sub(1) / chunk_len;
            if whole_chunks == 0 {
                self.writer.write(b"\r\n\t");
                self.bytes_left = MAX_HEADER_LINE_LEN;
                continue;
            }
            let take = (whole_chunks * chunk_len).min(rest.len() - rest.len() % chunk_len);
            let (head, tail) = rest.split_at(take);
            self.writer.write(head);
            self.bytes_left -= take;
            rest = tail;
        }

        if !rest.is_empty() {
            self.write(rest);
        }
    }
}

pub(crate) struct ChainedHeaderIterator<'x, T: Iterator<Item = &'x [u8]>> {
    parts: T,
    iter: HeaderIterator<'x>,
}

pub(crate) struct HeaderIterator<'x> {
    message: &'x [u8],
    pos: usize,
    start_pos: usize,
}

pub(crate) struct HeaderParser<'x> {
    message: &'x [u8],
    pos: usize,
    start_pos: usize,
    pub num_received: usize,
    pub has_message_id: bool,
    pub has_date: bool,
}

enum FieldScan {
    Named { colon: usize, end: usize },
    Unnamed { end: usize },
    End { pos: usize },
}

#[inline(always)]
fn scan_field(message: &[u8], start_pos: usize, from: usize) -> FieldScan {
    let mut cur = from;

    while let Some(rest) = message.get(cur..) {
        let Some(offset) = memchr2(b':', b'\n', rest) else {
            break;
        };
        let Some((head, tail)) = rest.split_at_checked(offset) else {
            break;
        };
        let pos = cur + offset;

        if tail.first() == Some(&b':') {
            return scan_value(message, pos);
        } else if head.last() == Some(&b'\r') || pos == start_pos {
            return FieldScan::End { pos: pos + 1 };
        }

        match message.get(pos + 1) {
            Some(b' ' | b'\t') => cur = pos + 1,
            _ => return FieldScan::Unnamed { end: pos + 1 },
        }
    }

    FieldScan::End { pos: message.len() }
}

#[inline(always)]
fn scan_value(message: &[u8], colon: usize) -> FieldScan {
    let mut cur = colon + 1;

    while let Some(rest) = message.get(cur..) {
        let Some(offset) = memchr(b'\n', rest) else {
            break;
        };
        let pos = cur + offset;

        match message.get(pos + 1) {
            Some(b' ' | b'\t') => cur = pos + 1,
            _ => {
                return FieldScan::Named {
                    colon,
                    end: pos + 1,
                };
            }
        }
    }

    FieldScan::End { pos: message.len() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatedHeader<'x> {
    Ds(&'x [u8]),
    D2s(&'x [u8]),
    D2i(&'x [u8]),
    #[cfg(feature = "arc")]
    Aar(&'x [u8]),
    #[cfg(feature = "arc")]
    Ams(&'x [u8]),
    #[cfg(feature = "arc")]
    As(&'x [u8]),
    From(&'x [u8]),
    Other(&'x [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'x, T> {
    pub name: &'x [u8],
    pub value: &'x [u8],
    pub header: T,
}

impl<'x> HeaderParser<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderParser {
            message,
            pos: 0,
            start_pos: 0,
            num_received: 0,
            has_message_id: false,
            has_date: false,
        }
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        (self.pos < self.message.len()).then_some(self.pos)
    }
}

impl<'x> HeaderIterator<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            pos: 0,
            start_pos: 0,
        }
    }

    pub fn seek_start(&mut self) {
        let rest = self.message.get(self.pos..).unwrap_or_default();
        self.pos += rest
            .iter()
            .position(|ch| !ch.is_ascii_whitespace())
            .unwrap_or(rest.len());
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        (self.pos < self.message.len()).then_some(self.pos)
    }
}

impl<'x> HeaderStream<'x> for HeaderIterator<'x> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])> {
        self.next()
    }

    fn body(&mut self) -> &'x [u8] {
        self.body_offset()
            .and_then(|offset| self.message.get(offset..))
            .unwrap_or_default()
    }
}

impl<'x> Iterator for HeaderIterator<'x> {
    type Item = (&'x [u8], &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match scan_field(self.message, self.start_pos, self.pos) {
            FieldScan::Named { colon, end } => {
                let header_name = self.message.get(self.start_pos..colon).unwrap_or_default();
                let header_value = self.message.get(colon + 1..end).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                Some((header_name, header_value))
            }
            FieldScan::Unnamed { end } => {
                let header_name = self.message.get(self.start_pos..end).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                Some((header_name, b""))
            }
            FieldScan::End { pos } => {
                self.pos = pos;

                None
            }
        }
    }
}

impl<'x, T: Iterator<Item = &'x [u8]>> ChainedHeaderIterator<'x, T> {
    pub fn new(mut parts: T) -> Self {
        ChainedHeaderIterator {
            iter: HeaderIterator::new(parts.next().unwrap_or_default()),
            parts,
        }
    }
}

impl<'x, T: Iterator<Item = &'x [u8]>> HeaderStream<'x> for ChainedHeaderIterator<'x, T> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])> {
        if let Some(header) = self.iter.next_header() {
            Some(header)
        } else {
            self.iter = HeaderIterator::new(self.parts.next()?);
            self.iter.next_header()
        }
    }

    fn body(&mut self) -> &'x [u8] {
        self.iter.body()
    }
}

impl<'x> Iterator for HeaderParser<'x> {
    type Item = (AuthenticatedHeader<'x>, &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let scan_start = self.pos;

        match scan_field(self.message, self.start_pos, scan_start) {
            FieldScan::Named { colon, end } => {
                let header_name = self.message.get(self.start_pos..colon).unwrap_or_default();
                let header_value = self.message.get(colon + 1..end).unwrap_or_default();
                let token = self.message.get(scan_start..colon).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                let header_name = match classify_name(token) {
                    HeaderClass::Received => {
                        self.num_received += 1;
                        AuthenticatedHeader::Other(header_name)
                    }
                    HeaderClass::MessageId => {
                        self.has_message_id = true;
                        AuthenticatedHeader::Other(header_name)
                    }
                    HeaderClass::Date => {
                        self.has_date = true;
                        AuthenticatedHeader::Other(header_name)
                    }
                    HeaderClass::From => AuthenticatedHeader::From(header_name),
                    HeaderClass::Ds => AuthenticatedHeader::Ds(header_name),
                    HeaderClass::D2s => AuthenticatedHeader::D2s(header_name),
                    HeaderClass::D2i => AuthenticatedHeader::D2i(header_name),
                    #[cfg(feature = "arc")]
                    HeaderClass::Aar => AuthenticatedHeader::Aar(header_name),
                    #[cfg(feature = "arc")]
                    HeaderClass::Ams => AuthenticatedHeader::Ams(header_name),
                    #[cfg(feature = "arc")]
                    HeaderClass::As => AuthenticatedHeader::As(header_name),
                    #[cfg(not(feature = "arc"))]
                    HeaderClass::Aar | HeaderClass::Ams | HeaderClass::As => {
                        AuthenticatedHeader::Other(header_name)
                    }
                    HeaderClass::Other => AuthenticatedHeader::Other(header_name),
                };

                Some((header_name, header_value))
            }
            FieldScan::Unnamed { end } => {
                let header_name = self.message.get(self.start_pos..end).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                Some((AuthenticatedHeader::Other(header_name), b""))
            }
            FieldScan::End { pos } => {
                self.pos = pos;

                None
            }
        }
    }
}

enum HeaderClass {
    Received,
    From,
    Date,
    MessageId,
    Ds,
    D2s,
    D2i,
    Aar,
    Ams,
    As,
    Other,
}

#[inline(always)]
fn is_field_token(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'-'
}

#[inline(always)]
fn classify_name(name: &[u8]) -> HeaderClass {
    if name.iter().fold(true, |acc, &ch| acc & is_field_token(ch)) {
        match name.len() {
            4 if name.eq_ignore_ascii_case(b"from") => HeaderClass::From,
            4 if name.eq_ignore_ascii_case(b"date") => HeaderClass::Date,
            8 if name.eq_ignore_ascii_case(b"received") => HeaderClass::Received,
            10 if name.eq_ignore_ascii_case(b"message-id") => HeaderClass::MessageId,
            14 if name.eq_ignore_ascii_case(b"dkim-signature") => HeaderClass::Ds,
            15 if name.eq_ignore_ascii_case(b"dkim2-signature") => HeaderClass::D2s,
            16 if name.eq_ignore_ascii_case(b"message-instance") => HeaderClass::D2i,
            21 if name.eq_ignore_ascii_case(b"arc-message-signature") => HeaderClass::Ams,
            26 if name.eq_ignore_ascii_case(b"arc-authentication-results") => HeaderClass::Aar,
            _ if name
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"arc-seal")) =>
            {
                HeaderClass::As
            }
            _ => HeaderClass::Other,
        }
    } else {
        classify_folded_name(name)
    }
}

#[inline(never)]
fn classify_folded_name(name: &[u8]) -> HeaderClass {
    let mut token_start = usize::MAX;
    let mut token_end = usize::MAX;

    let mut hash: u64 = 0;
    let mut hash_shift = 0;

    for (pos, &ch) in name.iter().enumerate() {
        let token = match ch {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'A'..=b'Z' => ch - b'A' + b'a',
            b'a'..=b'z' | b'-' | b'0'..=b'9' => ch,
            _ => {
                hash = u64::MAX;
                continue;
            }
        };

        if hash_shift < 64 {
            hash |= (token as u64) << hash_shift;
            hash_shift += 8;

            if token_start == usize::MAX {
                token_start = pos;
            }
        }
        token_end = pos;
    }

    let tail = name
        .get(token_start.wrapping_add(8)..token_end.wrapping_add(1))
        .unwrap_or_default();

    match hash {
        RECEIVED if token_start.wrapping_add(7) == token_end => HeaderClass::Received,
        FROM => HeaderClass::From,
        AS => HeaderClass::As,
        AAR if tail.eq_ignore_ascii_case(b"entication-Results") => HeaderClass::Aar,
        AMS if tail.eq_ignore_ascii_case(b"age-Signature") => HeaderClass::Ams,
        DKIM if tail.eq_ignore_ascii_case(b"nature") => HeaderClass::Ds,
        DKIM2 if tail.eq_ignore_ascii_case(b"gnature") => HeaderClass::D2s,
        MSGID if tail.eq_ignore_ascii_case(b"id") => HeaderClass::MessageId,
        MSGID if tail.eq_ignore_ascii_case(b"instance") => HeaderClass::D2i,
        DATE => HeaderClass::Date,
        _ => HeaderClass::Other,
    }
}

pub(crate) const HEADER_CAPACITY: usize = 512;

pub trait HeaderWriter: Sized {
    fn write_header(&self, writer: &mut impl Writer);
    fn to_header(&self) -> String {
        let mut buf = Vec::with_capacity(HEADER_CAPACITY);
        self.write_header(&mut buf);
        String::from_utf8(buf)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

pub trait Writable {
    fn write(self, writer: &mut impl Writer);
}

impl Writable for &[u8] {
    fn write(self, writer: &mut impl Writer) {
        writer.write(self);
    }
}

pub trait Writer {
    fn write(&mut self, buf: &[u8]);

    fn write_len(&mut self, buf: &[u8], len: &mut usize) {
        self.write(buf);
        *len += buf.len();
    }

    /// Writes `buf` as if it had been split into `chunk_len` sized pieces, each
    /// passed to [`Writer::write`] in turn. Writers whose output only depends on
    /// the concatenation of what they receive take the default implementation.
    fn write_chunked(&mut self, buf: &[u8], _chunk_len: usize) {
        self.write(buf);
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

pub(crate) fn write_wrapped(
    writer: &mut impl Writer,
    value: &[u8],
    bytes_written: &mut usize,
    new_line: &[u8],
) {
    let mut rest = value;
    while !rest.is_empty() {
        let take = MAX_HEADER_LINE_LEN
            .saturating_sub(*bytes_written)
            .max(1)
            .min(rest.len());
        let (head, tail) = rest.split_at(take);
        writer.write_len(head, bytes_written);
        if *bytes_written >= MAX_HEADER_LINE_LEN {
            writer.write(new_line);
            *bytes_written = 1;
        }
        rest = tail;
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) const BASE64_GROUP_LEN: usize = 4;
const BASE64_INPUT_LEN: usize = 192;
const BASE64_OUTPUT_LEN: usize = BASE64_INPUT_LEN / 3 * BASE64_GROUP_LEN;

#[inline(always)]
fn base64_group(word: u32, len: usize) -> [u8; BASE64_GROUP_LEN] {
    let pad = |shift: u32, keep: usize| {
        if len > keep {
            BASE64_ALPHABET[(word >> shift) as usize & 0x3f]
        } else {
            b'='
        }
    };
    [
        BASE64_ALPHABET[(word >> 18) as usize & 0x3f],
        BASE64_ALPHABET[(word >> 12) as usize & 0x3f],
        pad(6, 1),
        pad(0, 2),
    ]
}

pub(crate) fn base64_encode_slice(bytes: &[u8], out: &mut [u8]) -> usize {
    let (groups, tail) = bytes.as_chunks::<3>();
    let mut written = 0;

    let (slots, _) = out.as_chunks_mut::<BASE64_GROUP_LEN>();
    for (group, slot) in groups.iter().zip(slots.iter_mut()) {
        let [b0, b1, b2] = *group;
        let word = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        slot.copy_from_slice(&base64_group(word, 3));
        written += BASE64_GROUP_LEN;
    }

    if !tail.is_empty() {
        let word = tail.iter().enumerate().fold(0u32, |word, (pos, byte)| {
            word | (*byte as u32) << (16 - pos * 8)
        });
        if let Some(slot) = out.get_mut(written..written + BASE64_GROUP_LEN) {
            slot.copy_from_slice(&base64_group(word, tail.len()));
            written += BASE64_GROUP_LEN;
        }
    }

    written
}

pub(crate) fn write_base64(writer: &mut impl Writer, bytes: &[u8]) {
    let mut buffer = [0u8; BASE64_OUTPUT_LEN];
    for window in bytes.chunks(BASE64_INPUT_LEN) {
        let written = base64_encode_slice(window, &mut buffer);
        writer.write_chunked(buffer.get(..written).unwrap_or_default(), BASE64_GROUP_LEN);
    }
}

pub(crate) fn write_wrapped_base64(
    writer: &mut impl Writer,
    bytes: &[u8],
    bytes_written: &mut usize,
    new_line: &[u8],
) {
    let mut buffer = [0u8; BASE64_OUTPUT_LEN];
    for window in bytes.chunks(BASE64_INPUT_LEN) {
        let written = base64_encode_slice(window, &mut buffer);
        write_wrapped(
            writer,
            buffer.get(..written).unwrap_or_default(),
            bytes_written,
            new_line,
        );
    }
}

const FROM: u64 =
    (b'f' as u64) | ((b'r' as u64) << 8) | ((b'o' as u64) << 16) | ((b'm' as u64) << 24);
const DKIM: u64 = (b'd' as u64)
    | ((b'k' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'm' as u64) << 24)
    | ((b'-' as u64) << 32)
    | ((b's' as u64) << 40)
    | ((b'i' as u64) << 48)
    | ((b'g' as u64) << 56);
const DKIM2: u64 = (b'd' as u64)
    | ((b'k' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'm' as u64) << 24)
    | ((b'2' as u64) << 32)
    | ((b'-' as u64) << 40)
    | ((b's' as u64) << 48)
    | ((b'i' as u64) << 56);
const AAR: u64 = (b'a' as u64)
    | ((b'r' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'-' as u64) << 24)
    | ((b'a' as u64) << 32)
    | ((b'u' as u64) << 40)
    | ((b't' as u64) << 48)
    | ((b'h' as u64) << 56);
const AMS: u64 = (b'a' as u64)
    | ((b'r' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'-' as u64) << 24)
    | ((b'm' as u64) << 32)
    | ((b'e' as u64) << 40)
    | ((b's' as u64) << 48)
    | ((b's' as u64) << 56);
const AS: u64 = (b'a' as u64)
    | ((b'r' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'-' as u64) << 24)
    | ((b's' as u64) << 32)
    | ((b'e' as u64) << 40)
    | ((b'a' as u64) << 48)
    | ((b'l' as u64) << 56);
const RECEIVED: u64 = (b'r' as u64)
    | ((b'e' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'e' as u64) << 24)
    | ((b'i' as u64) << 32)
    | ((b'v' as u64) << 40)
    | ((b'e' as u64) << 48)
    | ((b'd' as u64) << 56);
const DATE: u64 =
    (b'd' as u64) | ((b'a' as u64) << 8) | ((b't' as u64) << 16) | ((b'e' as u64) << 24);
const MSGID: u64 = (b'm' as u64)
    | ((b'e' as u64) << 8)
    | ((b's' as u64) << 16)
    | ((b's' as u64) << 24)
    | ((b'a' as u64) << 32)
    | ((b'g' as u64) << 40)
    | ((b'e' as u64) << 48)
    | ((b'-' as u64) << 56);

#[cfg(test)]
mod test {
    use super::{ChainedHeaderIterator, HeaderIterator, HeaderStream};
    use super::{HeaderFolder, MAX_HEADER_LINE_LEN};
    use crate::common::headers::{AuthenticatedHeader, HeaderParser, Writer};

    #[test]
    fn header_iterator() {
        for (message, headers) in [
            (
                "From: a\nTo: b\nEmpty:\nMulti: 1\n 2\nSubject: c\n\nNot-header: ignore\n",
                vec![
                    ("From", " a\n"),
                    ("To", " b\n"),
                    ("Empty", "\n"),
                    ("Multi", " 1\n 2\n"),
                    ("Subject", " c\n"),
                ],
            ),
            (
                ": a\nTo: b\n \n \nc\n:\nFrom : d\nSubject: e\n\nNot-header: ignore\n",
                vec![
                    ("", " a\n"),
                    ("To", " b\n \n \n"),
                    ("c\n", ""),
                    ("", "\n"),
                    ("From ", " d\n"),
                    ("Subject", " e\n"),
                ],
            ),
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                ),
                vec![("A", " X\r\n"), ("B ", " Y\t\r\n\tZ  \r\n")],
            ),
        ] {
            assert_eq!(
                HeaderIterator::new(message.as_bytes())
                    .map(|(h, v)| {
                        (
                            std::str::from_utf8(h).unwrap(),
                            std::str::from_utf8(v).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
                headers
            );

            assert_eq!(
                HeaderParser::new(message.as_bytes())
                    .map(|(h, v)| {
                        (
                            std::str::from_utf8(match h {
                                #[cfg(feature = "arc")]
                                AuthenticatedHeader::Aar(v)
                                | AuthenticatedHeader::Ams(v)
                                | AuthenticatedHeader::As(v) => v,
                                AuthenticatedHeader::Ds(v)
                                | AuthenticatedHeader::D2s(v)
                                | AuthenticatedHeader::D2i(v)
                                | AuthenticatedHeader::From(v)
                                | AuthenticatedHeader::Other(v) => v,
                            })
                            .unwrap(),
                            std::str::from_utf8(v).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
                headers
            );
        }
    }

    #[cfg(feature = "arc")]
    #[test]
    fn header_parser() {
        let message = concat!(
            "ARC-Message-Signature: i=1; a=rsa-sha256;\n",
            "ARC-Authentication-Results: i=1;\n",
            "ARC-Seal: i=1; a=rsa-sha256;\n",
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple;\n",
            "From: jdoe@domain\n",
            "F r o m : jane@domain.com\n",
            "ARC-Authentication: i=1;\n",
            "Received: r1\n",
            "Received: r2\n",
            "Received: r3\n",
            "Received-From: test\n",
            "Date: date\n",
            "Message-Id: myid\n",
            "\nhey",
        );
        let mut parser = HeaderParser::new(message.as_bytes());
        assert_eq!(
            (&mut parser).map(|(h, _)| { h }).collect::<Vec<_>>(),
            vec![
                AuthenticatedHeader::Ams(b"ARC-Message-Signature"),
                AuthenticatedHeader::Aar(b"ARC-Authentication-Results"),
                AuthenticatedHeader::As(b"ARC-Seal"),
                AuthenticatedHeader::Ds(b"DKIM-Signature"),
                AuthenticatedHeader::From(b"From"),
                AuthenticatedHeader::From(b"F r o m "),
                AuthenticatedHeader::Other(b"ARC-Authentication"),
                AuthenticatedHeader::Other(b"Received"),
                AuthenticatedHeader::Other(b"Received"),
                AuthenticatedHeader::Other(b"Received"),
                AuthenticatedHeader::Other(b"Received-From"),
                AuthenticatedHeader::Other(b"Date"),
                AuthenticatedHeader::Other(b"Message-Id"),
            ]
        );
        assert!(parser.has_date);
        assert!(parser.has_message_id);
        assert_eq!(parser.num_received, 3);
    }

    #[test]
    fn chained_header_iterator() {
        let parts = [
            &b"From: a\nTo: b\nEmpty:\nMulti: 1\n 2\n"[..],
            &b"Subject: c\nReceived: d\n\nhey"[..],
        ];
        let mut headers = vec![
            ("From", " a\n"),
            ("To", " b\n"),
            ("Empty", "\n"),
            ("Multi", " 1\n 2\n"),
            ("Subject", " c\n"),
            ("Received", " d\n"),
        ]
        .into_iter();
        let mut it = ChainedHeaderIterator::new(parts.iter().copied());

        while let Some((k, v)) = it.next_header() {
            assert_eq!(
                (
                    std::str::from_utf8(k).unwrap(),
                    std::str::from_utf8(v).unwrap()
                ),
                headers.next().unwrap()
            );
        }
        assert_eq!(it.body(), b"hey");
    }

    fn fold(header: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(header.len() + 16);
        let mut folder = HeaderFolder::new(&mut buf);
        folder.write(header);
        buf
    }

    fn unfold(folded: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(folded.len());
        let mut i = 0;
        while i < folded.len() {
            if folded[i..].starts_with(b"\r\n\t") {
                i += 3;
            } else {
                out.push(folded[i]);
                i += 1;
            }
        }
        out
    }

    fn assert_folded(original: &[u8]) -> Vec<u8> {
        let folded = fold(original);

        assert_eq!(
            unfold(&folded),
            original,
            "folding must only insert CRLF+TAB fold points, never alter bytes: {:?}",
            String::from_utf8_lossy(original)
        );

        for (n, line) in folded.split(|&c| c == b'\n').enumerate() {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let content = line.strip_prefix(b"\t").unwrap_or(line);
            assert!(
                content.len() <= MAX_HEADER_LINE_LEN,
                "line {n} of {content_len} bytes exceeds {MAX_HEADER_LINE_LEN}: {:?}",
                String::from_utf8_lossy(content),
                content_len = content.len(),
            );
        }

        for (i, &ch) in folded.iter().enumerate() {
            if ch == b'\n' {
                assert!(
                    i >= 1 && folded[i - 1] == b'\r' && folded.get(i + 1) == Some(&b'\t'),
                    "every LF must be part of a CRLF+TAB fold at offset {i}: {:?}",
                    String::from_utf8_lossy(&folded)
                );
            }
        }

        assert!(
            !folded.starts_with(b"\r\n\t"),
            "output must never begin with a fold"
        );

        folded
    }

    fn extract_header<'a>(eml: &'a str, name: &str) -> &'a [u8] {
        eml.lines()
            .find(|l| {
                l.len() > name.len()
                    && l.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes())
                    && l.as_bytes()[name.len()] == b':'
            })
            .unwrap_or_else(|| panic!("header {name} not found"))
            .as_bytes()
    }

    #[test]
    fn header_folder_passthrough() {
        for input in [
            &b""[..],
            &b";"[..],
            &b"a;;b;;;c"[..],
            &b"Subject: hello world"[..],
            &b"Dkim2-Signature: i=1; m=1; d=test.dkim2.eu"[..],
        ] {
            assert_eq!(
                fold(input),
                input,
                "should pass through unchanged: {:?}",
                String::from_utf8_lossy(input)
            );
        }

        let just_under = vec![b'a'; MAX_HEADER_LINE_LEN - 1];
        assert_eq!(fold(&just_under), just_under);
    }

    #[test]
    fn header_folder_boundaries() {
        let exactly_max = vec![b'a'; MAX_HEADER_LINE_LEN];
        let folded = assert_folded(&exactly_max);
        assert_eq!(folded, exactly_max, "76 bytes fit on one line, no fold");

        let over_max = vec![b'a'; MAX_HEADER_LINE_LEN + 1];
        let folded = assert_folded(&over_max);
        let mut expected = vec![b'a'; MAX_HEADER_LINE_LEN];
        expected.extend_from_slice(b"\r\n\t");
        expected.push(b'a');
        assert_eq!(folded, expected, "77 bytes wrap into 76 + fold + 1");

        let two_pieces = vec![b'a'; MAX_HEADER_LINE_LEN * 2];
        let folded = assert_folded(&two_pieces);
        assert_eq!(
            folded.iter().filter(|&&c| c == b'\n').count(),
            1,
            "an exact multiple of the limit yields exactly one fold"
        );
    }

    #[test]
    fn header_folder_large_chunk_followed_by_tags() {
        let big = vec![b'A'; MAX_HEADER_LINE_LEN * 2 - 3];
        let mut input = b"v=".to_vec();
        input.extend_from_slice(&big);
        input.extend_from_slice(b";a=1;b=2;c=3;d=4;e=5");
        assert_folded(&input);

        let big = vec![b'A'; MAX_HEADER_LINE_LEN + 20];
        let mut input = b"s=".to_vec();
        input.extend_from_slice(&big);
        input.extend_from_slice(b";f=feedback");
        assert_folded(&input);
    }

    #[test]
    fn header_folder_consecutive_large_chunks() {
        let mf = vec![b'A'; 100];
        let rt = vec![b'B'; 90];
        let mut input = b"Dkim2-Signature:mf=".to_vec();
        input.extend_from_slice(&mf);
        input.extend_from_slice(b";rt=");
        input.extend_from_slice(&rt);
        input.extend_from_slice(b";f=feedback");
        assert_folded(&input);
    }

    #[test]
    fn header_folder_many_small_tags() {
        let mut input = b"Dkim2-Signature:".to_vec();
        for i in 0..40 {
            input.extend_from_slice(format!(" tag{i}=value{i};").as_bytes());
        }
        assert_folded(&input);
    }

    #[test]
    fn header_folder_large_leading_chunk_over_partial_line() {
        let mut input = b"Message-Instance: m=1; h=sha256:".to_vec();
        input.extend_from_slice(&[b'Z'; 120]);
        assert_folded(&input);
    }

    #[test]
    fn header_folder_real_dkim2_headers() {
        const FILES: [&str; 2] = [
            include_str!("../../resources/dkim2/expected/d2_duplicate_rt_tag.eml"),
            include_str!("../../resources/dkim2/expected/pkix_rsa8192.eml"),
        ];

        for eml in FILES {
            for name in ["Message-Instance", "Dkim2-Signature"] {
                let header = extract_header(eml, name);
                assert!(
                    header.len() > MAX_HEADER_LINE_LEN,
                    "{name} should exceed the fold limit to exercise folding"
                );
                let folded = assert_folded(header);
                assert!(
                    folded.windows(3).any(|w| w == b"\r\n\t"),
                    "long real header {name} should have been folded"
                );
            }
        }
    }
}
