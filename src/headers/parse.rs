/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::HeaderStream;
use memchr::{memchr, memchr2};

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

    #[cfg(feature = "report")]
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
