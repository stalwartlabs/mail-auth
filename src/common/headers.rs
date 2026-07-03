/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    iter::{Enumerate, Peekable},
    slice::Iter,
};

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

const MAX_HEADER_LINE_LEN: usize = 76;

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
}

impl<'x, W: Writer> Writer for HeaderFolder<'x, W> {
    fn write(&mut self, buf: &[u8]) {
        for chunk in buf.split_inclusive(|ch| *ch == b';') {
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
}

pub(crate) struct ChainedHeaderIterator<'x, T: Iterator<Item = &'x [u8]>> {
    parts: T,
    iter: HeaderIterator<'x>,
}

pub(crate) struct HeaderIterator<'x> {
    message: &'x [u8],
    iter: Peekable<Enumerate<Iter<'x, u8>>>,
    start_pos: usize,
}

pub(crate) struct HeaderParser<'x> {
    message: &'x [u8],
    iter: Peekable<Enumerate<Iter<'x, u8>>>,
    start_pos: usize,
    pub num_received: usize,
    pub has_message_id: bool,
    pub has_date: bool,
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
            iter: message.iter().enumerate().peekable(),
            start_pos: 0,
            num_received: 0,
            has_message_id: false,
            has_date: false,
        }
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        self.iter.peek().map(|(pos, _)| *pos)
    }
}

impl<'x> HeaderIterator<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            iter: message.iter().enumerate().peekable(),
            start_pos: 0,
        }
    }

    pub fn seek_start(&mut self) {
        while let Some((_, ch)) = self.iter.peek() {
            if !ch.is_ascii_whitespace() {
                break;
            } else {
                self.iter.next();
            }
        }
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        self.iter.peek().map(|(pos, _)| *pos)
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
        let mut colon_pos = usize::MAX;
        let mut last_ch = 0;

        while let Some((pos, &ch)) = self.iter.next() {
            if colon_pos == usize::MAX {
                match ch {
                    b':' => {
                        colon_pos = pos;
                    }
                    b'\n' => {
                        if last_ch == b'\r' || self.start_pos == pos {
                            // End of headers
                            return None;
                        } else if self
                            .iter
                            .peek()
                            .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                        {
                            // Invalid header, return anyway.
                            let header_name = self
                                .message
                                .get(self.start_pos..pos + 1)
                                .unwrap_or_default();
                            self.start_pos = pos + 1;
                            return Some((header_name, b""));
                        }
                    }
                    _ => (),
                }
            } else if ch == b'\n'
                && self
                    .iter
                    .peek()
                    .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
            {
                let header_name = self
                    .message
                    .get(self.start_pos..colon_pos)
                    .unwrap_or_default();
                let header_value = self.message.get(colon_pos + 1..pos + 1).unwrap_or_default();

                self.start_pos = pos + 1;

                return Some((header_name, header_value));
            }

            last_ch = ch;
        }

        None
    }
}

impl<'x, T: Iterator<Item = &'x [u8]>> ChainedHeaderIterator<'x, T> {
    pub fn new(mut parts: T) -> Self {
        ChainedHeaderIterator {
            iter: HeaderIterator::new(parts.next().unwrap()),
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
        let mut colon_pos = usize::MAX;
        let mut last_ch = 0;

        let mut token_start = usize::MAX;
        let mut token_end = usize::MAX;

        let mut hash: u64 = 0;
        let mut hash_shift = 0;

        while let Some((pos, &ch)) = self.iter.next() {
            if colon_pos == usize::MAX {
                match ch {
                    b':' => {
                        colon_pos = pos;
                    }
                    b'\n' => {
                        if last_ch == b'\r' || self.start_pos == pos {
                            // End of headers
                            return None;
                        } else if self
                            .iter
                            .peek()
                            .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                        {
                            // Invalid header, return anyway.
                            let header_name = self
                                .message
                                .get(self.start_pos..pos + 1)
                                .unwrap_or_default();
                            self.start_pos = pos + 1;
                            return Some((AuthenticatedHeader::Other(header_name), b""));
                        }
                    }
                    b' ' | b'\t' | b'\r' => (),
                    b'A'..=b'Z' => {
                        if hash_shift < 64 {
                            hash |= ((ch - b'A' + b'a') as u64) << hash_shift;
                            hash_shift += 8;

                            if token_start == usize::MAX {
                                token_start = pos;
                            }
                        }
                        token_end = pos;
                    }
                    b'a'..=b'z' | b'-' | b'0'..=b'9' => {
                        if hash_shift < 64 {
                            hash |= (ch as u64) << hash_shift;
                            hash_shift += 8;

                            if token_start == usize::MAX {
                                token_start = pos;
                            }
                        }
                        token_end = pos;
                    }
                    _ => {
                        hash = u64::MAX;
                    }
                }
            } else if ch == b'\n'
                && self
                    .iter
                    .peek()
                    .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
            {
                let header_name = self
                    .message
                    .get(self.start_pos..colon_pos)
                    .unwrap_or_default();
                let header_value = self.message.get(colon_pos + 1..pos + 1).unwrap_or_default();
                let header_name = match hash {
                    RECEIVED if token_start + 8 == token_end + 1 => {
                        self.num_received += 1;
                        AuthenticatedHeader::Other(header_name)
                    }
                    FROM => AuthenticatedHeader::From(header_name),
                    #[cfg(feature = "arc")]
                    AS => AuthenticatedHeader::As(header_name),
                    #[cfg(feature = "arc")]
                    AAR if self
                        .message
                        .get(token_start + 8..token_end + 1)
                        .unwrap_or_default()
                        .eq_ignore_ascii_case(b"entication-Results") =>
                    {
                        AuthenticatedHeader::Aar(header_name)
                    }
                    #[cfg(feature = "arc")]
                    AMS if self
                        .message
                        .get(token_start + 8..token_end + 1)
                        .unwrap_or_default()
                        .eq_ignore_ascii_case(b"age-Signature") =>
                    {
                        AuthenticatedHeader::Ams(header_name)
                    }
                    DKIM if self
                        .message
                        .get(token_start + 8..token_end + 1)
                        .unwrap_or_default()
                        .eq_ignore_ascii_case(b"nature") =>
                    {
                        AuthenticatedHeader::Ds(header_name)
                    }
                    DKIM2
                        if self
                            .message
                            .get(token_start + 8..token_end + 1)
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(b"gnature") =>
                    {
                        AuthenticatedHeader::D2s(header_name)
                    }
                    MSGID
                        if self
                            .message
                            .get(token_start + 8..token_end + 1)
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(b"id") =>
                    {
                        self.has_message_id = true;
                        AuthenticatedHeader::Other(header_name)
                    }
                    MSGID
                        if self
                            .message
                            .get(token_start + 8..token_end + 1)
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(b"instance") =>
                    {
                        AuthenticatedHeader::D2i(header_name)
                    }
                    DATE => {
                        self.has_date = true;
                        AuthenticatedHeader::Other(header_name)
                    }
                    _ => AuthenticatedHeader::Other(header_name),
                };

                self.start_pos = pos + 1;

                return Some((header_name, header_value));
            }

            last_ch = ch;
        }

        None
    }
}

pub trait HeaderWriter: Sized {
    fn write_header(&self, writer: &mut impl Writer);
    fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write_header(&mut buf);
        String::from_utf8(buf).unwrap()
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
#[cfg(feature = "arc")]
const AAR: u64 = (b'a' as u64)
    | ((b'r' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'-' as u64) << 24)
    | ((b'a' as u64) << 32)
    | ((b'u' as u64) << 40)
    | ((b't' as u64) << 48)
    | ((b'h' as u64) << 56);
#[cfg(feature = "arc")]
const AMS: u64 = (b'a' as u64)
    | ((b'r' as u64) << 8)
    | ((b'c' as u64) << 16)
    | ((b'-' as u64) << 24)
    | ((b'm' as u64) << 32)
    | ((b'e' as u64) << 40)
    | ((b's' as u64) << 48)
    | ((b's' as u64) << 56);
#[cfg(feature = "arc")]
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
