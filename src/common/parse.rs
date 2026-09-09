/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_parser::decoders::{
    base64::base64_decode_slice, quoted_printable::quoted_printable_decode_char,
};
use memchr::{memchr, memchr_iter};
use std::{borrow::Cow, slice::Iter};

const MAX_ITEMS: usize = 32;

pub(crate) const V: u64 = b'v' as u64;
pub(crate) const A: u64 = b'a' as u64;
pub(crate) const B: u64 = b'b' as u64;
pub(crate) const BH: u64 = (b'b' as u64) | ((b'h' as u64) << 8);
pub(crate) const C: u64 = b'c' as u64;
pub(crate) const D: u64 = b'd' as u64;
pub(crate) const H: u64 = b'h' as u64;
pub(crate) const I: u64 = b'i' as u64;
pub(crate) const K: u64 = b'k' as u64;
pub(crate) const L: u64 = b'l' as u64;
pub(crate) const N: u64 = b'n' as u64;
pub(crate) const O: u64 = b'o' as u64;
pub(crate) const P: u64 = b'p' as u64;
pub(crate) const R: u64 = b'r' as u64;
pub(crate) const S: u64 = b's' as u64;
pub(crate) const T: u64 = b't' as u64;
pub(crate) const U: u64 = b'u' as u64;
pub(crate) const X: u64 = b'x' as u64;
pub(crate) const Y: u64 = b'y' as u64;
pub(crate) const Z: u64 = b'z' as u64;

pub trait TxtRecordParser: Sized {
    fn parse(record: &[u8]) -> crate::Result<Self>;
}

pub(crate) trait TagParser: Sized {
    fn match_bytes(&mut self, bytes: &[u8]) -> bool;
    fn key(&mut self) -> Option<u64>;
    fn value(&mut self) -> u64;
    fn text(&mut self, to_lower: bool) -> String;
    fn text_qp(&mut self, base: Vec<u8>, to_lower: bool, stop_comma: bool) -> String;
    fn headers_qp<T: ItemParser>(&mut self) -> Vec<T>;
    fn number(&mut self) -> Option<u64>;
    fn items<T: ItemParser>(&mut self) -> Vec<T>;
    fn flag_value(&mut self) -> (u64, u8);
    fn flags<T: ItemParser + Into<u64>>(&mut self) -> u64;
    fn ignore(&mut self);
    fn base64(&mut self) -> Option<Vec<u8>>;
    fn seek_tag_end(&mut self) -> bool;
    fn next_skip_whitespaces(&mut self) -> Option<u8>;
}

pub(crate) trait ItemParser: Sized {
    fn parse(bytes: &[u8]) -> Option<Self>;
}

#[inline(always)]
fn split_tag_value(slice: &[u8]) -> (&[u8], &[u8]) {
    match memchr(b';', slice) {
        Some(pos) => (
            slice.get(..pos).unwrap_or(slice),
            slice.get(pos + 1..).unwrap_or_default(),
        ),
        None => (slice, &[]),
    }
}

#[inline(always)]
fn is_text_stop(ch: u8, to_lower: bool) -> bool {
    ch.is_ascii_whitespace() || (to_lower && (ch.is_ascii_uppercase() || ch >= 0x7f))
}

#[inline(always)]
fn is_qp_stop(ch: u8, stop_comma: bool) -> bool {
    ch == b'=' || ch == b';' || ch.is_ascii_whitespace() || (stop_comma && ch == b',')
}

#[inline(always)]
fn is_header_stop(ch: u8) -> bool {
    ch == b'=' || ch == b'|' || ch == b';' || ch.is_ascii_whitespace()
}

#[inline(always)]
fn slice_to_string(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(value) => value.to_string(),
        Err(_) => String::from_utf8_lossy(value).into_owned(),
    }
}

#[inline(always)]
fn vec_to_string(tag: Vec<u8>) -> String {
    String::from_utf8(tag)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

#[inline(always)]
fn parse_item<T: ItemParser>(item: &[u8], scratch: &mut Vec<u8>) -> Option<T> {
    match item.iter().position(|&ch| ch.is_ascii_whitespace()) {
        None => {
            if !item.is_empty() {
                T::parse(item)
            } else {
                None
            }
        }
        Some(pos) => {
            let (head, tail) = item.split_at_checked(pos).unwrap_or((item, &[]));
            scratch.clear();
            scratch.reserve(item.len());
            scratch.extend_from_slice(head);
            for &ch in tail {
                if !ch.is_ascii_whitespace() {
                    scratch.push(ch);
                }
            }
            if !scratch.is_empty() {
                T::parse(scratch)
            } else {
                None
            }
        }
    }
}

#[inline(never)]
fn text_value(value: &[u8], pos: usize, to_lower: bool) -> String {
    let Some((head, mut rest)) = value.split_at_checked(pos) else {
        return slice_to_string(value);
    };
    let mut tag = Vec::with_capacity(value.len());
    let mut has_high = false;
    tag.extend_from_slice(head);

    while let Some((&ch, next)) = rest.split_first() {
        if !is_text_stop(ch, to_lower) {
            let end = rest
                .iter()
                .position(|&ch| is_text_stop(ch, to_lower))
                .unwrap_or(rest.len());
            let Some((run, tail)) = rest.split_at_checked(end) else {
                break;
            };
            tag.extend_from_slice(run);
            rest = tail;
            continue;
        }

        rest = next;
        if ch.is_ascii_whitespace() {
        } else if ch.is_ascii_uppercase() {
            tag.push(ch + 32);
        } else {
            has_high = true;
            tag.push(ch);
        }
    }

    if to_lower && has_high {
        String::from_utf8_lossy(&tag).to_lowercase()
    } else {
        vec_to_string(tag)
    }
}

#[inline(always)]
fn push_item<T: ItemParser>(tag: &mut Vec<u8>, tags: &mut Vec<T>) {
    if !tag.is_empty() {
        if let Some(parsed) = T::parse(tag) {
            tags.push(parsed);
        }
        tag.clear();
    }
}

impl TagParser for Iter<'_, u8> {
    #[allow(clippy::while_let_on_iterator)]
    fn key(&mut self) -> Option<u64> {
        let mut key: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' if shift < 64 => {
                    key |= (ch as u64) << shift;
                    shift += 8;
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'=' => {
                    return key.into();
                }
                b'A'..=b'Z' if shift < 64 => {
                    key |= ((ch - b'A' + b'a') as u64) << shift;
                    shift += 8;
                }
                b';' => {
                    key = 0;
                }
                _ => {
                    key = u64::MAX;
                    shift = 64;
                }
            }
        }

        None
    }

    #[allow(clippy::while_let_on_iterator)]
    fn value(&mut self) -> u64 {
        let mut value: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' | b'0'..=b'9' if shift < 64 => {
                    value |= (ch as u64) << shift;
                    shift += 8;
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'A'..=b'Z' if shift < 64 => {
                    value |= ((ch - b'A' + b'a') as u64) << shift;
                    shift += 8;
                }
                b';' => {
                    break;
                }
                _ => {
                    value = u64::MAX;
                    shift = 64;
                }
            }
        }

        value
    }

    #[allow(clippy::while_let_on_iterator)]
    fn flag_value(&mut self) -> (u64, u8) {
        let mut value: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' | b'0'..=b'9' if shift < 64 => {
                    value |= (ch as u64) << shift;
                    shift += 8;
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'A'..=b'Z' if shift < 64 => {
                    value |= ((ch - b'A' + b'a') as u64) << shift;
                    shift += 8;
                }
                b';' | b':' => {
                    return (value, ch);
                }
                _ => {
                    value = u64::MAX;
                    shift = 64;
                }
            }
        }

        (value, 0)
    }

    #[inline(always)]
    #[allow(clippy::while_let_on_iterator)]
    fn match_bytes(&mut self, bytes: &[u8]) -> bool {
        let slice = self.as_slice();

        if let Some(head) = slice.get(..bytes.len())
            && head
                .iter()
                .zip(bytes)
                .all(|(ch, byte)| ch.eq_ignore_ascii_case(byte) && !ch.is_ascii_whitespace())
        {
            *self = slice.get(bytes.len()..).unwrap_or_default().iter();
            return true;
        }

        'outer: for byte in bytes {
            while let Some(&ch) = self.next() {
                if !ch.is_ascii_whitespace() {
                    if ch.eq_ignore_ascii_case(byte) {
                        continue 'outer;
                    } else {
                        return false;
                    }
                }
            }
            return false;
        }

        true
    }

    #[inline(always)]
    fn text(&mut self, to_lower: bool) -> String {
        let slice = self.as_slice();
        let (value, tail) = split_tag_value(slice);
        *self = tail.iter();

        match value.iter().position(|&ch| is_text_stop(ch, to_lower)) {
            Some(pos) => text_value(value, pos, to_lower),
            None => slice_to_string(value),
        }
    }

    #[inline(always)]
    fn text_qp(&mut self, mut tag: Vec<u8>, to_lower: bool, stop_comma: bool) -> String {
        let mut rest = self.as_slice();

        'outer: loop {
            let Some(pos) = rest.iter().position(|&ch| is_qp_stop(ch, stop_comma)) else {
                tag.extend_from_slice(rest);
                rest = &[];
                break;
            };
            let Some((head, next)) = rest.split_at_checked(pos) else {
                break;
            };
            tag.extend_from_slice(head);
            let Some((&ch, mut next)) = next.split_first() else {
                break;
            };

            if ch == b';' || ch == b',' {
                rest = next;
                break;
            } else if ch == b'=' {
                let mut hex1 = 0;

                while let Some((&ch, tail)) = next.split_first() {
                    next = tail;
                    if ch.is_ascii_hexdigit() {
                        if hex1 != 0 {
                            if let Some(ch) = quoted_printable_decode_char(hex1, ch) {
                                tag.push(ch);
                            }
                            break;
                        } else {
                            hex1 = ch;
                        }
                    } else if ch == b';' {
                        rest = next;
                        break 'outer;
                    } else if !ch.is_ascii_whitespace() {
                        break;
                    }
                }
            }

            rest = next;
        }

        *self = rest.iter();

        if !to_lower {
            vec_to_string(tag)
        } else if tag.is_ascii() {
            tag.make_ascii_lowercase();
            vec_to_string(tag)
        } else {
            String::from_utf8_lossy(&tag).to_lowercase()
        }
    }

    #[inline(always)]
    fn headers_qp<T: ItemParser>(&mut self) -> Vec<T> {
        let mut tags = Vec::new();
        let mut tag = Vec::with_capacity(20);
        let mut rest = self.as_slice();

        'outer: loop {
            let Some(pos) = rest.iter().position(|&ch| is_header_stop(ch)) else {
                tag.extend_from_slice(rest);
                rest = &[];
                break;
            };
            let Some((head, next)) = rest.split_at_checked(pos) else {
                break;
            };
            tag.extend_from_slice(head);
            let Some((&ch, mut next)) = next.split_first() else {
                break;
            };

            if ch == b';' {
                rest = next;
                break;
            } else if ch == b'|' {
                push_item(&mut tag, &mut tags);
            } else if ch == b'=' {
                let mut hex1 = 0;

                while let Some((&ch, tail)) = next.split_first() {
                    next = tail;
                    if ch.is_ascii_hexdigit() {
                        if hex1 != 0 {
                            if let Some(ch) = quoted_printable_decode_char(hex1, ch) {
                                tag.push(ch);
                            }
                            break;
                        } else {
                            hex1 = ch;
                        }
                    } else if ch == b'|' {
                        push_item(&mut tag, &mut tags);
                        break;
                    } else if ch == b';' {
                        rest = next;
                        break 'outer;
                    } else if !ch.is_ascii_whitespace() {
                        break;
                    }
                }
            }

            rest = next;
        }

        *self = rest.iter();

        if !tag.is_empty()
            && let Some(tag) = T::parse(&tag)
        {
            tags.push(tag);
        }

        tags
    }

    #[inline(always)]
    fn number(&mut self) -> Option<u64> {
        let mut num: u64 = 0;
        let mut has_digits = false;

        for &ch in &mut *self {
            if ch == b';' {
                break;
            } else if ch.is_ascii_digit() {
                num = (num.saturating_mul(10)).saturating_add((ch - b'0') as u64);
                has_digits = true;
            } else if !ch.is_ascii_whitespace() {
                return None;
            }
        }

        if has_digits { num.into() } else { None }
    }

    #[inline(always)]
    fn ignore(&mut self) {
        let (_, tail) = split_tag_value(self.as_slice());
        *self = tail.iter();
    }

    #[inline(always)]
    fn base64(&mut self) -> Option<Vec<u8>> {
        let slice = self.as_slice();
        match base64_decode_slice(slice, b';') {
            Some((decoded, consumed)) => {
                *self = slice.get(consumed..).unwrap_or_default().iter();
                Some(decoded)
            }
            None => {
                self.ignore();
                None
            }
        }
    }

    #[inline(always)]
    fn seek_tag_end(&mut self) -> bool {
        for &ch in &mut *self {
            if ch == b';' {
                return true;
            } else if !ch.is_ascii_whitespace() {
                return false;
            }
        }

        true
    }

    #[inline(always)]
    fn next_skip_whitespaces(&mut self) -> Option<u8> {
        for &ch in &mut *self {
            if !ch.is_ascii_whitespace() {
                return ch.into();
            }
        }

        None
    }

    fn items<T: ItemParser>(&mut self) -> Vec<T> {
        let (value, tail) = split_tag_value(self.as_slice());
        *self = tail.iter();

        if value.is_empty() {
            return Vec::new();
        }

        let mut items = Vec::with_capacity(memchr_iter(b':', value).count().min(MAX_ITEMS) + 1);
        let mut scratch = Vec::new();

        for item in value.split(|&ch| ch == b':') {
            if let Some(item) = parse_item(item, &mut scratch) {
                items.push(item);
            }
        }

        items
    }

    fn flags<T: ItemParser + Into<u64>>(&mut self) -> u64 {
        let (value, tail) = split_tag_value(self.as_slice());
        *self = tail.iter();

        let mut flags = 0;
        let mut scratch = Vec::new();

        for item in value.split(|&ch| ch == b':') {
            if let Some(item) = parse_item::<T>(item, &mut scratch) {
                flags |= item.into();
            }
        }

        flags
    }
}

impl ItemParser for Vec<u8> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}

impl ItemParser for Box<[u8]> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(bytes.into())
    }
}

impl ItemParser for Box<str> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(std::str::from_utf8(bytes).ok()?.into())
    }
}

impl ItemParser for String {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl ItemParser for Cow<'_, str> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(
            std::str::from_utf8(bytes)
                .unwrap_or_default()
                .to_string()
                .into(),
        )
    }
}
