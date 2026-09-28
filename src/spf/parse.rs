/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Directive, Macro, Mechanism, Qualifier, RR_FAIL, RR_NEUTRAL_NONE, RR_SOFTFAIL,
    RR_TEMP_PERM_ERROR, SpfRecord, Variable,
};
use crate::DnsError;
use crate::{
    Error,
    parse::{TagParser, TxtRecordParser, V},
    scan::{find_ascii_whitespace, find_le_space_or2},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    slice::Iter,
};

impl TxtRecordParser for SpfRecord {
    fn parse(bytes: &[u8]) -> crate::Result<SpfRecord> {
        let mut record = bytes.iter();
        if !matches!(record.key(), Some(k) if k == V)
            || !record.match_bytes(b"spf1")
            || record.next().is_some_and(|v| !v.is_ascii_whitespace())
        {
            return Err(Error::Dns(DnsError::InvalidRecordType));
        }

        let mut redirect = None;
        let mut exp = None;
        let mut ra = None;
        let mut rp = 100;
        let mut rr = u8::MAX;
        let mut directives = Vec::new();

        while let Some((term, qualifier, mut stop_char)) = record.next_term() {
            match term {
                A | MX => {
                    let mut ip4_cidr_length = 32;
                    let mut ip6_cidr_length = 128;
                    let mut macro_string = Macro::None;

                    match stop_char {
                        b' ' => (),
                        b':' | b'=' => {
                            let (ds, stop_char) = record.macro_string(false)?;
                            macro_string = ds;
                            if stop_char == b'/' {
                                let (l1, l2) = record.dual_cidr_length()?;
                                ip4_cidr_length = l1;
                                ip6_cidr_length = l2;
                            } else if stop_char != b' ' {
                                return Err(Error::Parse);
                            }
                        }
                        b'/' => {
                            let (l1, l2) = record.dual_cidr_length()?;
                            ip4_cidr_length = l1;
                            ip6_cidr_length = l2;
                        }
                        _ => return Err(Error::Parse),
                    }

                    directives.push(Directive::new(
                        qualifier,
                        if term == A {
                            Mechanism::A {
                                macro_string,
                                ip4_mask: ip4_mask(ip4_cidr_length),
                                ip6_mask: ip6_mask(ip6_cidr_length),
                            }
                        } else {
                            Mechanism::Mx {
                                macro_string,
                                ip4_mask: ip4_mask(ip4_cidr_length),
                                ip6_mask: ip6_mask(ip6_cidr_length),
                            }
                        },
                    ));
                }
                ALL => {
                    if stop_char == b' ' {
                        directives.push(Directive::new(qualifier, Mechanism::All))
                    } else {
                        return Err(Error::Parse);
                    }
                }
                INCLUDE | EXISTS => {
                    if stop_char != b':' {
                        return Err(Error::Parse);
                    }
                    let (macro_string, stop_char) = record.macro_string(false)?;
                    if stop_char == b' ' {
                        directives.push(Directive::new(
                            qualifier,
                            if term == INCLUDE {
                                Mechanism::Include { macro_string }
                            } else {
                                Mechanism::Exists { macro_string }
                            },
                        ));
                    } else {
                        return Err(Error::Parse);
                    }
                }
                IP4 => {
                    if stop_char != b':' {
                        return Err(Error::Parse);
                    }
                    let mut cidr_length = 32;
                    let (addr, stop_char) = record.ip4()?;
                    if stop_char == b'/' {
                        cidr_length = std::cmp::min(cidr_length, record.cidr_length()?);
                    } else if stop_char != b' ' {
                        return Err(Error::Parse);
                    }
                    directives.push(Directive::new(
                        qualifier,
                        Mechanism::Ip4 {
                            addr,
                            mask: ip4_mask(cidr_length),
                        },
                    ));
                }
                IP6 => {
                    if stop_char != b':' {
                        return Err(Error::Parse);
                    }
                    let mut cidr_length = 128;
                    let (addr, stop_char) = record.ip6()?;
                    if stop_char == b'/' {
                        cidr_length = std::cmp::min(cidr_length, record.cidr_length()?);
                    } else if stop_char != b' ' {
                        return Err(Error::Parse);
                    }
                    directives.push(Directive::new(
                        qualifier,
                        Mechanism::Ip6 {
                            addr,
                            mask: ip6_mask(cidr_length),
                        },
                    ));
                }
                PTR => {
                    let mut macro_string = Macro::None;
                    if stop_char == b':' {
                        let (ds, stop_char_) = record.macro_string(false)?;
                        macro_string = ds;
                        stop_char = stop_char_;
                    }

                    if stop_char == b' ' {
                        directives.push(Directive::new(qualifier, Mechanism::Ptr { macro_string }));
                    } else {
                        return Err(Error::Parse);
                    }
                }
                EXP | REDIRECT => {
                    if stop_char != b'=' {
                        return Err(Error::Parse);
                    }
                    let (macro_string, stop_char) = record.macro_string(false)?;
                    if stop_char != b' ' {
                        return Err(Error::Parse);
                    }
                    if term == REDIRECT {
                        if redirect.is_none() {
                            redirect = macro_string.into()
                        } else {
                            return Err(Error::Parse);
                        }
                    } else if exp.is_none() {
                        exp = macro_string.into()
                    } else {
                        return Err(Error::Parse);
                    };
                }
                RA => {
                    let ra_ = record.ra()?;
                    if !ra_.is_empty() {
                        ra = ra_.into_boxed_slice().into();
                    }
                }
                RP => {
                    rp = std::cmp::min(record.cidr_length()?, 100);
                }
                RR => {
                    rr = record.rr()?;
                }
                _ => {
                    let (_, stop_char) = record.macro_string(false)?;
                    if stop_char != b' ' {
                        return Err(Error::Parse);
                    }
                }
            }
        }

        Ok(SpfRecord {
            directives: directives.into_boxed_slice(),
            redirect,
            exp,
            ra,
            rp,
            rr,
        })
    }
}

#[inline(always)]
fn ip4_mask(cidr_length: u8) -> u32 {
    if cidr_length == 0 {
        0
    } else {
        u32::MAX << (32 - cidr_length)
    }
}

#[inline(always)]
fn ip6_mask(cidr_length: u8) -> u128 {
    if cidr_length == 0 {
        0
    } else {
        u128::MAX << (128 - cidr_length)
    }
}

const TERM_POISON: u8 = 0;
const TERM_SPACE: u8 = 1;
const TERM_STOP: u8 = 2;

const TERM_CLASS: [u8; 256] = {
    let mut table = [TERM_POISON; 256];
    let mut ch = 0usize;
    while ch < 256 {
        table[ch] = match ch as u8 {
            b'a'..=b'z' => ch as u8,
            b'A'..=b'Z' => (ch as u8) - b'A' + b'a',
            b'4' => b'4',
            b'6' => b'6',
            b':' | b'=' | b'/' => TERM_STOP,
            b'\t' | b'\n' | b'\x0C' | b'\r' | b' ' => TERM_SPACE,
            _ => TERM_POISON,
        };
        ch += 1;
    }
    table
};

const A: u64 = b'a' as u64;
const ALL: u64 = ((b'l' as u64) << 16) | ((b'l' as u64) << 8) | (b'a' as u64);
const EXISTS: u64 = ((b's' as u64) << 40)
    | ((b't' as u64) << 32)
    | ((b's' as u64) << 24)
    | ((b'i' as u64) << 16)
    | ((b'x' as u64) << 8)
    | (b'e' as u64);
const EXP: u64 = ((b'p' as u64) << 16) | ((b'x' as u64) << 8) | (b'e' as u64);
const INCLUDE: u64 = ((b'e' as u64) << 48)
    | ((b'd' as u64) << 40)
    | ((b'u' as u64) << 32)
    | ((b'l' as u64) << 24)
    | ((b'c' as u64) << 16)
    | ((b'n' as u64) << 8)
    | (b'i' as u64);
const IP4: u64 = ((b'4' as u64) << 16) | ((b'p' as u64) << 8) | (b'i' as u64);
const IP6: u64 = ((b'6' as u64) << 16) | ((b'p' as u64) << 8) | (b'i' as u64);
const MX: u64 = ((b'x' as u64) << 8) | (b'm' as u64);
const PTR: u64 = ((b'r' as u64) << 16) | ((b't' as u64) << 8) | (b'p' as u64);
const REDIRECT: u64 = ((b't' as u64) << 56)
    | ((b'c' as u64) << 48)
    | ((b'e' as u64) << 40)
    | ((b'r' as u64) << 32)
    | ((b'i' as u64) << 24)
    | ((b'd' as u64) << 16)
    | ((b'e' as u64) << 8)
    | (b'r' as u64);
const RA: u64 = ((b'a' as u64) << 8) | (b'r' as u64);
const RP: u64 = ((b'p' as u64) << 8) | (b'r' as u64);
const RR: u64 = ((b'r' as u64) << 8) | (b'r' as u64);

pub(crate) trait SPFParser: Sized {
    fn next_term(&mut self) -> Option<(u64, Qualifier, u8)>;
    fn macro_string(&mut self, is_exp: bool) -> crate::Result<(Macro, u8)>;
    fn ip4(&mut self) -> crate::Result<(Ipv4Addr, u8)>;
    fn ip6(&mut self) -> crate::Result<(Ipv6Addr, u8)>;
    fn cidr_length(&mut self) -> crate::Result<u8>;
    fn dual_cidr_length(&mut self) -> crate::Result<(u8, u8)>;
    fn rr(&mut self) -> crate::Result<u8>;
    fn ra(&mut self) -> crate::Result<Vec<u8>>;
}

impl SPFParser for Iter<'_, u8> {
    fn next_term(&mut self) -> Option<(u64, Qualifier, u8)> {
        let input = self.as_slice();
        let mut pos = 0;
        let mut qualifier = Qualifier::Pass;

        while let Some(&ch) = input.get(pos) {
            match ch {
                b'+' => qualifier = Qualifier::Pass,
                b'-' => qualifier = Qualifier::Fail,
                b'~' => qualifier = Qualifier::SoftFail,
                b'?' => qualifier = Qualifier::Neutral,
                b'\t' | b'\n' | b'\x0C' | b'\r' | b' ' => (),
                _ => break,
            }
            pos += 1;
        }

        let mut d = 0u64;
        let mut shift = 0;
        let mut stop_char = b' ';

        while let Some(&ch) = input.get(pos) {
            pos += 1;
            match TERM_CLASS[ch as usize] {
                TERM_POISON => {
                    d = u64::MAX;
                    shift = 64;
                }
                TERM_SPACE => {
                    stop_char = b' ';
                    break;
                }
                TERM_STOP => {
                    stop_char = ch;
                    break;
                }
                lower if shift < 64 => {
                    d |= (lower as u64) << shift;
                    shift += 8;
                }
                _ => {
                    d = u64::MAX;
                    shift = 64;
                }
            }
        }

        *self = input.get(pos..).unwrap_or_default().iter();

        if d != 0 {
            (d, qualifier, stop_char).into()
        } else {
            None
        }
    }

    fn macro_string(&mut self, is_exp: bool) -> crate::Result<(Macro, u8)> {
        let input = self.as_slice();
        let mut pos = 0;

        loop {
            let rest = input.get(pos..).unwrap_or_default();
            let hit = pos
                + if is_exp {
                    memchr::memchr(b'%', rest).unwrap_or(rest.len())
                } else {
                    find_le_space_or2(rest, b'%', b'/')
                };

            match input.get(hit) {
                None => {
                    *self = [].iter();
                    return literal_macro(input, b' ');
                }
                Some(&b'%') => break,
                Some(&ch) if !is_exp && (ch == b'/' || ch.is_ascii_whitespace()) => {
                    *self = input.get(hit + 1..).unwrap_or_default().iter();
                    return literal_macro(
                        input.get(..hit).unwrap_or_default(),
                        if ch == b'/' { b'/' } else { b' ' },
                    );
                }
                Some(_) => pos = hit + 1,
            }
        }

        self.macro_string_slow(is_exp)
    }

    fn ip4(&mut self) -> crate::Result<(Ipv4Addr, u8)> {
        let input = self.as_slice();
        let mut pos = 0;
        let mut stop_char = b' ';
        let mut ip = [0u8; 4];
        let mut octet = 0u8;
        let mut group = 0usize;

        while let Some(&ch) = input.get(pos) {
            pos += 1;
            match ch {
                b'0'..=b'9' => {
                    octet = octet.saturating_mul(10).saturating_add(ch - b'0');
                }
                b'.' if group < 3 => {
                    ip[group] = octet;
                    octet = 0;
                    group += 1;
                }
                _ => {
                    stop_char = if ch.is_ascii_whitespace() { b' ' } else { ch };
                    break;
                }
            }
        }

        *self = input.get(pos..).unwrap_or_default().iter();

        if group == 3 {
            let [a, b, c, _] = ip;
            Ok((Ipv4Addr::new(a, b, c, octet), stop_char))
        } else {
            Err(Error::Parse)
        }
    }

    fn ip6(&mut self) -> crate::Result<(Ipv6Addr, u8)> {
        let input = self.as_slice();
        let (result, pos) = parse_ip6(input);
        *self = input.get(pos..).unwrap_or_default().iter();
        result
    }

    fn cidr_length(&mut self) -> crate::Result<u8> {
        let input = self.as_slice();
        let mut pos = 0;
        let mut cidr_length = 0u8;

        while let Some(&ch) = input.get(pos) {
            pos += 1;
            match ch {
                b'0'..=b'9' => {
                    cidr_length = cidr_length.saturating_mul(10).saturating_add(ch - b'0');
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        *self = input.get(pos..).unwrap_or_default().iter();
                        return Err(Error::Parse);
                    }
                    break;
                }
            }
        }

        *self = input.get(pos..).unwrap_or_default().iter();
        Ok(cidr_length)
    }

    fn dual_cidr_length(&mut self) -> crate::Result<(u8, u8)> {
        let input = self.as_slice();
        let mut pos = 0;
        let mut ip4_length = u8::MAX;
        let mut ip6_length = u8::MAX;
        let mut in_ip6 = false;

        while let Some(&ch) = input.get(pos) {
            pos += 1;
            match ch {
                b'0'..=b'9' => {
                    let digit = ch - b'0';
                    let length = if in_ip6 {
                        &mut ip6_length
                    } else {
                        &mut ip4_length
                    };
                    *length = if *length != u8::MAX {
                        length.saturating_mul(10).saturating_add(digit)
                    } else {
                        digit
                    };
                }
                b'/' => {
                    if !in_ip6 {
                        in_ip6 = true;
                    } else if ip6_length != u8::MAX {
                        *self = input.get(pos..).unwrap_or_default().iter();
                        return Err(Error::Parse);
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        *self = input.get(pos..).unwrap_or_default().iter();
                        return Err(Error::Parse);
                    }
                    break;
                }
            }
        }

        *self = input.get(pos..).unwrap_or_default().iter();
        Ok((
            std::cmp::min(ip4_length, 32),
            std::cmp::min(ip6_length, 128),
        ))
    }

    fn rr(&mut self) -> crate::Result<u8> {
        let mut flags: u8 = 0;

        'outer: while let Some(&ch) = self.next() {
            match ch {
                b'a' | b'A' => {
                    for _ in 0..2 {
                        match self.next().unwrap_or(&0) {
                            b'l' | b'L' => {}
                            b' ' | b'\t' => {
                                return Ok(flags);
                            }
                            _ => {
                                continue 'outer;
                            }
                        }
                    }
                    flags = u8::MAX;
                }
                b'e' | b'E' => {
                    flags |= RR_TEMP_PERM_ERROR;
                }
                b'f' | b'F' => {
                    flags |= RR_FAIL;
                }
                b's' | b'S' => {
                    flags |= RR_SOFTFAIL;
                }
                b'n' | b'N' => {
                    flags |= RR_NEUTRAL_NONE;
                }
                b':' => {}
                _ => {
                    if ch.is_ascii_whitespace() {
                        break;
                    } else if !ch.is_ascii_alphanumeric() {
                        return Err(Error::Parse);
                    }
                }
            }
        }

        Ok(flags)
    }

    fn ra(&mut self) -> crate::Result<Vec<u8>> {
        let input = self.as_slice();
        let end = find_ascii_whitespace(input);
        let ra = input.get(..end).unwrap_or_default().to_vec();
        *self = input.get(end + 1..).unwrap_or_default().iter();
        Ok(ra)
    }
}

fn parse_ip6(input: &[u8]) -> (crate::Result<(Ipv6Addr, u8)>, usize) {
    let mut pos = 0;
    let mut stop_char = b' ';
    let mut ip = [0u16; 8];
    let mut ip_pos = 0;
    let mut ip4_pos = 0;
    let mut part = Ip6Part::default();
    let mut zero_group_pos = usize::MAX;

    while let Some(&ch) = input.get(pos) {
        pos += 1;
        match ch {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                if !part.push(ch) {
                    return (Err(Error::Parse), pos);
                }
            }
            b':' => {
                if ip_pos < 8 {
                    if !part.is_empty() {
                        ip[ip_pos] = part.take_hex();
                        ip_pos += 1;
                    } else if zero_group_pos == usize::MAX {
                        zero_group_pos = ip_pos;
                    } else if zero_group_pos != ip_pos {
                        return (Err(Error::Parse), pos);
                    }
                } else {
                    return (Err(Error::Parse), pos);
                }
            }
            b'.' => {
                if ip_pos < 8 && !part.is_empty() {
                    let Some(qnum) = part.take_octet() else {
                        return (Err(Error::Parse), pos);
                    };
                    if ip4_pos % 2 == 1 {
                        ip[ip_pos] = (ip[ip_pos] << 8) | qnum;
                        ip_pos += 1;
                    } else {
                        ip[ip_pos] = qnum;
                    }
                    ip4_pos += 1;
                } else {
                    return (Err(Error::Parse), pos);
                }
            }
            _ => {
                stop_char = if ch.is_ascii_whitespace() { b' ' } else { ch };
                break;
            }
        }
    }

    if !part.is_empty() {
        if ip_pos < 8 {
            ip[ip_pos] = if ip4_pos == 0 {
                part.take_hex()
            } else if ip4_pos == 3 {
                match part.take_octet() {
                    Some(qnum) => (ip[ip_pos] << 8) | qnum,
                    None => return (Err(Error::Parse), pos),
                }
            } else {
                return (Err(Error::Parse), pos);
            };

            ip_pos += 1;
        } else {
            return (Err(Error::Parse), pos);
        }
    }
    if zero_group_pos != usize::MAX && zero_group_pos < ip_pos {
        if ip_pos <= 7 {
            ip.copy_within(zero_group_pos..ip_pos, zero_group_pos + 8 - ip_pos);
            ip[zero_group_pos..zero_group_pos + 8 - ip_pos].fill(0);
        } else {
            return (Err(Error::Parse), pos);
        }
    }

    if ip_pos != 0 || zero_group_pos != usize::MAX {
        let [a, b, c, d, e, f, g, h] = ip;
        (Ok((Ipv6Addr::new(a, b, c, d, e, f, g, h), stop_char)), pos)
    } else {
        (Err(Error::Parse), pos)
    }
}

struct Ip6Part {
    hex: u16,
    decimal: u16,
    len: u8,
    is_decimal: bool,
}

impl Default for Ip6Part {
    fn default() -> Self {
        Ip6Part {
            hex: 0,
            decimal: 0,
            len: 0,
            is_decimal: true,
        }
    }
}

impl Ip6Part {
    #[inline(always)]
    fn push(&mut self, ch: u8) -> bool {
        if self.len < 4 {
            self.len += 1;
            self.hex = (self.hex << 4) | HEX_NIBBLE[ch as usize] as u16;
            if ch.is_ascii_digit() {
                self.decimal = self.decimal * 10 + (ch - b'0') as u16;
            } else {
                self.is_decimal = false;
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    fn take_hex(&mut self) -> u16 {
        let value = self.hex;
        *self = Ip6Part::default();
        value
    }

    #[inline(always)]
    fn take_octet(&mut self) -> Option<u16> {
        let value = (self.is_decimal && self.decimal <= 255).then_some(self.decimal);
        *self = Ip6Part::default();
        value
    }
}

const HEX_NIBBLE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut ch = 0usize;
    while ch < 256 {
        table[ch] = match ch as u8 {
            b'0'..=b'9' => (ch as u8) - b'0',
            b'a'..=b'f' => (ch as u8) - b'a' + 10,
            b'A'..=b'F' => (ch as u8) - b'A' + 10,
            _ => 0,
        };
        ch += 1;
    }
    table
};

#[inline(always)]
fn literal_macro(literal: &[u8], stop_char: u8) -> crate::Result<(Macro, u8)> {
    if literal.is_empty() {
        Err(Error::Parse)
    } else {
        Ok((Macro::Literal(literal.into()), stop_char))
    }
}

trait SPFMacroParser {
    fn macro_string_slow(&mut self, is_exp: bool) -> crate::Result<(Macro, u8)>;
}

impl SPFMacroParser for Iter<'_, u8> {
    #[inline(never)]
    #[allow(clippy::while_let_on_iterator)]
    fn macro_string_slow(&mut self, is_exp: bool) -> crate::Result<(Macro, u8)> {
        let mut stop_char = b' ';
        let mut last_is_pct = false;
        let mut literal = Vec::with_capacity(16);
        let mut macro_string = Vec::new();

        while let Some(&ch) = self.next() {
            match ch {
                b'%' => {
                    if last_is_pct {
                        literal.push(b'%');
                    } else {
                        last_is_pct = true;
                        continue;
                    }
                }
                b'_' if last_is_pct => {
                    literal.push(b' ');
                }
                b'-' if last_is_pct => {
                    literal.extend_from_slice(b"%20");
                }
                b'{' if last_is_pct => {
                    if !literal.is_empty() {
                        macro_string.push(Macro::Literal(literal.as_slice().into()));
                        literal.clear();
                    }

                    let (letter, escape) = self
                        .next()
                        .copied()
                        .and_then(|l| {
                            if !is_exp {
                                Variable::parse(l)
                            } else {
                                Variable::parse_exp(l)
                            }
                        })
                        .ok_or(Error::Parse)?;
                    let mut num_parts: u32 = 0;
                    let mut reverse = false;
                    let mut delimiters = 0;

                    while let Some(&ch) = self.next() {
                        match ch {
                            b'0'..=b'9' => {
                                num_parts = num_parts
                                    .saturating_mul(10)
                                    .saturating_add((ch - b'0') as u32);
                            }
                            b'r' | b'R' => {
                                reverse = true;
                            }
                            b'}' => {
                                break;
                            }
                            b'.' | b'-' | b'+' | b',' | b'/' | b'_' | b'=' => {
                                delimiters |= 1u64 << (ch - b'+');
                            }
                            _ => {
                                return Err(Error::Parse);
                            }
                        }
                    }

                    if delimiters == 0 {
                        delimiters = 1u64 << (b'.' - b'+');
                    }

                    macro_string.push(Macro::Variable {
                        letter,
                        num_parts,
                        reverse,
                        escape,
                        delimiters,
                    });
                }
                b'/' if !is_exp => {
                    stop_char = ch;
                    break;
                }
                _ => {
                    if last_is_pct {
                        return Err(Error::Parse);
                    } else if !ch.is_ascii_whitespace() || is_exp {
                        literal.push(ch);
                    } else {
                        break;
                    }
                }
            }

            last_is_pct = false;
        }

        if !literal.is_empty() {
            macro_string.push(Macro::Literal(literal.into_boxed_slice()));
        }

        match macro_string.len() {
            1 => macro_string
                .pop()
                .map(|m| (m, stop_char))
                .ok_or(Error::Parse),
            0 => Err(Error::Parse),
            _ => Ok((Macro::List(macro_string.into_boxed_slice()), stop_char)),
        }
    }
}

impl Variable {
    pub(crate) fn parse(ch: u8) -> Option<(Self, bool)> {
        match ch {
            b's' => (Variable::Sender, false),
            b'l' => (Variable::SenderLocalPart, false),
            b'o' => (Variable::SenderDomainPart, false),
            b'd' => (Variable::Domain, false),
            b'i' => (Variable::Ip, false),
            b'p' => (Variable::ValidatedDomain, false),
            b'v' => (Variable::IpVersion, false),
            b'h' => (Variable::HeloDomain, false),

            b'S' => (Variable::Sender, true),
            b'L' => (Variable::SenderLocalPart, true),
            b'O' => (Variable::SenderDomainPart, true),
            b'D' => (Variable::Domain, true),
            b'I' => (Variable::Ip, true),
            b'P' => (Variable::ValidatedDomain, true),
            b'V' => (Variable::IpVersion, true),
            b'H' => (Variable::HeloDomain, true),
            _ => return None,
        }
        .into()
    }

    pub(crate) fn parse_exp(ch: u8) -> Option<(Self, bool)> {
        match ch {
            b's' => (Variable::Sender, false),
            b'l' => (Variable::SenderLocalPart, false),
            b'o' => (Variable::SenderDomainPart, false),
            b'd' => (Variable::Domain, false),
            b'i' => (Variable::Ip, false),
            b'p' => (Variable::ValidatedDomain, false),
            b'v' => (Variable::IpVersion, false),
            b'h' => (Variable::HeloDomain, false),
            b'c' => (Variable::SmtpIp, false),
            b'r' => (Variable::HostDomain, false),
            b't' => (Variable::CurrentTime, false),

            b'S' => (Variable::Sender, true),
            b'L' => (Variable::SenderLocalPart, true),
            b'O' => (Variable::SenderDomainPart, true),
            b'D' => (Variable::Domain, true),
            b'I' => (Variable::Ip, true),
            b'P' => (Variable::ValidatedDomain, true),
            b'V' => (Variable::IpVersion, true),
            b'H' => (Variable::HeloDomain, true),
            b'C' => (Variable::SmtpIp, true),
            b'R' => (Variable::HostDomain, true),
            b'T' => (Variable::CurrentTime, true),
            _ => return None,
        }
        .into()
    }
}

impl TxtRecordParser for Macro {
    fn parse(record: &[u8]) -> crate::Result<Self> {
        record.iter().macro_string(true).map(|(m, _)| m)
    }
}

#[cfg(test)]
mod tests;
