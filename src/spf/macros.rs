/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Macro, Variable, Variables};
use crate::SystemTime;
use crate::common::resolver::{decimal_u8, hex_nibble};
use std::{borrow::Cow, net::IpAddr};

const DEFAULT_DELIMITERS: u64 = 1u64 << (b'.' - b'+');
const LAST_DELIMITER: u8 = b'_' - b'+';

impl Macro {
    pub fn eval<'z, 'x: 'z>(
        &'z self,
        vars: &'x Variables<'x>,
        default: &'x str,
        fqdn: bool,
    ) -> Cow<'z, str> {
        match self {
            Macro::Literal(literal) => std::str::from_utf8(literal).unwrap_or_default().into(),
            Macro::Variable {
                letter,
                num_parts,
                reverse,
                escape,
                delimiters,
            } => match vars.get(*letter, *num_parts, *reverse, *escape, fqdn, *delimiters) {
                Cow::Borrowed(bytes) => std::str::from_utf8(bytes).unwrap_or_default().into(),
                Cow::Owned(bytes) => String::from_utf8(bytes).unwrap_or_default().into(),
            },
            Macro::List(list) => {
                let mut result = Vec::with_capacity(
                    list.iter()
                        .map(|item| match item {
                            Macro::Literal(literal) => literal.len(),
                            _ => 24,
                        })
                        .sum::<usize>()
                        + 1,
                );
                for item in list {
                    match item {
                        Macro::Literal(literal) => {
                            result.extend_from_slice(literal);
                        }
                        Macro::Variable {
                            letter,
                            num_parts,
                            reverse,
                            escape,
                            delimiters,
                        } => {
                            vars.append(
                                &mut result,
                                *letter,
                                Transform {
                                    num_parts: *num_parts,
                                    reverse: *reverse,
                                    escape: *escape,
                                    fqdn: false,
                                    delimiters: *delimiters,
                                },
                            );
                        }
                        Macro::List(_) | Macro::None => unreachable!(),
                    }
                }
                if fqdn && matches!(result.last(), Some(last) if *last != b'.') {
                    result.push(b'.');
                }
                String::from_utf8(result).unwrap_or_default().into()
            }
            Macro::None => default.into(),
        }
    }

    pub fn needs_ptr(&self) -> bool {
        match self {
            Macro::Variable { letter, .. } => *letter == Variable::ValidatedDomain,
            Macro::List(list) => list.iter().any(|m| matches!(m, Macro::Variable { letter, .. } if *letter == Variable::ValidatedDomain)),
            _ => false,
        }
    }
}

impl<'x> Variables<'x> {
    pub fn new() -> Self {
        Variables {
            current_time_on_demand: true,
            ..Default::default()
        }
    }

    pub fn set_ip(&mut self, value: &IpAddr) {
        let (v, i, c): (&'static [u8], Vec<u8>, Vec<u8>) = match value {
            IpAddr::V4(ip) => {
                let mut dotted = Vec::with_capacity(15);
                let mut buf = [0u8; 3];
                for octet in ip.octets() {
                    if !dotted.is_empty() {
                        dotted.push(b'.');
                    }
                    dotted.extend_from_slice(decimal_u8(octet, &mut buf));
                }
                (b"in-addr", dotted.clone(), dotted)
            }
            IpAddr::V6(ip) => {
                let mut segments = Vec::with_capacity(63);
                for segment in ip.segments() {
                    for shift in [12u32, 8, 4, 0] {
                        if !segments.is_empty() {
                            segments.push(b'.');
                        }
                        segments.push(hex_nibble((segment >> shift) as u8));
                    }
                }
                (b"ip6", segments, ip.to_string().into_bytes())
            }
        };
        self.vars[Variable::IpVersion as usize] = v.into();
        self.vars[Variable::Ip as usize] = i.into();
        self.vars[Variable::SmtpIp as usize] = c.into();
    }

    pub fn set_sender(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        let value = value.into();
        for (pos, ch) in value.iter().enumerate() {
            if ch == &b'@' {
                if pos > 0 {
                    self.vars[Variable::SenderLocalPart as usize] = match &value {
                        Cow::Borrowed(value) => (&value[..pos]).into(),
                        Cow::Owned(value) => value[..pos].to_vec().into(),
                    };
                }
                self.vars[Variable::SenderDomainPart as usize] = match &value {
                    Cow::Borrowed(value) => (value.get(pos + 1..).unwrap_or_default()).into(),
                    Cow::Owned(value) => (value.get(pos + 1..).unwrap_or_default()).to_vec().into(),
                };
                break;
            }
        }

        self.vars[Variable::Sender as usize] = value;
    }

    pub fn set_helo_domain(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        self.vars[Variable::HeloDomain as usize] = value.into();
    }

    pub fn set_host_domain(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        self.vars[Variable::HostDomain as usize] = value.into();
    }

    pub fn set_validated_domain(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        self.vars[Variable::ValidatedDomain as usize] = value.into();
    }

    pub fn set_domain(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        self.vars[Variable::Domain as usize] = value.into();
    }

    pub fn get(
        &self,
        name: Variable,
        num_parts: u32,
        reverse: bool,
        escape: bool,
        fqdn: bool,
        delimiters: u64,
    ) -> Cow<'_, [u8]> {
        let transform = Transform {
            num_parts,
            reverse,
            escape,
            fqdn,
            delimiters,
        };
        let var: &[u8] = self.vars[name as usize].as_ref();
        if var.is_empty() && self.current_time_on_demand && matches!(name, Variable::CurrentTime) {
            let now = current_time();
            if transform.is_verbatim() {
                return Cow::Owned(now);
            }
            let mut result = Vec::with_capacity(transform.capacity_for(&now));
            append_transformed(&mut result, &now, transform);
            return Cow::Owned(result);
        }
        if var.is_empty() || transform.is_verbatim() {
            return Cow::Borrowed(var);
        }

        let mut result = Vec::with_capacity(transform.capacity_for(var));
        append_transformed(&mut result, var, transform);
        Cow::Owned(result)
    }

    fn append(&self, result: &mut Vec<u8>, name: Variable, transform: Transform) {
        let var: &[u8] = self.vars[name as usize].as_ref();
        if var.is_empty() && self.current_time_on_demand && matches!(name, Variable::CurrentTime) {
            append_variable(result, &current_time(), transform);
        } else {
            append_variable(result, var, transform);
        }
    }
}

#[derive(Clone, Copy)]
struct Transform {
    num_parts: u32,
    reverse: bool,
    escape: bool,
    fqdn: bool,
    delimiters: u64,
}

impl Transform {
    #[inline(always)]
    fn is_verbatim(&self) -> bool {
        self.num_parts == 0
            && !self.reverse
            && !self.escape
            && self.delimiters == DEFAULT_DELIMITERS
    }

    #[inline(always)]
    fn capacity_for(&self, var: &[u8]) -> usize {
        if self.escape {
            var.len() * 3 + 1
        } else {
            var.len() + 1
        }
    }

    #[inline(always)]
    fn is_delimiter(&self, ch: u8) -> bool {
        let offset = ch.wrapping_sub(b'+');
        offset <= LAST_DELIMITER && (self.delimiters & (1u64 << offset)) != 0
    }
}

fn append_variable(result: &mut Vec<u8>, var: &[u8], transform: Transform) {
    if var.is_empty() || transform.is_verbatim() {
        result.extend_from_slice(var);
    } else {
        append_transformed(result, var, transform);
    }
}

fn append_transformed(result: &mut Vec<u8>, var: &[u8], transform: Transform) {
    let skipped = if transform.num_parts == 0 {
        0
    } else {
        let total = 1 + var.iter().filter(|ch| transform.is_delimiter(**ch)).count();
        total - std::cmp::min(total, transform.num_parts as usize)
    };

    let start = result.len();
    if !transform.reverse {
        for (pos, part) in var
            .split(|ch| transform.is_delimiter(*ch))
            .skip(skipped)
            .enumerate()
        {
            add_part(result, part, pos, transform.escape);
        }
    } else {
        for (pos, part) in var
            .rsplit(|ch| transform.is_delimiter(*ch))
            .skip(skipped)
            .enumerate()
        {
            add_part(result, part, pos, transform.escape);
        }
    }
    if transform.fqdn && !matches!(result.get(start..), Some([.., b'.'])) {
        result.push(b'.');
    }
}

fn current_time() -> Vec<u8> {
    let mut seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut buf = [0u8; 20];
    let mut len = 0;
    for slot in buf.iter_mut().rev() {
        *slot = b'0' + (seconds % 10) as u8;
        len += 1;
        seconds /= 10;
        if seconds == 0 {
            break;
        }
    }
    buf[buf.len() - len..].to_vec()
}

#[inline(always)]
fn add_part(result: &mut Vec<u8>, part: &[u8], pos: usize, escape: bool) {
    if pos > 0 {
        result.push(b'.');
    }
    if !escape {
        result.extend_from_slice(part);
    } else {
        for &ch in part {
            if ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'.' | b'_' | b'~') {
                result.push(ch);
            } else {
                result.extend_from_slice(&[b'%', hex_nibble(ch >> 4), hex_nibble(ch)]);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::spf::{Variables, parse::SPFParser};

    #[test]
    fn expand_macro() {
        let mut vars = Variables::new();
        vars.set_sender("strong-bad@email.example.com".as_bytes());
        vars.set_ip(&"192.0.2.3".parse::<IpAddr>().unwrap());
        vars.set_validated_domain("mx.example.org".as_bytes());
        vars.set_domain("email.example.com".as_bytes());
        vars.set_helo_domain("....".as_bytes());

        for (macro_string, expansion) in [
            ("%{s}", "strong-bad@email.example.com"),
            ("%{o}", "email.example.com"),
            ("%{d}", "email.example.com"),
            ("%{d4}", "email.example.com"),
            ("%{d3}", "email.example.com"),
            ("%{d2}", "example.com"),
            ("%{d1}", "com"),
            ("%{dr}", "com.example.email"),
            ("%{d2r}", "example.email"),
            ("%{l}", "strong-bad"),
            ("%{l-}", "strong.bad"),
            ("%{lr}", "strong-bad"),
            ("%{lr-}", "bad.strong"),
            ("%{l1r-}", "strong"),
            ("%{p1r}", "mx"),
            ("%{h3r}", ".."),
            (
                "%{ir}.%{v}._spf.%{d2}",
                "3.2.0.192.in-addr._spf.example.com",
            ),
            ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
            (
                "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
                "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
            ),
            (
                "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
                "3.2.0.192.in-addr.strong.lp._spf.example.com",
            ),
            (
                "%{d2}.trusted-domains.example.net",
                "example.com.trusted-domains.example.net",
            ),
        ] {
            let (m, _) = macro_string.as_bytes().iter().macro_string(false).unwrap();
            assert_eq!(m.eval(&vars, "", false), expansion, "{macro_string:?}");
        }

        let mut vars = Variables::new();
        vars.set_sender("strong-bad@email.example.com".as_bytes());
        vars.set_ip(&"2001:db8::cb01".parse::<IpAddr>().unwrap());
        vars.set_validated_domain("mx.example.org".as_bytes());
        vars.set_domain("email.example.com".as_bytes());

        for (macro_string, expansion) in [
            (
                "%{ir}.%{v}._spf.%{d2}",
                concat!(
                    "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.",
                    "0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
                ),
            ),
            ("%{c}", "2001:db8::cb01"),
            (
                "%{c} is not one of %{d}'s designated mail servers.",
                "2001:db8::cb01 is not one of email.example.com's designated mail servers.",
            ),
            (
                "See http://%{d}/why.html?s=%{S}&i=%{C}",
                concat!(
                    "See http://email.example.com/why.html?",
                    "s=strong-bad%40email.example.com&i=2001%3adb8%3a%3acb01"
                ),
            ),
        ] {
            let (m, _) = macro_string.as_bytes().iter().macro_string(true).unwrap();
            assert_eq!(m.eval(&vars, "", false), expansion, "{macro_string:?}");
        }
    }
}
