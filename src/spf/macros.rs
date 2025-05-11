/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{borrow::Cow, net::IpAddr, time::SystemTime};

use super::{Macro, Variable, Variables};

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
                let mut result = Vec::with_capacity(32);
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
                            result.extend_from_slice(
                                vars.get(
                                    *letter,
                                    *num_parts,
                                    *reverse,
                                    *escape,
                                    false,
                                    *delimiters,
                                )
                                .as_ref(),
                            );
                        }
                        Macro::List(_) | Macro::None => unreachable!(),
                    }
                }
                if fqdn && !result.is_empty() && result.last().unwrap() != &b'.' {
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
        let mut vars = Variables::default();
        vars.vars[Variable::CurrentTime as usize] = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
            .into_bytes()
            .into();
        vars
    }

    pub fn set_ip(&mut self, value: &IpAddr) {
        let (v, i, c) = match value {
            IpAddr::V4(ip) => (
                "in-addr".as_bytes(),
                ip.to_string().into_bytes(),
                ip.to_string(),
            ),
            IpAddr::V6(ip) => {
                let mut segments = Vec::with_capacity(63);
                for segment in ip.segments() {
                    for &p in format!("{segment:04x}").as_bytes() {
                        if !segments.is_empty() {
                            segments.push(b'.');
                        }
                        segments.push(p);
                    }
                }
                ("ip6".as_bytes(), segments, ip.to_string())
            }
        };
        self.vars[Variable::IpVersion as usize] = v.into();
        self.vars[Variable::Ip as usize] = i.into();
        self.vars[Variable::SmtpIp as usize] = c.into_bytes().into();
    }

    pub fn set_sender(&mut self, value: impl Into<Cow<'x, [u8]>>) {
        let value = value.into();
        for (pos, ch) in value.as_ref().iter().enumerate() {
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
        let var = self.vars[name as usize].as_ref();
        if var.is_empty()
            || (num_parts == 0 && !reverse && !escape && delimiters == 1u64 << (b'.' - b'+'))
        {
            return var.into();
        }
        let mut parts = Vec::new();
        let mut parts_len = 0;
        let mut start_pos = 0;

        for (pos, ch) in var.iter().enumerate() {
            if (b'+'..=b'_').contains(ch) && (delimiters & (1u64 << (*ch - b'+'))) != 0 {
                parts_len += pos - start_pos + 1;
                parts.push(&var[start_pos..pos]);
                start_pos = pos + 1;
            }
        }
        parts.push(&var[start_pos..var.len()]);

        let num_parts = if num_parts == 0 {
            parts.len()
        } else {
            std::cmp::min(parts.len(), num_parts as usize)
        };

        let mut result = Vec::with_capacity(parts_len + var.len() - start_pos);
        if !reverse {
            for (pos, part) in parts.iter().skip(parts.len() - num_parts).enumerate() {
                add_part(&mut result, part, pos, escape);
            }
        } else {
            for (pos, part) in parts.iter().rev().skip(parts.len() - num_parts).enumerate() {
                add_part(&mut result, part, pos, escape);
            }
        }
        if fqdn && result.last().unwrap_or(&0) != &b'.' {
            result.push(b'.');
        }
        result.into()
    }
}

#[inline(always)]
fn add_part(result: &mut Vec<u8>, part: &[u8], pos: usize, escape: bool) {
    if pos > 0 {
        result.push(b'.');
    }
    if !escape {
        result.extend_from_slice(part);
    } else {
        for ch in part {
            if ch.is_ascii_alphanumeric() || [b'-', b'.', b'_', b'~'].contains(ch) {
                result.push(*ch);
            } else {
                result.extend_from_slice(format!("%{ch:02x}").as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::spf::{parse::SPFParser, Variables};

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
