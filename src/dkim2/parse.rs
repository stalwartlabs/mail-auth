/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsing of `DKIM2-Signature` (§10) and `Message-Instance` (§9) header
//! field values, which are Tag=Value lists (§8).

use super::{
    ChainBinding, Dkim2Error, Dkim2Hash, Flag, HashName, MessageHash, MessageInstance, Signature,
    SignatureValue, canonicalize::cmp_ignore_ascii_case, recipe::Recipe,
};
use crate::{Error, crypto::Algorithm};
use encodify::base64;
use memchr::memchr;
use std::collections::HashSet;

const MAX_NONCE_LEN: usize = 64;
const MAX_LABEL_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_ENTRIES_PER_ALGORITHM: usize = 2;
const INLINE_SCAN_LIMIT: usize = 16;

#[derive(Clone, Copy)]
#[repr(u8)]
enum SignatureTag {
    I,
    M,
    T,
    D,
    S,
    Mf,
    Rt,
    Nd,
    N,
    F,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum InstanceTag {
    M,
    H,
    R,
}

impl SignatureTag {
    fn parse(name: &[u8]) -> Option<Self> {
        hashify::map!(name, SignatureTag,
            b"i" => SignatureTag::I,
            b"m" => SignatureTag::M,
            b"t" => SignatureTag::T,
            b"d" => SignatureTag::D,
            b"s" => SignatureTag::S,
            b"mf" => SignatureTag::Mf,
            b"rt" => SignatureTag::Rt,
            b"nd" => SignatureTag::Nd,
            b"n" => SignatureTag::N,
            b"f" => SignatureTag::F,
        )
        .copied()
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

impl InstanceTag {
    fn parse(name: &[u8]) -> Option<Self> {
        hashify::map!(name, InstanceTag,
            b"m" => InstanceTag::M,
            b"h" => InstanceTag::H,
            b"r" => InstanceTag::R,
        )
        .copied()
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

#[derive(Default)]
struct SeenTags<'x> {
    known: u16,
    unknown: Vec<&'x [u8]>,
    unknown_set: HashSet<&'x [u8]>,
}

impl<'x> SeenTags<'x> {
    fn insert_known(&mut self, bit: u16) -> bool {
        let fresh = self.known & bit == 0;
        self.known |= bit;
        fresh
    }

    fn contains_known(&self, bit: u16) -> bool {
        self.known & bit != 0
    }

    fn insert_unknown(&mut self, name: &'x [u8]) -> bool {
        if !self.unknown_set.is_empty() {
            return self.unknown_set.insert(name);
        } else if self.unknown.contains(&name) {
            return false;
        }
        self.unknown.push(name);
        if self.unknown.len() > INLINE_SCAN_LIMIT {
            self.unknown_set.extend(self.unknown.drain(..));
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
enum ParseError {
    Syntax,
    TagMissing(&'static str),
    TagUnexpected(&'static str),
    DuplicateSelector,
    TooManySelectors,
    DuplicateHash,
    InvalidJson,
}

impl ParseError {
    #[cold]
    fn into_signature_error(self, header: &[u8]) -> Error {
        let i = tag_number(header, b"i");
        Error::Dkim2(match self {
            ParseError::TagMissing(tag) => Dkim2Error::SignatureTagMissing { i, tag },
            ParseError::TagUnexpected(tag) => Dkim2Error::SignatureTagUnexpected { i, tag },
            ParseError::DuplicateSelector => Dkim2Error::DuplicateSelector(i),
            ParseError::TooManySelectors => Dkim2Error::TooManySelectors(i),
            ParseError::Syntax | ParseError::DuplicateHash | ParseError::InvalidJson => {
                Dkim2Error::SignatureSyntax(i)
            }
        })
    }

    #[cold]
    fn into_instance_error(self, header: &[u8]) -> Error {
        let m = tag_number(header, b"m");
        Error::Dkim2(match self {
            ParseError::TagMissing(tag) => Dkim2Error::InstanceTagMissing { m, tag },
            ParseError::DuplicateHash => Dkim2Error::InstanceDuplicateHash(m),
            ParseError::InvalidJson => Dkim2Error::InvalidJson(m),
            ParseError::Syntax
            | ParseError::TagUnexpected(_)
            | ParseError::DuplicateSelector
            | ParseError::TooManySelectors => Dkim2Error::InstanceSyntax(m),
        })
    }
}

impl Signature {
    /// Parses a single `DKIM2-Signature` header field value (without the
    /// field name).
    ///
    /// The value is a Tag=Value list (§8): tag names are case-sensitive,
    /// unrecognized tags (including upper-case variants of known ones) are
    /// ignored, and a repeated tag name invalidates the field. `s=` entries
    /// with an algorithm this crate does not implement are dropped after the
    /// selector checks, so `s` can be empty. `mf=` and `rt=` are
    /// base64-decoded.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::SignatureSyntax`] for a malformed tag list or
    /// value, a repeated tag or a nonce that is not up to 64 printable ASCII
    /// characters; [`Dkim2Error::DuplicateSelector`] or
    /// [`Dkim2Error::TooManySelectors`] when `s=` repeats a selector or has
    /// more than two entries for one algorithm;
    /// [`Dkim2Error::SignatureTagMissing`] if `i=`, `m=`, `t=`, `d=` or `s=`
    /// is missing, or if neither `nd=` nor both `mf=` and `rt=` are present;
    /// and [`Dkim2Error::SignatureTagUnexpected`] if `nd=` appears together
    /// with `mf=` or `rt=`.
    pub fn parse(header: &[u8]) -> crate::Result<Signature> {
        parse_signature(header).map_err(|err| err.into_signature_error(header))
    }
}

fn parse_signature(header: &[u8]) -> Result<Signature, ParseError> {
    let mut signature = Signature::default();
    let mut seen = SeenTags::default();
    let mut mail_from = None;
    let mut rcpt_to = None;
    let mut next_domain = None;

    for spec in tag_list(header) {
        let (name, value) = spec.ok_or(ParseError::Syntax)?;
        let Some(tag) = SignatureTag::parse(name) else {
            if is_tag_value(value) && seen.insert_unknown(name) {
                continue;
            }
            return Err(ParseError::Syntax);
        };
        if !seen.insert_known(tag.bit()) {
            return Err(ParseError::Syntax);
        }
        match tag {
            SignatureTag::I => signature.i = parse_number(value).ok_or(ParseError::Syntax)?,
            SignatureTag::M => signature.m = parse_number(value).ok_or(ParseError::Syntax)?,
            SignatureTag::T => signature.t = parse_number(value).ok_or(ParseError::Syntax)?,
            SignatureTag::D => signature.d = parse_domain(value).ok_or(ParseError::Syntax)?,
            SignatureTag::S => signature.s = parse_signature_values(value)?,
            SignatureTag::Mf => mail_from = Some(decode_string(value)?),
            SignatureTag::Rt => {
                rcpt_to = Some(
                    split_bytes(value, b',')
                        .map(decode_string)
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            SignatureTag::Nd => next_domain = Some(parse_domain(value).ok_or(ParseError::Syntax)?),
            SignatureTag::N => signature.n = Some(parse_nonce(value).ok_or(ParseError::Syntax)?),
            SignatureTag::F => signature.flags = parse_flags(value)?,
        }
    }

    for (tag, name) in [
        (SignatureTag::I, "i"),
        (SignatureTag::M, "m"),
        (SignatureTag::T, "t"),
        (SignatureTag::D, "d"),
        (SignatureTag::S, "s"),
    ] {
        if !seen.contains_known(tag.bit()) {
            return Err(ParseError::TagMissing(name));
        }
    }

    signature.chain = match (next_domain, mail_from, rcpt_to) {
        (Some(domain), None, None) => ChainBinding::NextDomain(domain),
        (Some(_), _, _) => return Err(ParseError::TagUnexpected("nd")),
        (None, Some(mail_from), Some(rcpt_to)) => ChainBinding::Envelope { mail_from, rcpt_to },
        (None, None, _) => return Err(ParseError::TagMissing("mf")),
        (None, Some(_), None) => return Err(ParseError::TagMissing("rt")),
    };

    Ok(signature)
}

impl MessageInstance {
    /// Parses a single `Message-Instance` header field value (without the
    /// field name).
    ///
    /// The value is a Tag=Value list (§8) with the same rules as
    /// [`Signature::parse`]. Hash names are case-sensitive; unsupported ones
    /// are kept as [`HashName::Unknown`]. The `r=` recipe is base64-decoded
    /// and parsed and validated as JSON (§5).
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::InstanceSyntax`] for a malformed tag list or
    /// value or a repeated tag, [`Dkim2Error::InstanceTagMissing`] if `m=`
    /// or `h=` is missing, [`Dkim2Error::InstanceDuplicateHash`] if `h=`
    /// repeats a hash algorithm, and [`Dkim2Error::InvalidJson`] if the
    /// recipe is not valid JSON or does not follow the recipe schema.
    pub fn parse(header: &[u8]) -> crate::Result<MessageInstance> {
        parse_instance(header).map_err(|err| err.into_instance_error(header))
    }
}

fn parse_instance(header: &[u8]) -> Result<MessageInstance, ParseError> {
    let mut instance = MessageInstance::default();
    let mut seen = SeenTags::default();

    for spec in tag_list(header) {
        let (name, value) = spec.ok_or(ParseError::Syntax)?;
        let Some(tag) = InstanceTag::parse(name) else {
            if is_tag_value(value) && seen.insert_unknown(name) {
                continue;
            }
            return Err(ParseError::Syntax);
        };
        if !seen.insert_known(tag.bit()) {
            return Err(ParseError::Syntax);
        }
        match tag {
            InstanceTag::M => instance.m = parse_number(value).ok_or(ParseError::Syntax)?,
            InstanceTag::H => instance.hashes = parse_hashes(value)?,
            InstanceTag::R => {
                let json = base64::LENIENT
                    .decode(value)
                    .map_err(|_| ParseError::Syntax)?;
                instance.recipe =
                    Some(Recipe::from_json(&json).map_err(|_| ParseError::InvalidJson)?);
            }
        }
    }

    for (tag, name) in [(InstanceTag::M, "m"), (InstanceTag::H, "h")] {
        if !seen.contains_known(tag.bit()) {
            return Err(ParseError::TagMissing(name));
        }
    }

    Ok(instance)
}

fn tag_list(header: &[u8]) -> impl Iterator<Item = Option<(&[u8], &[u8])>> {
    split_bytes(header, b';')
        .map(<[u8]>::trim_ascii)
        .filter(|spec| !spec.is_empty())
        .map(tag_spec)
}

fn split_bytes(value: &[u8], separator: u8) -> SplitBytes<'_> {
    SplitBytes {
        rest: Some(value),
        separator,
    }
}

struct SplitBytes<'x> {
    rest: Option<&'x [u8]>,
    separator: u8,
}

impl<'x> Iterator for SplitBytes<'x> {
    type Item = &'x [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (part, rest) = split_at_byte(self.rest?, self.separator);
        self.rest = rest;
        Some(part)
    }
}

fn split_at_byte(value: &[u8], separator: u8) -> (&[u8], Option<&[u8]>) {
    match memchr(separator, value) {
        Some(pos) => (
            value.get(..pos).unwrap_or_default(),
            Some(value.get(pos + 1..).unwrap_or_default()),
        ),
        None => (value, None),
    }
}

fn tag_spec(spec: &[u8]) -> Option<(&[u8], &[u8])> {
    let (name, value) = split_at_byte(spec, b'=');
    let (name, value) = (name.trim_ascii(), value?.trim_ascii());
    let (first, rest) = name.split_first()?;
    (first.is_ascii_alphabetic()
        && rest
            .iter()
            .all(|&ch| ch.is_ascii_alphanumeric() || ch == b'_'))
    .then_some((name, value))
}

fn is_tag_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&ch| ch.is_ascii_graphic() || matches!(ch, b' ' | b'\t' | b'\r' | b'\n'))
}

#[cold]
fn tag_number(header: &[u8], tag: &[u8]) -> u32 {
    tag_list(header)
        .flatten()
        .find(|(name, _)| *name == tag)
        .and_then(|(_, value)| parse_number(value))
        .unwrap_or(0)
}

fn parse_number<T: TryFrom<u64>>(value: &[u8]) -> Option<T> {
    if value.is_empty() {
        return None;
    }
    value
        .iter()
        .try_fold(0u64, |acc, &ch| {
            ch.is_ascii_digit()
                .then(|| acc.checked_mul(10)?.checked_add(u64::from(ch - b'0')))
                .flatten()
        })
        .and_then(|number| T::try_from(number).ok())
}

fn parse_domain(value: &[u8]) -> Option<String> {
    is_dns_name(value).then(|| String::from_utf8_lossy(value).to_ascii_lowercase())
}

fn is_dns_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DOMAIN_LEN
        && split_bytes(value, b'.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && label
                    .iter()
                    .all(|&ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_'))
        })
}

pub(crate) fn is_domain(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DOMAIN_LEN
        && split_bytes(value, b'.').all(|label| label.len() <= MAX_LABEL_LEN)
        && split_bytes(value, b'.').all(|label| match label {
            [first, middle @ .., last] => {
                first.is_ascii_alphanumeric()
                    && last.is_ascii_alphanumeric()
                    && middle
                        .iter()
                        .all(|&ch| ch.is_ascii_alphanumeric() || ch == b'-')
            }
            [single] => single.is_ascii_alphanumeric(),
            [] => false,
        })
}

fn parse_nonce(value: &[u8]) -> Option<String> {
    (value.len() <= MAX_NONCE_LEN && value.iter().all(u8::is_ascii_graphic))
        .then(|| String::from_utf8_lossy(value).into_owned())
}

pub(crate) fn is_textstring(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|&ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_'))
}

fn decode_string(value: &[u8]) -> Result<String, ParseError> {
    base64::LENIENT
        .decode_to_string(value)
        .map_err(|_| ParseError::Syntax)
}

fn parse_flags(value: &[u8]) -> Result<Vec<Flag>, ParseError> {
    split_bytes(value, b',')
        .map(<[u8]>::trim_ascii)
        .filter(|flag| !flag.is_empty())
        .map(|flag| {
            is_textstring(flag)
                .then(|| Flag::parse_bytes(flag))
                .ok_or(ParseError::Syntax)
        })
        .collect()
}

fn parse_signature_values(value: &[u8]) -> Result<Vec<SignatureValue>, ParseError> {
    let mut values = Vec::with_capacity(2);
    let mut inline: [(&[u8], &[u8]); INLINE_SCAN_LIMIT] = [(&[], &[]); INLINE_SCAN_LIMIT];
    let mut spill = Vec::new();
    let mut count = 0;
    for set in split_bytes(value, b',') {
        let (selector, algorithm, signature) = split_triple(set).ok_or(ParseError::Syntax)?;
        if !is_dns_name(selector) || !is_textstring(algorithm) {
            return Err(ParseError::Syntax);
        }
        match inline.get_mut(count) {
            Some(slot) => *slot = (selector, algorithm),
            None => {
                if spill.is_empty() {
                    spill.extend_from_slice(&inline);
                }
                spill.push((selector, algorithm));
            }
        }
        count += 1;

        let Some(algorithm) = Algorithm::parse_dkim2(algorithm) else {
            continue;
        };
        let b = if signature.is_empty() {
            Vec::new()
        } else {
            base64::LENIENT
                .decode(signature)
                .map_err(|_| ParseError::Syntax)?
        };
        values.push(SignatureValue {
            selector: String::from_utf8_lossy(selector).into_owned(),
            a: algorithm,
            b,
        });
    }

    if spill.is_empty() {
        check_selectors_inline(inline.get(..count).unwrap_or_default())?;
    } else {
        check_selectors_sorted(&mut spill)?;
    }
    Ok(values)
}

fn check_selectors_inline(entries: &[(&[u8], &[u8])]) -> Result<(), ParseError> {
    for (pos, (selector, algorithm)) in entries.iter().enumerate() {
        let mut same_algorithm = 1;
        for (other_selector, other_algorithm) in entries.iter().skip(pos + 1) {
            if selector.eq_ignore_ascii_case(other_selector) {
                return Err(ParseError::DuplicateSelector);
            }
            same_algorithm += usize::from(algorithm == other_algorithm);
        }
        if same_algorithm > MAX_ENTRIES_PER_ALGORITHM {
            return Err(ParseError::TooManySelectors);
        }
    }
    Ok(())
}

fn check_selectors_sorted(entries: &mut [(&[u8], &[u8])]) -> Result<(), ParseError> {
    entries.sort_unstable_by(|(a, _), (b, _)| cmp_ignore_ascii_case(a, b));
    if entries
        .windows(2)
        .any(|pair| matches!(pair, [(a, _), (b, _)] if a.eq_ignore_ascii_case(b)))
    {
        return Err(ParseError::DuplicateSelector);
    }
    entries.sort_unstable_by_key(|(_, algorithm)| *algorithm);
    if entries.windows(MAX_ENTRIES_PER_ALGORITHM + 1).any(|run| {
        run.iter()
            .all(|(_, algorithm)| run.first().is_some_and(|(_, first)| first == algorithm))
    }) {
        return Err(ParseError::TooManySelectors);
    }
    Ok(())
}

fn parse_hashes(value: &[u8]) -> Result<Vec<MessageHash>, ParseError> {
    let mut hashes = Vec::with_capacity(1);
    for set in split_bytes(value, b',') {
        let (name, header_hash, body_hash) = split_triple(set).ok_or(ParseError::Syntax)?;
        if !is_textstring(name) {
            return Err(ParseError::Syntax);
        }
        hashes.push(MessageHash {
            name: Dkim2Hash::parse(name).map_or_else(
                || HashName::Unknown(String::from_utf8_lossy(name).into()),
                HashName::Known,
            ),
            header_hash: base64::LENIENT
                .decode(header_hash)
                .map_err(|_| ParseError::Syntax)?,
            body_hash: base64::LENIENT
                .decode(body_hash)
                .map_err(|_| ParseError::Syntax)?,
        });
    }

    let unique = if hashes.len() <= INLINE_SCAN_LIMIT {
        hashes.iter().enumerate().all(|(pos, hash)| {
            hashes
                .iter()
                .skip(pos + 1)
                .all(|other| other.name.as_str() != hash.name.as_str())
        })
    } else {
        let mut names = hashes
            .iter()
            .map(|hash| hash.name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.windows(2).all(|pair| pair.first() != pair.last())
    };
    if unique {
        Ok(hashes)
    } else {
        Err(ParseError::DuplicateHash)
    }
}

fn split_triple(set: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (first, rest) = split_at_byte(set, b':');
    let (second, third) = split_at_byte(rest?, b':');
    Some((first.trim_ascii(), second.trim_ascii(), third?.trim_ascii()))
}

impl Flag {
    /// Parses one `f=` flag value. Flag names are case-sensitive;
    /// unrecognized values become [`Flag::Unknown`].
    pub fn parse(value: &str) -> Flag {
        Flag::parse_bytes(value.as_bytes())
    }

    fn parse_bytes(value: &[u8]) -> Flag {
        hashify::fnc_map!(value,
            b"feedback" => Some(Flag::Feedback),
            b"feedhere" => Some(Flag::FeedHere),
            b"exploded" => Some(Flag::Exploded),
            _ => None,
        )
        .unwrap_or_else(|| Flag::Unknown(String::from_utf8_lossy(value).into_owned()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::AuthenticatedMessage;
    use crate::dkim2::HashName;
    use mail_parser::MessageParser;

    #[test]
    fn from_parsed_classifies_dkim2_headers() {
        let raw = concat!(
            "DKIM2-Signature: i=1; m=1; t=1740000000; d=test4.dkim2.com; mf=PHNlbmRlckB0ZXN0NC5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:651OFNp+DdgjeVHm1EaEmnpcP6L9PWJczuJ5Oo9dzWPf0xnVgDLcVu4IMmNgW8stVVocIt7MBd8aL0Gc/lCsAA==;\r\n",
            "Message-Instance: m=1; h=sha256:WT8nqIyG8W1R78H1QT4oZdo1SKdQrY9JHQ4fMC+IXHU=:frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=;\r\n",
            "From: sender@test4.dkim2.com\r\n",
            "To: recipient@example.com\r\n",
            "\r\n",
            "body\r\n",
        )
        .as_bytes();

        let from_parsed =
            AuthenticatedMessage::from_parsed(&MessageParser::new().parse(raw).unwrap(), raw, true);
        assert_eq!(from_parsed.dkim2_signatures.len(), 1);
        assert_eq!(from_parsed.dkim2_instances.len(), 1);

        assert_eq!(from_parsed, AuthenticatedMessage::parse(raw).unwrap());
    }

    #[test]
    fn signature_parse_malformed_does_not_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"garbage no equals",
            b"i=; m=; t=; d=;",
            b"i=1; m=1; t=0; d=example.com; mf=; s=sel",
            b"i=1; m=1; t=0; d=example.com; mf=; s=",
            b"i=1; m=1; t=0; d=example.com; mf=; s=,,",
            b"i=1; m=1; t=0; d=example.com; mf=; s=sel:rsa-sha256:",
        ];
        for c in cases {
            let _ = Signature::parse(c);
        }
    }

    #[test]
    fn signature_parse_nd_with_envelope_is_rejected() {
        assert!(Signature::parse(b"nd=next.example; mf=a@b.com").is_err());
    }

    #[test]
    fn header_classification_no_false_positive() {
        let msg = b"DKIM2-Silly: foo\r\nMessage-Idle: bar\r\nFrom: a@b\r\n\r\nbody\r\n";
        let parsed = AuthenticatedMessage::parse(msg).unwrap();
        assert_eq!(parsed.dkim2_signatures.len(), 0);
        assert_eq!(parsed.dkim2_instances.len(), 0);
    }

    #[test]
    fn header_with_digit_parses() {
        let msg = b"X-Test1-Header: v\r\nFrom: a@b\r\n\r\nbody\r\n";
        let parsed = AuthenticatedMessage::parse(msg).unwrap();
        assert_eq!(parsed.headers().len(), 2);
    }

    #[test]
    fn signature_parse_reordered_tags_and_multi_sset() {
        let v = b"f=feedback; m=2; s=sel:rsa-sha256:AAAA,sel2:ed25519-sha256:BBBB; i=3; d=ex.com; mf=; rt=Yg==; t=5; xunknown=zz";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.i, 3);
        assert_eq!(sig.m, 2);
        assert_eq!(sig.s.len(), 2);
    }

    #[test]
    fn message_instance_parse_huge_recipe_does_not_panic_on_parse() {
        let json = br#"{"b":[{"c":[1,4294967295]}]}"#;
        let mut hdr = b"m=2; h=sha256:QQ==:Qg==; r=".to_vec();
        base64::STANDARD.encode_append(json, &mut hdr);
        let mi = MessageInstance::parse(&hdr).unwrap();
        assert!(mi.recipe.is_some());
    }

    #[test]
    fn signature_m_can_reach_u32_max() {
        let v: &[u8] =
            b"i=1; m=4294967295; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==; f=feedback;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.m, u32::MAX);
    }

    #[test]
    fn signature_parse_decodes_null_reverse_path() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=PD4=; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        if let ChainBinding::Envelope { mail_from, .. } = &sig.chain {
            assert_eq!(mail_from, "<>");
        } else {
            panic!("expected envelope chain");
        }
    }

    #[test]
    fn nonce_over_64_chars_is_rejected() {
        let long = "a".repeat(65);
        let v = format!("i=1; m=1; t=0; d=ex.com; mf=YQ==; n={long}; s=sel:rsa-sha256:QQ==;");
        assert!(matches!(
            Signature::parse(v.as_bytes()),
            Err(Error::Dkim2(Dkim2Error::SignatureSyntax(_)))
        ));
    }

    #[test]
    fn nonce_exactly_64_chars_is_accepted() {
        let n = "a".repeat(64);
        let v = format!("i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; n={n}; s=sel:rsa-sha256:QQ==;");
        let sig = Signature::parse(v.as_bytes()).unwrap();
        assert_eq!(sig.n.as_deref(), Some(n.as_str()));
    }

    #[test]
    fn duplicate_signature_tag_is_rejected() {
        let v: &[u8] = b"i=1; i=2; m=1; t=0; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureSyntax(_)))
        ));
    }

    // -07 §8: tag names are case-sensitive, so M= is an unknown tag and is ignored.
    #[test]
    fn upper_case_tags_are_unknown() {
        let v: &[u8] = b"i=1; m=1; M=2; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert_eq!(Signature::parse(v).unwrap().m, 1);
        assert!(matches!(
            Signature::parse(b"I=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;"),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "i",
                ..
            }))
        ));
    }

    // Unknown tags are compared by their full name: a repeat invalidates the list, a shared prefix does not.
    #[test]
    fn unknown_tag_duplicates() {
        let base = "i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert!(
            Signature::parse(format!("{base} longunknowntag1=a; longunknowntag2=b").as_bytes())
                .is_ok()
        );
        assert!(matches!(
            Signature::parse(format!("{base} x_y=a; x_y=b").as_bytes()),
            Err(Error::Dkim2(Dkim2Error::SignatureSyntax(1)))
        ));
        let many = (0..40).map(|n| format!("t{n}=v; ")).collect::<String>();
        assert!(Signature::parse(format!("{base} {many}").as_bytes()).is_ok());
        assert!(Signature::parse(format!("{base} {many} t7=v").as_bytes()).is_err());
        assert!(Signature::parse(format!("{base} 1x=v").as_bytes()).is_err());
        assert!(Signature::parse(format!("{base} novalue").as_bytes()).is_err());
    }

    #[test]
    fn selector_rules() {
        let sig = |s: &str| {
            Signature::parse(
                format!("i=7; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s={s};").as_bytes(),
            )
        };
        assert!(matches!(
            sig("a:rsa-sha256:QQ==,A:ed25519-sha256:QQ=="),
            Err(Error::Dkim2(Dkim2Error::DuplicateSelector(7)))
        ));
        assert!(matches!(
            sig("a:rsa-sha256:QQ==,b:rsa-sha256:QQ==,c:rsa-sha256:QQ=="),
            Err(Error::Dkim2(Dkim2Error::TooManySelectors(7)))
        ));
        assert!(matches!(
            sig("a:x-new:QQ==,b:x-new:QQ==,c:x-new:QQ==,d:ed25519-sha256:QQ=="),
            Err(Error::Dkim2(Dkim2Error::TooManySelectors(7)))
        ));
        let many = (0..20)
            .map(|n| format!("s{n}:alg{n}:QQ=="))
            .collect::<Vec<_>>()
            .join(",");
        assert!(sig(&many).is_ok());
        assert!(matches!(
            sig(&format!("{many},S3:x:QQ==")),
            Err(Error::Dkim2(Dkim2Error::DuplicateSelector(7)))
        ));
        assert!(matches!(
            sig(&format!("{many},z:alg3:QQ==,y:alg3:QQ==")),
            Err(Error::Dkim2(Dkim2Error::TooManySelectors(7)))
        ));

        let parsed = sig("a:mldsa44-ed25519-sha512:QQ==,b:RSA-SHA256:QQ==").unwrap();
        assert_eq!(parsed.s.len(), 1);
        assert_eq!(parsed.s[0].a, Algorithm::MlDsa44Ed25519Sha512);
    }

    #[test]
    fn message_instance_rules() {
        assert!(matches!(
            MessageInstance::parse(b"h=sha256:QQ==:QQ==;"),
            Err(Error::Dkim2(Dkim2Error::InstanceTagMissing {
                m: 0,
                tag: "m"
            }))
        ));
        assert!(matches!(
            MessageInstance::parse(b"m=3;"),
            Err(Error::Dkim2(Dkim2Error::InstanceTagMissing {
                m: 3,
                tag: "h"
            }))
        ));
        assert!(matches!(
            MessageInstance::parse(b"m=3; h=sha256:QQ==:QQ==,sha256:Qg==:Qg==;"),
            Err(Error::Dkim2(Dkim2Error::InstanceDuplicateHash(3)))
        ));
        let many = (0..20)
            .map(|n| format!("h{n}:QQ==:QQ=="))
            .collect::<Vec<_>>()
            .join(",");
        assert!(MessageInstance::parse(format!("m=3; h={many};").as_bytes()).is_ok());
        assert!(matches!(
            MessageInstance::parse(format!("m=3; h={many},h7:QQ==:QQ==;").as_bytes()),
            Err(Error::Dkim2(Dkim2Error::InstanceDuplicateHash(3)))
        ));
        let instance =
            MessageInstance::parse(b"m=3; h=sha512:QQ==:QQ==, SHA256:QQ==:QQ==, sha3:Qg==:Qg==;")
                .unwrap();
        assert_eq!(
            instance
                .hashes
                .iter()
                .map(|hash| hash.name.clone())
                .collect::<Vec<_>>(),
            vec![
                HashName::Known(Dkim2Hash::Sha512),
                HashName::Unknown("SHA256".into()),
                HashName::Unknown("sha3".into()),
            ]
        );
        let mut written = Vec::new();
        instance.write_value(&mut written);
        assert_eq!(MessageInstance::parse(&written).unwrap(), instance);
    }

    #[test]
    fn nonce_and_flag_syntax() {
        let sig = |extra: &str| {
            Signature::parse(
                format!(
                    "i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==; {extra}"
                )
                .as_bytes(),
            )
        };
        assert!(sig("n=two words").is_err());
        assert!(sig("n=caf\u{e9}").is_err());
        assert_eq!(
            sig("f=Exploded, feedhere").unwrap().flags,
            vec![Flag::Unknown("Exploded".into()), Flag::FeedHere]
        );
        assert!(sig("f=bad flag").is_err());
        let with_domain = |domain: &str| {
            Signature::parse(
                format!("i=1; m=1; t=0; d={domain}; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;")
                    .as_bytes(),
            )
        };
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = ["abcdefghi"; 26].join(".");
        assert!(with_domain(&format!("{}.com", "a".repeat(63))).is_ok());
        for domain in [
            "ex..com",
            ".",
            "ex.com.",
            ".ex.com",
            "e x.com",
            "ex/com",
            "ex.com\\",
            &long_label,
            &long_name,
        ] {
            assert!(with_domain(domain).is_err(), "{domain}");
        }
        for (domain, parsed) in [
            ("Mail-1.Ex.com", "mail-1.ex.com"),
            ("_dmarc_ish.ex.com", "_dmarc_ish.ex.com"),
            ("-ex.com", "-ex.com"),
        ] {
            assert_eq!(with_domain(domain).unwrap().d, parsed);
        }
        assert_eq!(
            Signature::parse(
                b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=my_sel.2024:rsa-sha256:QQ==;"
            )
            .unwrap()
            .s[0]
                .selector,
            "my_sel.2024"
        );
        assert!(
            Signature::parse(b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=a..b:rsa-sha256:QQ==;")
                .is_err()
        );
        assert!(sig("i=4294967296").is_err());
    }

    #[test]
    fn duplicate_message_instance_tag_is_rejected() {
        let v: &[u8] = b"m=1; m=2; h=sha256:QQ==:Qg==;";
        assert!(matches!(
            MessageInstance::parse(v),
            Err(Error::Dkim2(Dkim2Error::InstanceSyntax(_)))
        ));
    }

    #[test]
    fn missing_t_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "t",
                ..
            }))
        ));
    }

    #[test]
    fn missing_s_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "s",
                ..
            }))
        ));
    }

    #[test]
    fn nd_with_envelope_is_rejected_as_unexpected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; nd=next.example; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagUnexpected {
                tag: "nd",
                ..
            }))
        ));
    }

    #[test]
    fn unknown_algorithm_in_s_is_ignored() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=banana:banana:,sel:ed25519-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.s.len(), 1);
        assert_eq!(sig.s[0].selector, "sel");
    }

    #[test]
    fn only_unknown_algorithms_yields_empty_s() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=banana:banana:;";
        let sig = Signature::parse(v).unwrap();
        assert!(sig.s.is_empty());
    }

    #[test]
    fn mf_without_rt_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "rt",
                ..
            }))
        ));
    }

    #[test]
    fn rt_without_mf_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "mf",
                ..
            }))
        ));
    }

    #[test]
    fn missing_d_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "d",
                ..
            }))
        ));
    }

    #[test]
    fn neither_nd_nor_envelope_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "mf",
                ..
            }))
        ));
    }

    #[test]
    fn rsa_sha1_set_is_dropped() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha1:QQ==,sel2:ed25519-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.s.len(), 1);
        assert_eq!(sig.s[0].selector, "sel2");
    }

    #[test]
    fn only_rsa_sha1_yields_empty_s() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha1:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert!(sig.s.is_empty());
    }

    #[test]
    fn feedhere_flag_is_parsed() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==; f=feedback,feedhere;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.flags, vec![Flag::Feedback, Flag::FeedHere]);
    }
}
