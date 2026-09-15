/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::SystemTime;
use crate::{
    AuthenticatedMessage, DkimOutput, DkimResult, Error, MX, MessageAuthenticator, Parameters,
    RecordSet, ResolverCache, Txt,
    common::{
        base32::Base32Writer,
        cache::NoCache,
        headers::Writer,
        verify::{DomainKey, VerifySignature},
    },
    is_within_pct,
};
use crate::{DnsError, common::crypto::CryptoError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    Atps, DkimError, DomainKeyReport, Flag, HashAlgorithm, RR_DNS, RR_EXPIRATION, RR_OTHER,
    RR_SIGNATURE, RR_VERIFICATION, Signature,
};

impl MessageAuthenticator {
    /// Verifies DKIM headers of an RFC5322 message.
    #[inline(always)]
    pub async fn verify_dkim<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> Vec<DkimOutput<'x>>
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
    {
        let params = params.into();
        let signature_time_check = params.params.check_signature_from_epoch.unwrap_or(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        );
        self.verify_dkim_(
            params,
            signature_time_check
        )
        .await
    }

    pub(crate) async fn verify_dkim_<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>,
        now: u64,
    ) -> Vec<DkimOutput<'x>>
    where
        TXT: ResolverCache<Box<str>, Txt>,
        MXX: ResolverCache<Box<str>, RecordSet<MX>>,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>>,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>>,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>>,
    {
        let message = params.params;
        let mut output = Vec::with_capacity(message.dkim_headers.len() + message.errors.len());
        let mut report_requested = false;

        // Surface malformed DKIM signatures
        for header in &message.errors {
            if let Error::Dkim(_) = &header.header {
                output.push(DkimOutput::neutral(header.header.clone()));
            }
        }

        // Validate DKIM headers
        for header in &message.dkim_headers {
            let signature = &header.header;
            if signature.r {
                report_requested = true;
            }

            if !(signature.x == 0 || (signature.x > signature.t && signature.x > now)) {
                output.push(
                    DkimOutput::neutral(Error::Dkim(DkimError::SignatureExpired))
                        .with_signature(signature),
                );
                continue;
            }

            // Validate body hash
            let ha = HashAlgorithm::from(signature.a);
            let bh = &message
                .body_hashes
                .iter()
                .find(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                .unwrap()
                .3;

            if bh != &signature.bh {
                output.push(
                    DkimOutput::neutral(Error::Dkim(DkimError::FailedBodyHashMatch))
                        .with_signature(signature),
                );
                continue;
            }

            // Obtain ._domainkey TXT record
            let record = match self
                .txt_lookup::<DomainKey>(signature.domain_key(), params.cache_txt)
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    output.push(DkimOutput::dns_error(err).with_signature(signature));
                    continue;
                }
            };

            // Enforce t=s flag
            if !signature.validate_auid(&record) {
                output.push(
                    DkimOutput::fail(Error::Dkim(DkimError::FailedAuidMatch))
                        .with_signature(signature),
                );
                continue;
            }

            // Hash headers
            let dkim_hdr_value = header.value.strip_signature();
            let mut headers = message.signed_headers(&signature.h, header.name, &dkim_hdr_value);

            // Verify signature
            if let Err(err) = record.verify(&mut headers, signature, signature.ch) {
                output.push(DkimOutput::fail(err).with_signature(signature));
                continue;
            }

            // Verify third-party signature, if any.
            if let Some(atps) = &signature.atps {
                let mut found = false;
                // RFC5322.From has to match atps=
                for from in &message.from {
                    if let Some((_, domain)) = from.rsplit_once('@')
                        && domain.eq(atps)
                    {
                        found = true;
                        break;
                    }
                }

                if found {
                    let mut query_domain = match &signature.atpsh {
                        Some(algorithm) => {
                            let mut writer = Base32Writer::with_capacity(40);
                            let output = algorithm.hash(signature.d.as_bytes());
                            writer.write(output.as_ref());
                            writer.finalize()
                        }
                        None => signature.d.to_string(),
                    };
                    query_domain.push_str("._atps.");
                    query_domain.push_str(atps);
                    query_domain.push('.');

                    match self
                        .txt_lookup::<Atps>(query_domain, params.cache_txt)
                        .await
                    {
                        Ok(_) => {
                            // ATPS Verification successful
                            output.push(DkimOutput::pass().with_atps().with_signature(signature));
                        }
                        Err(err) => {
                            output.push(
                                DkimOutput::dns_error(err)
                                    .with_atps()
                                    .with_signature(signature),
                            );
                        }
                    }
                    continue;
                }
            }

            // Verification successful
            output.push(DkimOutput::pass().with_signature(signature));
        }

        // Handle reports
        if report_requested {
            for dkim in &mut output {
                // Process signatures with errors that requested reports
                let signature = if let Some(signature) = &dkim.signature {
                    if signature.r && dkim.result != DkimResult::Pass {
                        signature
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                // Obtain ._domainkey TXT record
                let record = if let Ok(record) = self
                    .txt_lookup::<DomainKeyReport>(
                        format!("_report._domainkey.{}.", signature.d),
                        params.cache_txt,
                    )
                    .await
                {
                    if is_within_pct(record.rp) {
                        record
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                // Set report address
                dkim.report = match &dkim.result() {
                    DkimResult::Neutral(err)
                    | DkimResult::Fail(err)
                    | DkimResult::PermError(err)
                    | DkimResult::TempError(err) => {
                        let send_report = match err {
                            Error::Crypto(CryptoError::Library(_))
                            | Error::Io(_)
                            | Error::Crypto(CryptoError::FailedVerification)
                            | Error::Dkim(DkimError::FailedBodyHashMatch)
                            | Error::Dkim(DkimError::FailedAuidMatch) => {
                                (record.rr & RR_VERIFICATION) != 0
                            }
                            Error::Base64
                            | Error::Dkim(DkimError::UnsupportedVersion)
                            | Error::Dkim(DkimError::UnsupportedAlgorithm)
                            | Error::Dkim(DkimError::UnsupportedCanonicalization)
                            | Error::Dkim(DkimError::UnsupportedKeyType)
                            | Error::Crypto(CryptoError::IncompatibleAlgorithms) => {
                                (record.rr & RR_SIGNATURE) != 0
                            }
                            Error::Dkim(DkimError::SignatureExpired) => {
                                (record.rr & RR_EXPIRATION) != 0
                            }
                            Error::Dns(DnsError::Resolver(_))
                            | Error::Dns(DnsError::RecordNotFound(_))
                            | Error::Dns(DnsError::InvalidRecordType)
                            | Error::ParseError
                            | Error::Dkim(DkimError::RevokedPublicKey) => (record.rr & RR_DNS) != 0,
                            #[cfg(feature = "arc")]
                            Error::Arc(_) => (record.rr & RR_OTHER) != 0,
                            Error::MissingParameters
                            | Error::NoHeadersFound
                            | Error::Dkim(DkimError::SignatureLength)
                            | Error::NotAligned
                            | Error::Dkim2(_) => (record.rr & RR_OTHER) != 0,
                        };

                        if send_report {
                            format!("{}@{}", record.ra, signature.d).into()
                        } else {
                            None
                        }
                    }
                    DkimResult::None | DkimResult::Pass => None,
                };
            }
        }

        output
    }
}

impl<'x> AuthenticatedMessage<'x> {
    pub async fn get_canonicalized_header(&self) -> Result<Vec<u8>, Error> {
        // Based on verify_dkim_ function
        // Iterate through possible DKIM headers
        let mut data = Vec::with_capacity(256);
        for header in &self.dkim_headers {
            // Ensure signature is not obviously invalid
            let signature = &header.header;
            if !(signature.x == 0 || (signature.x > signature.t)) {
                continue;
            }

            // Get pre-hashed but canonically ordered headers, who's hash is signed
            let dkim_hdr_value = header.value.strip_signature();
            let headers = self.signed_headers(&signature.h, header.name, &dkim_hdr_value);
            signature.ch.canonicalize_headers(headers, &mut data);

            return Ok(data);
        }
        // Return not ok
        Err(Error::Dkim(DkimError::FailedBodyHashMatch))
    }

    pub fn signed_headers<'z: 'x>(
        &'z self,
        headers: &'x [String],
        dkim_hdr_name: &'x [u8],
        dkim_hdr_value: &'x [u8],
    ) -> impl Iterator<Item = (&'x [u8], &'x [u8])> {
        let mut last_header_pos: Vec<(&[u8], usize)> = Vec::with_capacity(headers.len());
        headers
            .iter()
            .filter_map(move |h| {
                let name = h.as_bytes();
                let slot = match last_header_pos
                    .iter()
                    .position(|(lh, _)| lh.eq_ignore_ascii_case(name))
                {
                    Some(slot) => slot,
                    None => {
                        last_header_pos.push((name, 0));
                        last_header_pos.len() - 1
                    }
                };
                let header_pos = last_header_pos.get(slot).map_or(0, |(_, pos)| *pos);
                let (next_pos, result) = match self
                    .headers
                    .iter()
                    .rev()
                    .enumerate()
                    .skip(header_pos)
                    .find(|(_, (mh, _))| name.eq_ignore_ascii_case(mh))
                {
                    Some((last_pos, result)) => (last_pos + 1, Some(*result)),
                    None => (self.headers.len(), None),
                };
                if let Some((_, pos)) = last_header_pos.get_mut(slot) {
                    *pos = next_pos;
                }
                result
            })
            .chain([(dkim_hdr_name, dkim_hdr_value)])
    }
}

impl Signature {
    pub(crate) fn validate_auid(&self, record: &DomainKey) -> bool {
        if self.i.is_empty() {
            return true;
        }

        let auid_domain = self
            .i
            .split_once('@')
            .map_or("", |(_, auid_domain)| auid_domain)
            .as_bytes();
        let domain = self.d.as_bytes();

        match auid_domain
            .len()
            .checked_sub(domain.len())
            .and_then(|split| auid_domain.split_at_checked(split))
        {
            Some((parent, suffix)) if suffix.eq_ignore_ascii_case(domain) => {
                parent.is_empty() || (!record.has_flag(Flag::MatchDomain) && parent.ends_with(b"."))
            }
            _ => false,
        }
    }
}

pub(crate) trait Verifier: Sized {
    fn strip_signature(&self) -> Vec<u8>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TagState {
    Semicolon,
    Tag,
    Value,
    Signature,
}

fn strip_tag_segment(
    segment: &[u8],
    terminated: bool,
    state: TagState,
    unsigned_dkim: &mut Vec<u8>,
) -> TagState {
    if state != TagState::Semicolon {
        unsigned_dkim.extend_from_slice(segment);
        return if terminated {
            TagState::Semicolon
        } else {
            state
        };
    }

    let tag = segment
        .iter()
        .position(|ch| !ch.is_ascii_whitespace())
        .unwrap_or(segment.len());

    if !matches!(segment.get(tag), Some(b'b' | b'B')) {
        unsigned_dkim.extend_from_slice(segment);
        return if terminated || tag == segment.len() {
            TagState::Semicolon
        } else {
            TagState::Value
        };
    }

    let after_tag = &segment[tag + 1..];
    let equals = after_tag
        .iter()
        .position(|ch| !ch.is_ascii_whitespace())
        .unwrap_or(after_tag.len());

    if after_tag.get(equals) != Some(&b'=') {
        unsigned_dkim.extend_from_slice(segment);
        return if terminated {
            TagState::Semicolon
        } else if equals == after_tag.len() {
            TagState::Tag
        } else {
            TagState::Value
        };
    }

    unsigned_dkim.extend_from_slice(&segment[..tag + equals + 2]);
    if terminated {
        unsigned_dkim.push(b';');
        TagState::Value
    } else {
        TagState::Signature
    }
}

fn strip_tag_list(mut rest: &[u8], unsigned_dkim: &mut Vec<u8>) -> TagState {
    let mut state = TagState::Semicolon;
    loop {
        match memchr::memchr(b';', rest) {
            Some(position) => {
                let (segment, tail) = rest.split_at(position + 1);
                state = strip_tag_segment(segment, true, state, unsigned_dkim);
                rest = tail;
            }
            None => return strip_tag_segment(rest, false, state, unsigned_dkim),
        }
    }
}

fn strip_trailing_byte(ch: u8, discard: bool, state: &mut TagState, unsigned_dkim: &mut Vec<u8>) {
    if *state == TagState::Signature {
        if ch == b';' {
            unsigned_dkim.push(b';');
            *state = TagState::Semicolon;
        }
        return;
    }

    match ch {
        b'=' if *state == TagState::Tag => {
            unsigned_dkim.push(ch);
            *state = TagState::Signature;
        }
        b'b' | b'B' if *state == TagState::Semicolon => {
            unsigned_dkim.push(ch);
            *state = TagState::Tag;
        }
        b';' => {
            unsigned_dkim.push(ch);
            *state = TagState::Semicolon;
        }
        _ if discard => (),
        _ => {
            unsigned_dkim.push(ch);
            if !ch.is_ascii_whitespace() {
                *state = TagState::Value;
            }
        }
    }
}

impl Verifier for &[u8] {
    fn strip_signature(&self) -> Vec<u8> {
        let mut unsigned_dkim = Vec::with_capacity(self.len());
        let (head, tail) = match self.len() {
            0 => return unsigned_dkim,
            1 => self.split_at(0),
            len => self.split_at(len - 2),
        };

        let mut state = strip_tag_list(head, &mut unsigned_dkim);
        match tail {
            [cr, lf] => {
                strip_trailing_byte(*cr, *cr == b'\r', &mut state, &mut unsigned_dkim);
                strip_trailing_byte(*lf, *lf == b'\n', &mut state, &mut unsigned_dkim);
            }
            [lf] => strip_trailing_byte(*lf, *lf == b'\n', &mut state, &mut unsigned_dkim),
            _ => (),
        }

        unsigned_dkim
    }
}

impl<'x> From<&'x AuthenticatedMessage<'x>>
    for Parameters<
        'x,
        &'x AuthenticatedMessage<'x>,
        NoCache<Box<str>, Txt>,
        NoCache<Box<str>, RecordSet<MX>>,
        NoCache<Box<str>, RecordSet<Ipv4Addr>>,
        NoCache<Box<str>, RecordSet<Ipv6Addr>>,
        NoCache<IpAddr, RecordSet<Box<str>>>,
    >
{
    fn from(params: &'x AuthenticatedMessage<'x>) -> Self {
        Parameters::new(params)
    }
}

#[cfg(test)]
#[allow(unused)]
pub mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use mail_parser::MessageParser;

    use crate::{
        AuthenticatedMessage, DkimResult, MessageAuthenticator,
        common::{cache::test::DummyCaches, parse::TxtRecordParser, verify::DomainKey},
        dkim::{Signature, verify::Verifier},
    };

    #[test]
    fn validate_auid() {
        let strict = DomainKey::parse(
            b"v=DKIM1; k=ed25519; t=s; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        )
        .unwrap();
        let relaxed =
            DomainKey::parse(b"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
                .unwrap();

        for (auid, strict_expected, relaxed_expected) in [
            ("", true, true),
            ("@example.com", true, true),
            ("john@example.com", true, true),
            ("@EXAMPLE.com", true, true),
            ("@sub.example.com", false, true),
            ("john@deep.sub.example.com", false, true),
            ("@example.com.evil", false, false),
            ("@xexample.com", false, false),
            ("@other.org", false, false),
            ("john", false, false),
            ("@", false, false),
        ] {
            let signature = Signature {
                i: auid.to_string(),
                d: "example.com".to_string(),
                ..Default::default()
            };
            assert_eq!(
                signature.validate_auid(&strict),
                strict_expected,
                "t=s {auid:?}"
            );
            assert_eq!(
                signature.validate_auid(&relaxed),
                relaxed_expected,
                "{auid:?}"
            );
        }
    }

    #[tokio::test]
    async fn dkim_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("dkim");
        let resolver = MessageAuthenticator::new_system_conf().unwrap();

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            /*if !file_name.to_str().unwrap().contains("002") {
                continue;
            }*/
            println!("DKIM verifying {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, raw_message) = test.split_once("\n\n").unwrap();
            let caches = new_cache(dns_records);
            let raw_message = raw_message.replace('\n', "\r\n");
            let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
            assert_eq!(
                message,
                AuthenticatedMessage::from_parsed(
                    &MessageParser::new().parse(&raw_message).unwrap(),
                    raw_message.as_bytes(),
                    true
                )
            );

            let dkim = resolver
                .verify_dkim_(caches.parameters(&message), 1667843664)
                .await;

            assert_eq!(dkim.last().unwrap().result(), &DkimResult::Pass);
        }
    }

    #[test]
    fn dkim_strip_signature() {
        for (value, stripped_value) in [
            ("b=abc;h=From\r\n", "b=;h=From"),
            ("bh=B64b=;h=From;b=abc\r\n", "bh=B64b=;h=From;b="),
            ("h=From; b = abc\r\ndef\r\n; v=1\r\n", "h=From; b =; v=1"),
            ("B\r\n=abc;v=1\r\n", "B\r\n=;v=1"),
        ] {
            assert_eq!(
                String::from_utf8(value.as_bytes().strip_signature()).unwrap(),
                stripped_value
            );
        }
    }

    pub(crate) fn new_cache(dns_records: &str) -> DummyCaches {
        let caches = DummyCaches::new();
        for (key, value) in dns_records
            .split('\n')
            .filter_map(|r| r.split_once(' ').map(|(a, b)| (a, b.as_bytes())))
        {
            caches.txt_add(
                format!("{key}."),
                DomainKey::parse(value).unwrap(),
                Instant::now() + Duration::new(3200, 0),
            );
        }

        caches
    }
}
