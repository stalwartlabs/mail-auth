/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::SystemTime,
};

use crate::{
    common::{
        base32::Base32Writer,
        cache::NoCache,
        headers::Writer,
        verify::{DomainKey, VerifySignature},
    },
    is_within_pct, AuthenticatedMessage, DkimOutput, DkimResult, Error, MessageAuthenticator,
    Parameters, ResolverCache, Txt, MX,
};

use super::{
    Atps, DomainKeyReport, Flag, HashAlgorithm, Signature, RR_DNS, RR_EXPIRATION, RR_OTHER,
    RR_SIGNATURE, RR_VERIFICATION,
};

impl MessageAuthenticator {
    /// Verifies DKIM headers of an RFC5322 message.
    #[inline(always)]
    pub async fn verify_dkim<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> Vec<DkimOutput<'x>>
    where
        TXT: ResolverCache<String, Txt> + 'x,
        MXX: ResolverCache<String, Arc<Vec<MX>>> + 'x,
        IPV4: ResolverCache<String, Arc<Vec<Ipv4Addr>>> + 'x,
        IPV6: ResolverCache<String, Arc<Vec<Ipv6Addr>>> + 'x,
        PTR: ResolverCache<IpAddr, Arc<Vec<String>>> + 'x,
    {
        self.verify_dkim_(
            params.into(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .await
    }

    pub(crate) async fn verify_dkim_<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>,
        now: u64,
    ) -> Vec<DkimOutput<'x>>
    where
        TXT: ResolverCache<String, Txt>,
        MXX: ResolverCache<String, Arc<Vec<MX>>>,
        IPV4: ResolverCache<String, Arc<Vec<Ipv4Addr>>>,
        IPV6: ResolverCache<String, Arc<Vec<Ipv6Addr>>>,
        PTR: ResolverCache<IpAddr, Arc<Vec<String>>>,
    {
        let message = params.params;
        let mut output = Vec::with_capacity(message.dkim_headers.len());
        let mut report_requested = false;

        // Validate DKIM headers
        for header in &message.dkim_headers {
            // Validate body hash
            let signature = match &header.header {
                Ok(signature) => {
                    if signature.r {
                        report_requested = true;
                    }

                    if signature.x == 0 || (signature.x > signature.t && signature.x > now) {
                        signature
                    } else {
                        output.push(
                            DkimOutput::neutral(Error::SignatureExpired).with_signature(signature),
                        );
                        continue;
                    }
                }
                Err(err) => {
                    output.push(DkimOutput::neutral(err.clone()));
                    continue;
                }
            };

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
                    DkimOutput::neutral(Error::FailedBodyHashMatch).with_signature(signature),
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
                output.push(DkimOutput::fail(Error::FailedAuidMatch).with_signature(signature));
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
                    if let Some((_, domain)) = from.rsplit_once('@') {
                        if domain.eq(atps) {
                            found = true;
                            break;
                        }
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
                            Error::CryptoError(_)
                            | Error::Io(_)
                            | Error::FailedVerification
                            | Error::FailedBodyHashMatch
                            | Error::FailedAuidMatch => (record.rr & RR_VERIFICATION) != 0,
                            Error::Base64
                            | Error::UnsupportedVersion
                            | Error::UnsupportedAlgorithm
                            | Error::UnsupportedCanonicalization
                            | Error::UnsupportedKeyType
                            | Error::IncompatibleAlgorithms => (record.rr & RR_SIGNATURE) != 0,
                            Error::SignatureExpired => (record.rr & RR_EXPIRATION) != 0,
                            Error::DnsError(_)
                            | Error::DnsRecordNotFound(_)
                            | Error::InvalidRecordType
                            | Error::ParseError
                            | Error::RevokedPublicKey => (record.rr & RR_DNS) != 0,
                            Error::MissingParameters
                            | Error::NoHeadersFound
                            | Error::ArcChainTooLong
                            | Error::ArcInvalidInstance(_)
                            | Error::ArcInvalidCV
                            | Error::ArcHasHeaderTag
                            | Error::ArcBrokenChain
                            | Error::SignatureLength
                            | Error::NotAligned => (record.rr & RR_OTHER) != 0,
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
            let signature = match &header.header {
                Ok(signature) => {
                    if signature.x == 0 || (signature.x > signature.t) {
                        signature
                    } else {
                        continue;
                    }
                }
                Err(_err) => {
                    continue;
                }
            };

            // Get pre-hashed but canonically ordered headers, who's hash is signed
            let dkim_hdr_value = header.value.strip_signature();
            let headers = self.signed_headers(&signature.h, header.name, &dkim_hdr_value);
            signature.ch.canonicalize_headers(headers, &mut data);

            return Ok(data);
        }
        // Return not ok
        Err(Error::FailedBodyHashMatch)
    }

    pub fn signed_headers<'z: 'x>(
        &'z self,
        headers: &'x [String],
        dkim_hdr_name: &'x [u8],
        dkim_hdr_value: &'x [u8],
    ) -> impl Iterator<Item = (&'x [u8], &'x [u8])> {
        let mut last_header_pos: Vec<(&[u8], usize)> = Vec::new();
        headers
            .iter()
            .filter_map(move |h| {
                let header_pos = if let Some((_, header_pos)) = last_header_pos
                    .iter_mut()
                    .find(|(lh, _)| lh.eq_ignore_ascii_case(h.as_bytes()))
                {
                    header_pos
                } else {
                    last_header_pos.push((h.as_bytes(), 0));
                    &mut last_header_pos.last_mut().unwrap().1
                };
                if let Some((last_pos, result)) = self
                    .headers
                    .iter()
                    .rev()
                    .enumerate()
                    .skip(*header_pos)
                    .find(|(_, (mh, _))| h.as_bytes().eq_ignore_ascii_case(mh))
                {
                    *header_pos = last_pos + 1;
                    Some(*result)
                } else {
                    *header_pos = self.headers.len();
                    None
                }
            })
            .chain([(dkim_hdr_name, dkim_hdr_value)])
    }
}

impl Signature {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn validate_auid(&self, record: &DomainKey) -> bool {
        // Enforce t=s flag
        if !self.i.is_empty() && record.has_flag(Flag::MatchDomain) {
            let mut auid = self.i.chars();
            let mut domain = self.d.chars();
            while let Some(ch) = auid.next() {
                if ch == '@' {
                    break;
                }
            }
            while let Some(ch) = auid.next() {
                if let Some(dch) = domain.next() {
                    if ch != dch {
                        return false;
                    }
                } else {
                    break;
                }
            }
            if domain.next().is_some() {
                return false;
            }
        }

        true
    }
}

pub(crate) trait Verifier: Sized {
    fn strip_signature(&self) -> Vec<u8>;
}

impl Verifier for &[u8] {
    fn strip_signature(&self) -> Vec<u8> {
        let mut unsigned_dkim = Vec::with_capacity(self.len());
        let mut iter = self.iter().enumerate();
        let mut last_ch = b';';
        while let Some((pos, &ch)) = iter.next() {
            match ch {
                b'=' if last_ch == b'b' => {
                    unsigned_dkim.push(ch);
                    #[allow(clippy::while_let_on_iterator)]
                    while let Some((_, &ch)) = iter.next() {
                        if ch == b';' {
                            unsigned_dkim.push(b';');
                            break;
                        }
                    }
                    last_ch = 0;
                }
                b'b' | b'B' if last_ch == b';' => {
                    last_ch = b'b';
                    unsigned_dkim.push(ch);
                }
                b';' => {
                    last_ch = b';';
                    unsigned_dkim.push(ch);
                }
                b'\r' if pos == self.len() - 2 => (),
                b'\n' if pos == self.len() - 1 => (),
                _ => {
                    unsigned_dkim.push(ch);
                    if !ch.is_ascii_whitespace() {
                        last_ch = 0;
                    }
                }
            }
        }
        unsigned_dkim
    }
}

impl<'x> From<&'x AuthenticatedMessage<'x>>
    for Parameters<
        'x,
        &'x AuthenticatedMessage<'x>,
        NoCache<String, Txt>,
        NoCache<String, Arc<Vec<MX>>>,
        NoCache<String, Arc<Vec<Ipv4Addr>>>,
        NoCache<String, Arc<Vec<Ipv6Addr>>>,
        NoCache<IpAddr, Arc<Vec<String>>>,
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
        common::{cache::test::DummyCaches, parse::TxtRecordParser, verify::DomainKey},
        dkim::verify::Verifier,
        AuthenticatedMessage, DkimResult, MessageAuthenticator,
    };

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
