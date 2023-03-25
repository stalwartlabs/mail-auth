/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::time::SystemTime;

use crate::{
    common::{
        base32::Base32Writer,
        headers::Writer,
        verify::{DomainKey, VerifySignature},
    },
    is_within_pct, AuthenticatedMessage, DkimOutput, DkimResult, Error, Resolver,
};

use super::{
    Atps, DomainKeyReport, Flag, HashAlgorithm, Signature, RR_DNS, RR_EXPIRATION, RR_OTHER,
    RR_SIGNATURE, RR_VERIFICATION,
};

impl Resolver {
    /// Verifies DKIM headers of an RFC5322 message.
    #[inline(always)]
    pub async fn verify_dkim<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
    ) -> Vec<DkimOutput<'x>> {
        self.verify_dkim_(
            message,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .await
    }

    pub(crate) async fn verify_dkim_<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        now: u64,
    ) -> Vec<DkimOutput<'x>> {
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
            let record = match self.txt_lookup::<DomainKey>(signature.domain_key()).await {
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

            println!(
                "header.name, &dkim_hdr_value {:?} {:?}\n",
                header.name, &dkim_hdr_value
            );

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

                    match self.txt_lookup::<Atps>(query_domain).await {
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
                    .txt_lookup::<DomainKeyReport>(format!("_report._domainkey.{}.", signature.d))
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

#[cfg(test)]
#[allow(unused)]
mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crate::{
        common::{parse::TxtRecordParser, verify::DomainKey},
        dkim::verify::Verifier,
        AuthenticatedMessage, DkimResult, Resolver,
    };

    #[tokio::test]
    async fn dkim_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("dkim");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            /*if !file_name.to_str().unwrap().contains("002") {
                continue;
            }*/
            println!("DKIM verifying {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, raw_message) = test.split_once("\n\n").unwrap();
            let resolver = new_resolver(dns_records);
            let raw_message = raw_message.replace('\n', "\r\n");
            let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();

            let dkim = resolver.verify_dkim_(&message, 1667843664).await;

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

    fn new_resolver(dns_records: &str) -> Resolver {
        let resolver = Resolver::new_system_conf().unwrap();
        for (key, value) in dns_records
            .split('\n')
            .filter_map(|r| r.split_once(' ').map(|(a, b)| (a, b.as_bytes())))
        {
            #[cfg(any(test, feature = "test"))]
            resolver.txt_add(
                format!("{key}."),
                DomainKey::parse(value).unwrap(),
                Instant::now() + Duration::new(3200, 0),
            );
        }

        resolver
    }
}
