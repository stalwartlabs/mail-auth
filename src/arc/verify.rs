/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcError, ChainValidation, Set};
use crate::SystemTime;
use crate::{
    ArcOutput, AuthenticatedMessage, DkimResult, Error, MX, MessageAuthenticator, Parameters,
    RecordSet, ResolverCache, Txt,
    common::{
        crypto::HashAlgorithm,
        headers::Header,
        verify::{DomainKey, VerifySignature},
    },
    dkim::{Canonicalization, verify::Verifier},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

impl MessageAuthenticator {
    /// Verifies ARC headers of an RFC5322 message.
    pub async fn verify_arc<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> ArcOutput<'x>
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
    {
        let params = params.into();
        let message = params.params;
        if message.has_arc_errors {
            let err = message
                .errors
                .iter()
                .find_map(|h| match &h.header {
                    Error::Arc(_) => Some(h.header.clone()),
                    _ => None,
                })
                .unwrap_or(Error::Arc(ArcError::BrokenChain));
            return ArcOutput::default().with_result(DkimResult::Neutral(err));
        }
        let arc_headers = message.ams_headers.len();
        if arc_headers == 0 {
            return ArcOutput::default();
        } else if arc_headers > 50 {
            return ArcOutput::default()
                .with_result(DkimResult::Fail(Error::Arc(ArcError::ChainTooLong)));
        } else if (arc_headers != message.as_headers.len())
            || (arc_headers != message.aar_headers.len())
        {
            return ArcOutput::default()
                .with_result(DkimResult::Fail(Error::Arc(ArcError::BrokenChain)));
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut output = ArcOutput {
            result: DkimResult::None,
            set: Vec::with_capacity(message.aar_headers.len() / 3),
        };

        // Group ARC headers in sets
        for (pos, ((seal_, signature_), results_)) in message
            .as_headers
            .iter()
            .zip(message.ams_headers.iter())
            .zip(message.aar_headers.iter())
            .enumerate()
        {
            let seal = &seal_.header;
            let signature = &signature_.header;
            let results = &results_.header;

            if output.result == DkimResult::None {
                if (seal.i as usize != (pos + 1))
                    || (signature.i as usize != (pos + 1))
                    || (results.i as usize != (pos + 1))
                {
                    output.result =
                        DkimResult::Fail(Error::Arc(ArcError::InvalidInstance((pos + 1) as u32)));
                } else if (pos == 0 && seal.cv != ChainValidation::None)
                    || (pos > 0 && seal.cv != ChainValidation::Pass)
                {
                    output.result = DkimResult::Fail(Error::Arc(ArcError::InvalidCV));
                } else if pos == arc_headers - 1 {
                    // Validate last signature in the chain
                    if signature.x == 0 || (signature.x > signature.t && signature.x > now) {
                        // Validate body hash
                        let ha = HashAlgorithm::from(signature.a);
                        let bh = &message
                            .body_hashes
                            .iter()
                            .find(|(c, h, l, _)| {
                                c == &signature.cb && h == &ha && l == &signature.l
                            })
                            .unwrap()
                            .3;
                        if bh != &signature.bh {
                            output.result =
                                DkimResult::Neutral(Error::Arc(ArcError::FailedBodyHashMatch));
                        }
                    } else {
                        output.result = DkimResult::Neutral(Error::Arc(ArcError::SignatureExpired));
                    }
                }
            }

            output.set.push(Set {
                signature: Header::new(signature_.name, signature_.value, signature),
                seal: Header::new(seal_.name, seal_.value, seal),
                results: Header::new(results_.name, results_.value, results),
            });
        }

        if output.result != DkimResult::None {
            return output;
        }

        // Validate ARC Set
        let arc_set = output.set.last().unwrap();
        let header = &arc_set.signature;
        let signature = &header.header;

        // Hash headers
        let dkim_hdr_value = header.value.strip_signature();
        let mut headers = message.signed_headers(&signature.h, header.name, &dkim_hdr_value);

        // Obtain record
        let record = match self
            .txt_lookup::<DomainKey>(signature.domain_key(), params.cache_txt)
            .await
        {
            Ok(record) => record,
            Err(err) => {
                return output.with_result(err.into());
            }
        };

        // Verify signature
        if let Err(err) = record.verify(&mut headers, *signature, signature.ch) {
            return output.with_result(DkimResult::Fail(err));
        }

        // Validate ARC Seals
        for (pos, set) in output.set.iter().enumerate().rev() {
            // Obtain record
            let header = &set.seal;
            let seal = &header.header;
            let record = match self
                .txt_lookup::<DomainKey>(seal.domain_key(), params.cache_txt)
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    return output.with_result(err.into());
                }
            };

            // Build Seal headers
            let seal_signature = header.value.strip_signature();
            let mut headers = output
                .set
                .iter()
                .take(pos)
                .flat_map(|set| {
                    [
                        (set.results.name, set.results.value),
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                    ]
                })
                .chain([
                    (set.results.name, set.results.value),
                    (set.signature.name, set.signature.value),
                    (set.seal.name, &seal_signature),
                ]);

            // Verify ARC Seal
            if let Err(err) = record.verify(&mut headers, *seal, Canonicalization::Relaxed) {
                return output.with_result(DkimResult::Fail(err));
            }
        }

        // ARC Validation successful
        output.with_result(DkimResult::Pass)
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

    use mail_parser::MessageParser;

    use crate::{
        AuthenticatedMessage, DkimResult, MessageAuthenticator,
        common::{cache::test::DummyCaches, parse::TxtRecordParser, verify::DomainKey},
        dkim::verify::test::new_cache,
    };

    #[tokio::test]
    async fn arc_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arc");
        let resolver = MessageAuthenticator::new_system_conf().unwrap();

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            /*if !file_name.to_str().unwrap().contains("002") {
                continue;
            }*/
            println!("file {}", file_name.to_str().unwrap());

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

            let arc = resolver.verify_arc(caches.parameters(&message)).await;
            assert_eq!(arc.result(), &DkimResult::Pass);

            let dkim = resolver.verify_dkim(caches.parameters(&message)).await;
            assert!(dkim.iter().any(|o| o.result() == &DkimResult::Pass));
        }
    }
}
