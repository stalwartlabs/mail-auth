/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::time::SystemTime;

use sha1::Sha1;
use sha2::Sha256;

use crate::{
    common::{headers::Header, verify::VerifySignature},
    dkim::{verify::Verifier, Algorithm, Canonicalization, DomainKey, HashAlgorithm},
    ARCOutput, AuthenticatedMessage, DKIMResult, Error, Resolver,
};

use super::{ChainValidation, Set};

impl Resolver {
    pub async fn verify_arc<'x>(&self, message: &'x AuthenticatedMessage<'x>) -> ARCOutput<'x> {
        let arc_headers = message.ams_headers.len();
        if arc_headers == 0 {
            return ARCOutput::default();
        } else if arc_headers > 50 {
            return ARCOutput::default().with_result(DKIMResult::Fail(Error::ARCChainTooLong));
        } else if (arc_headers != message.as_headers.len())
            || (arc_headers != message.aar_headers.len())
        {
            return ARCOutput::default().with_result(DKIMResult::Fail(Error::ARCBrokenChain));
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut output = ARCOutput {
            result: DKIMResult::None,
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
            let seal = match &seal_.header {
                Ok(seal) => seal,
                Err(err) => return output.with_result(DKIMResult::Neutral(err.clone())),
            };
            let signature = match &signature_.header {
                Ok(signature) => signature,
                Err(err) => return output.with_result(DKIMResult::Neutral(err.clone())),
            };
            let results = match &results_.header {
                Ok(results) => results,
                Err(err) => return output.with_result(DKIMResult::Neutral(err.clone())),
            };

            if output.result == DKIMResult::None {
                if (seal.i as usize != (pos + 1))
                    || (signature.i as usize != (pos + 1))
                    || (results.i as usize != (pos + 1))
                {
                    output.result = DKIMResult::Fail(Error::ARCInvalidInstance((pos + 1) as u32));
                } else if (pos == 0 && seal.cv != ChainValidation::None)
                    || (pos > 0 && seal.cv != ChainValidation::Pass)
                {
                    output.result = DKIMResult::Fail(Error::ARCInvalidCV);
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
                            output.result = DKIMResult::Neutral(Error::FailedBodyHashMatch);
                        }
                    } else {
                        output.result = DKIMResult::Neutral(Error::SignatureExpired);
                    }
                }
            }

            output.set.push(Set {
                signature: Header::new(signature_.name, signature_.value, signature),
                seal: Header::new(seal_.name, seal_.value, seal),
                results: Header::new(results_.name, results_.value, results),
            });
        }

        if output.result != DKIMResult::None {
            return output;
        }

        // Validate ARC Set
        let arc_set = output.set.last().unwrap();
        let header = &arc_set.signature;
        let signature = &header.header;

        // Hash headers
        let dkim_hdr_value = header.value.strip_signature();
        let headers = message.signed_headers(&signature.h, header.name, &dkim_hdr_value);
        let hh = match signature.a {
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                signature.ch.hash_headers::<Sha256>(headers)
            }
            Algorithm::RsaSha1 => signature.ch.hash_headers::<Sha1>(headers),
        }
        .unwrap_or_default();

        // Obtain record
        let record = match self.txt_lookup::<DomainKey>(signature.domain_key()).await {
            Ok(record) => record,
            Err(err) => {
                return output.with_result(err.into());
            }
        };

        // Verify signature
        if let Err(err) = signature.verify(record.as_ref(), &hh) {
            return output.with_result(DKIMResult::Fail(err));
        }

        // Validate ARC Seals
        for (pos, set) in output.set.iter().enumerate().rev() {
            // Obtain record
            let header = &set.seal;
            let seal = &header.header;
            let record = match self.txt_lookup::<DomainKey>(seal.domain_key()).await {
                Ok(record) => record,
                Err(err) => {
                    return output.with_result(err.into());
                }
            };

            // Build Seal headers
            let seal_signature = header.value.strip_signature();
            let headers = output
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

            let hh = match seal.a {
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                    Canonicalization::Relaxed.hash_headers::<Sha256>(headers)
                }
                Algorithm::RsaSha1 => Canonicalization::Relaxed.hash_headers::<Sha1>(headers),
            }
            .unwrap_or_default();

            // Verify ARC Seal
            if let Err(err) = seal.verify(record.as_ref(), &hh) {
                return output.with_result(DKIMResult::Fail(err));
            }
        }

        // ARC Validation successful
        output.with_result(DKIMResult::Pass)
    }
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crate::{
        common::parse::TxtRecordParser, dkim::DomainKey, AuthenticatedMessage, DKIMResult, Resolver,
    };

    #[tokio::test]
    async fn arc_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arc");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            /*if !file_name.to_str().unwrap().contains("002") {
                continue;
            }*/
            println!("file {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, raw_message) = test.split_once("\n\n").unwrap();
            let resolver = new_resolver(dns_records);
            let raw_message = raw_message.replace('\n', "\r\n");
            let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();

            let arc = resolver.verify_arc(&message).await;
            assert_eq!(arc.result(), &DKIMResult::Pass);

            let dkim = resolver.verify_dkim(&message).await;
            assert!(dkim.iter().any(|o| o.result() == &DKIMResult::Pass));
        }
    }

    fn new_resolver(dns_records: &str) -> Resolver {
        let resolver = Resolver::new_system_conf().unwrap();
        for (key, value) in dns_records
            .split('\n')
            .filter_map(|r| r.split_once(' ').map(|(a, b)| (a, b.as_bytes())))
        {
            resolver.txt_add(
                format!("{}.", key),
                DomainKey::parse(value).unwrap(),
                Instant::now() + Duration::new(3200, 0),
            );
        }

        resolver
    }
}
