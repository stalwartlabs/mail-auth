/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcError, ChainLink, ChainValidation};
use crate::SystemTime;
use crate::dns::DnsCache;
use crate::{
    ArcOutput, AuthenticatedMessage, DkimResult, Error, MessageAuthenticator, Parameters,
    crypto::HashAlgorithm,
    dkim::{Canonicalization, verify::Verifier},
    dkim::{DomainKey, VerifySignature},
    headers::Header,
};

impl MessageAuthenticator {
    /// Validates the ARC chain of a message (RFC 8617, Section 5.2).
    ///
    /// Takes a parsed [`AuthenticatedMessage`], optionally wrapped in
    /// [`Parameters`] to supply a DNS cache. The chain is checked for
    /// structure (instance numbers, `cv=` values, matching header counts),
    /// then the newest `ARC-Message-Signature` (body hash, expiration and
    /// signature) and every `ARC-Seal`, newest first, are verified. One DNS
    /// TXT lookup of the key at `<s>._domainkey.<d>` is performed for the
    /// newest `ARC-Message-Signature` and for each `ARC-Seal`.
    ///
    /// The [`ArcResult`](crate::ArcResult) of the returned [`ArcOutput`] is:
    ///
    /// - `None`: the message has no `ARC-Message-Signature` header; other ARC
    ///   headers are not examined in that case.
    /// - `Pass`: the chain validated.
    /// - `Fail`: the chain is broken (more than 50 sets, differing header
    ///   counts, wrong instance sequence, invalid `cv=`), or a signature or
    ///   seal failed cryptographic verification.
    /// - `Neutral`: an ARC header could not be parsed, or the newest
    ///   `ARC-Message-Signature` has expired or its body hash does not match.
    /// - `PermError`: a key record is missing or invalid.
    /// - `TempError`: a key lookup failed with a transient DNS error.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{AuthenticatedMessage, ArcResult, MessageAuthenticator};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator, raw_message: &[u8]) {
    /// let message = AuthenticatedMessage::parse(raw_message).unwrap();
    /// let output = authenticator.verify_arc(&message).await;
    /// match output.result() {
    ///     ArcResult::Pass => println!("chain of {} sets validated", output.chain().len()),
    ///     ArcResult::None => println!("no ARC chain"),
    ///     other => println!("arc={other}"),
    /// }
    /// # }
    /// ```
    pub async fn verify_arc<'x, C>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, C>>,
    ) -> ArcOutput<'x>
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        let message = params.input;
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
                    output.result = DkimResult::Fail(Error::Arc(ArcError::InvalidChainValidation));
                } else if pos == arc_headers - 1 {
                    if signature.x == 0 || (signature.x > signature.t && signature.x > now) {
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
                                DkimResult::Neutral(Error::Arc(ArcError::BodyHashMismatch));
                        }
                    } else {
                        output.result = DkimResult::Neutral(Error::Arc(ArcError::SignatureExpired));
                    }
                }
            }

            output.set.push(ChainLink {
                signature: Header::new(signature_.name, signature_.value, signature),
                seal: Header::new(seal_.name, seal_.value, seal),
                results: Header::new(results_.name, results_.value, results),
            });
        }

        if output.result != DkimResult::None {
            return output;
        }

        let arc_set = output.set.last().unwrap();
        let header = &arc_set.signature;
        let signature = &header.header;

        let dkim_hdr_value = header.value.strip_signature();
        let mut headers = message.signed_headers(&signature.h, header.name, &dkim_hdr_value);

        let record = match self
            .txt_lookup::<DomainKey>(signature.domain_key(), params.txt_cache())
            .await
        {
            Ok(record) => record,
            Err(err) => {
                return output.with_result(err.into());
            }
        };

        if let Err(err) = record.verify(&mut headers, *signature, signature.ch) {
            return output.with_result(DkimResult::Fail(err));
        }

        for (pos, set) in output.set.iter().enumerate().rev() {
            let header = &set.seal;
            let seal = &header.header;
            let record = match self
                .txt_lookup::<DomainKey>(seal.domain_key(), params.txt_cache())
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    return output.with_result(err.into());
                }
            };

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

            if let Err(err) = record.verify(&mut headers, *seal, Canonicalization::Relaxed) {
                return output.with_result(DkimResult::Fail(err));
            }
        }

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
        AuthenticatedMessage, DkimResult, MessageAuthenticator, dkim::DomainKey,
        dkim::verify::test::new_cache, dns::cache::test::DummyCaches, parse::TxtRecordParser,
    };

    #[tokio::test]
    async fn arc_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arc");
        let resolver = MessageAuthenticator::new_system_conf().unwrap();

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
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
                    raw_message.as_bytes(),
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
