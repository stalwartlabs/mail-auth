use std::{io::Write, time::SystemTime};

use mail_parser::{parsers::MessageStream, HeaderValue};
use rsa::PaddingScheme;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::{
    arc::{self, ChainValidation, Set},
    dkim::{
        self, verify::Verifier, Algorithm, Atps, Canonicalization, DomainKey, HashAlgorithm,
        PublicKey,
    },
    ARCOutput, AuthenticatedMessage, DKIMOutput, DKIMResult, Error, Resolver,
};

use super::{
    base32::Base32Writer,
    headers::{AuthenticatedHeader, Header, HeaderParser},
};

impl Resolver {
    /// Verifies DKIM and ARC headers of an RFC5322 message, returns None if the message could not be parsed.
    #[inline(always)]
    pub async fn verify_message<'x>(&self, message: &'x [u8]) -> Option<AuthenticatedMessage<'x>> {
        self.verify_message_(
            message,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .await
    }

    pub(crate) async fn verify_message_<'x>(
        &self,
        raw_message: &'x [u8],
        now: u64,
    ) -> Option<AuthenticatedMessage<'x>> {
        let mut message = AuthenticatedMessage {
            headers: Vec::new(),
            from: Vec::new(),
            dkim_output: Vec::new(),
            arc_output: ARCOutput {
                result: DKIMResult::None,
                set: Vec::new(),
            },
        };

        let mut ams_headers = Vec::new();
        let mut as_headers = Vec::new();
        let mut aar_headers = Vec::new();

        let mut headers = HeaderParser::new(raw_message);
        let mut dkim_headers = Vec::new();

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    match dkim::Signature::parse(value) {
                        Ok(signature) => {
                            if signature.x == 0 || (signature.x > signature.t && signature.x > now)
                            {
                                dkim_headers.push(Header::new(name, value, signature));
                            } else {
                                message.dkim_output.push(
                                    DKIMOutput::neutral(Error::SignatureExpired)
                                        .with_signature(signature),
                                );
                            }
                        }
                        Err(err) => {
                            message.dkim_output.push(DKIMOutput::neutral(err));
                        }
                    }

                    name
                }
                AuthenticatedHeader::Aar(name) => {
                    match arc::Results::parse(value) {
                        Ok(r) => {
                            aar_headers.push(Header::new(name, value, r));
                        }
                        Err(err) => {
                            message.arc_output.result = DKIMResult::Neutral(err);
                        }
                    }

                    name
                }
                AuthenticatedHeader::Ams(name) => {
                    match arc::Signature::parse(value) {
                        Ok(s) => {
                            ams_headers.push(Header::new(name, value, s));
                        }
                        Err(err) => {
                            message.arc_output.result = DKIMResult::Neutral(err);
                        }
                    }

                    name
                }
                AuthenticatedHeader::As(name) => {
                    match arc::Seal::parse(value) {
                        Ok(s) => {
                            as_headers.push(Header::new(name, value, s));
                        }
                        Err(err) => {
                            message.arc_output.result = DKIMResult::Neutral(err);
                        }
                    }
                    name
                }
                AuthenticatedHeader::From(name) => {
                    match MessageStream::new(value).parse_address() {
                        HeaderValue::Address(addr) => {
                            if let Some(addr) = addr.address {
                                message.from.push(addr);
                            }
                        }
                        HeaderValue::AddressList(list) => {
                            message
                                .from
                                .extend(list.into_iter().filter_map(|a| a.address));
                        }
                        HeaderValue::Group(group) => {
                            message
                                .from
                                .extend(group.addresses.into_iter().filter_map(|a| a.address));
                        }
                        HeaderValue::GroupList(group_list) => {
                            message
                                .from
                                .extend(group_list.into_iter().flat_map(|group| {
                                    group.addresses.into_iter().filter_map(|a| a.address)
                                }))
                        }
                        _ => (),
                    }

                    name
                }
                AuthenticatedHeader::Other(name) => name,
            };

            message.headers.push((name, value));
        }

        if message.headers.is_empty() {
            return None;
        }

        // Obtain message body
        let body = headers
            .body_offset()
            .and_then(|pos| raw_message.get(pos..))
            .unwrap_or_default();
        let mut body_hashes = Vec::new();

        // Group ARC headers in sets
        let arc_headers = ams_headers.len();
        let mut has_arc_headers = arc_headers > 0;
        if (1..=50).contains(&arc_headers)
            && (arc_headers == as_headers.len())
            && (arc_headers == aar_headers.len())
        {
            as_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            ams_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            aar_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));

            for (pos, ((seal, signature), results)) in as_headers
                .into_iter()
                .zip(ams_headers)
                .zip(aar_headers)
                .enumerate()
            {
                if (seal.header.i as usize == (pos + 1))
                    && (signature.header.i as usize == (pos + 1))
                    && (results.header.i as usize == (pos + 1))
                    && ((pos == 0 && seal.header.cv == ChainValidation::None)
                        || (pos > 0 && seal.header.cv == ChainValidation::Pass))
                {
                    // Validate last signature in the chain
                    if pos == arc_headers - 1 {
                        // Validate expiration
                        let signature_ = &signature.header;
                        if signature_.x > 0 && (signature_.x < signature_.t || signature_.x < now) {
                            message.arc_output.result =
                                DKIMResult::Neutral(Error::SignatureExpired);
                            break;
                        }

                        // Validate body hash
                        let bh = match signature_.a {
                            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                                signature_.cb.hash_body::<Sha256>(body, signature_.l)
                            }
                            Algorithm::RsaSha1 => {
                                signature_.cb.hash_body::<Sha1>(body, signature_.l)
                            }
                        }
                        .unwrap_or_default();

                        let body_hash_matches = bh == signature_.bh;
                        body_hashes.push((
                            signature_.cb,
                            HashAlgorithm::from(signature_.a),
                            signature_.l,
                            bh,
                        ));

                        if !body_hash_matches {
                            message.arc_output.result =
                                DKIMResult::Neutral(Error::FailedBodyHashMatch);
                            has_arc_headers = false;
                        }
                    }
                } else {
                    message.arc_output.result = DKIMResult::Neutral(Error::ARCBrokenChain);
                    has_arc_headers = false;
                }

                message.arc_output.set.push(Set {
                    signature,
                    seal,
                    results,
                });

                if !has_arc_headers {
                    break;
                }
            }
        } else if has_arc_headers {
            // Missing ARC headers, fail.
            message.arc_output.result = DKIMResult::Neutral(Error::ARCBrokenChain);
            has_arc_headers = false;
        }

        // Validate DKIM headers
        for header in dkim_headers {
            // Validate body hash
            let signature = &header.header;
            let ha = HashAlgorithm::from(signature.a);

            let bh = if let Some((_, _, _, bh)) = body_hashes
                .iter()
                .find(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
            {
                bh
            } else {
                let bh = match signature.a {
                    Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                        signature.cb.hash_body::<Sha256>(body, signature.l)
                    }
                    Algorithm::RsaSha1 => signature.cb.hash_body::<Sha1>(body, signature.l),
                }
                .unwrap_or_default();

                body_hashes.push((signature.cb, ha, signature.l, bh));
                &body_hashes.last().unwrap().3
            };
            if bh != &signature.bh {
                message.dkim_output.push(
                    DKIMOutput::neutral(Error::FailedBodyHashMatch).with_signature(header.header),
                );
                continue;
            }

            // Obtain ._domainkey TXT record
            let record = match self.txt_lookup::<DomainKey>(signature.domain_key()).await {
                Ok(record) => record,
                Err(err) => {
                    message
                        .dkim_output
                        .push(DKIMOutput::dns_error(err).with_signature(header.header));
                    continue;
                }
            };

            // Enforce t=s flag
            if !signature.validate_auid(&record) {
                message
                    .dkim_output
                    .push(DKIMOutput::fail(Error::FailedAUIDMatch).with_signature(header.header));
                continue;
            }

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

            // Verify signature
            if let Err(err) = signature.verify(record.as_ref(), &hh) {
                message
                    .dkim_output
                    .push(DKIMOutput::fail(err).with_signature(header.header));
                continue;
            }

            // Verify third-party signature, if any.
            if let Some(atps) = &signature.atps {
                let mut found = false;
                // RFC5322.From has to match atps=
                for from in &message.from {
                    if let Some((_, domain)) = from.rsplit_once('@') {
                        if domain.as_bytes().eq_ignore_ascii_case(atps.as_ref()) {
                            found = true;
                            break;
                        }
                    }
                }

                if found {
                    let mut query_domain = match &signature.atpsh {
                        Some(HashAlgorithm::Sha256) => {
                            let mut writer = Base32Writer::with_capacity(40);
                            let mut hash = Sha256::new();
                            for ch in signature.d.as_ref() {
                                hash.update([ch.to_ascii_lowercase()]);
                            }
                            writer.write_all(&hash.finalize()[..]).ok();
                            writer.finalize()
                        }
                        Some(HashAlgorithm::Sha1) => {
                            let mut writer = Base32Writer::with_capacity(40);
                            let mut hash = Sha1::new();
                            for ch in signature.d.as_ref() {
                                hash.update([ch.to_ascii_lowercase()]);
                            }
                            writer.write_all(&hash.finalize()[..]).ok();
                            writer.finalize()
                        }
                        None => std::str::from_utf8(signature.d.as_ref())
                            .unwrap_or_default()
                            .to_string(),
                    };
                    query_domain.push_str("._atps.");
                    query_domain.push_str(std::str::from_utf8(atps.as_ref()).unwrap_or_default());
                    query_domain.push('.');

                    match self.txt_lookup::<Atps>(query_domain).await {
                        Ok(_) => (),
                        Err(err) => {
                            message
                                .dkim_output
                                .push(DKIMOutput::dns_error(err).with_signature(header.header));
                            continue;
                        }
                    }
                }
            }

            // Verification successful
            message
                .dkim_output
                .push(DKIMOutput::pass().with_signature(header.header));
        }

        // Validate ARC Chain
        if has_arc_headers {
            let arc_set = message.arc_output.set.last().unwrap();
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
                    message.arc_output.result = err.into();
                    return message.into();
                }
            };

            // Verify signature
            if let Err(err) = signature.verify(record.as_ref(), &hh) {
                message.arc_output.result = DKIMResult::Fail(err);
                return message.into();
            }

            // Validate ARC Seals
            for (pos, set) in message.arc_output.set.iter().enumerate().rev() {
                // Obtain record
                let header = &set.seal;
                let seal = &header.header;
                let record = match self.txt_lookup::<DomainKey>(seal.domain_key()).await {
                    Ok(record) => record,
                    Err(err) => {
                        message.arc_output.result = err.into();
                        return message.into();
                    }
                };

                // Build Seal headers
                let seal_signature = header.value.strip_signature();
                let headers = message
                    .arc_output
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
                    message.arc_output.result = DKIMResult::Fail(err);
                    return message.into();
                }
            }

            // ARC Validation successful
            message.arc_output.result = DKIMResult::Pass;
        }

        message.into()
    }
}

impl<'x> AuthenticatedMessage<'x> {
    pub fn dkim_output(&self) -> &[DKIMOutput] {
        &self.dkim_output
    }

    pub fn arc_output(&self) -> &ARCOutput {
        &self.arc_output
    }

    pub fn has_dkim_pass(&self) -> bool {
        self.dkim_output
            .iter()
            .any(|o| matches!(o.result(), &DKIMResult::Pass))
    }
}

pub(crate) trait VerifySignature {
    fn s(&self) -> &[u8];

    fn d(&self) -> &[u8];

    fn b(&self) -> &[u8];

    fn a(&self) -> Algorithm;

    fn domain_key(&self) -> String {
        let s = self.s();
        let d = self.d();
        let mut key = Vec::with_capacity(s.len() + d.len() + 13);
        key.extend_from_slice(s);
        key.extend_from_slice(b"._domainkey.");
        key.extend_from_slice(d);
        key.push(b'.');
        String::from_utf8(key).unwrap_or_default()
    }

    fn verify(&self, record: &DomainKey, hh: &[u8]) -> crate::Result<()> {
        match (&self.a(), &record.p) {
            (Algorithm::RsaSha256, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                hh,
                self.b(),
            )
            .map_err(|_| Error::FailedVerification),

            (Algorithm::RsaSha1, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha1>(),
                hh,
                self.b(),
            )
            .map_err(|_| Error::FailedVerification),

            (Algorithm::Ed25519Sha256, PublicKey::Ed25519(public_key)) => public_key
                .verify_strict(
                    hh,
                    &ed25519_dalek::Signature::from_bytes(self.b())
                        .map_err(|err| Error::CryptoError(err.to_string()))?,
                )
                .map_err(|_| Error::FailedVerification),

            (_, PublicKey::Revoked) => Err(Error::RevokedPublicKey),

            (_, _) => Err(Error::IncompatibleAlgorithms),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crate::{common::parse::TxtRecordParser, dkim::DomainKey, DKIMResult, Resolver};

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
            println!("file {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, message) = test.split_once("\n\n").unwrap();
            let resolver = new_resolver(dns_records);
            let message = message.replace('\n', "\r\n");

            let message = resolver
                .verify_message_(message.as_bytes(), 1667843664)
                .await
                .unwrap();

            assert_eq!(
                message.dkim_output().last().unwrap().result(),
                &DKIMResult::Pass
            );
        }
    }

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
            let (dns_records, message) = test.split_once("\n\n").unwrap();
            let resolver = new_resolver(dns_records);
            let message = message.replace('\n', "\r\n");

            let message = resolver
                .verify_message_(message.as_bytes(), 1667843664)
                .await
                .unwrap();

            assert_eq!(message.arc_output().result(), &DKIMResult::Pass);
            assert!(message.has_dkim_pass());
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
