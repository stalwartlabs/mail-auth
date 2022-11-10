use rsa::PaddingScheme;
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    dkim::{verify::Verifier, Algorithm, Canonicalization, DomainKey, PublicKey},
    Error, Resolver,
};

use super::{headers::Header, AuthResult, AuthenticatedMessage};

impl<'x> AuthenticatedMessage<'x> {
    pub async fn verify(&mut self, resolver: &Resolver) {
        // Validate DKIM headers
        let dkim_pass_len = self.dkim_pass.len();
        for header in std::mem::replace(&mut self.dkim_pass, Vec::with_capacity(dkim_pass_len)) {
            let signature = &header.header;
            let record = match resolver
                .txt_lookup::<DomainKey>(signature.domain_key())
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    self.dkim_fail
                        .push(Header::new(header.name, header.value, err));
                    continue;
                }
            };

            // Enforce t=s flag
            if !signature.validate_auid(&record) {
                self.dkim_fail.push(Header::new(
                    header.name,
                    header.value,
                    Error::FailedAUIDMatch,
                ));
                continue;
            }

            // Hash headers
            let dkim_hdr_value = header.value.strip_signature();
            let headers = self.signed_headers(&signature.h, header.name, &dkim_hdr_value);
            let hh = match signature.a {
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                    signature.ch.hash_headers::<Sha256>(headers)
                }
                Algorithm::RsaSha1 => signature.ch.hash_headers::<Sha1>(headers),
            }
            .unwrap_or_default();

            // Verify signature
            match signature.verify(record.as_ref(), &hh) {
                Ok(_) => {
                    self.dkim_pass.push(header);
                }
                Err(err) => {
                    self.dkim_fail
                        .push(Header::new(header.name, header.value, err));
                }
            }
        }

        // Validate ARC Chain
        if let Some(arc_set) = self.arc_pass.last() {
            let header = &arc_set.signature;
            let signature = &header.header;

            // Hash headers
            let dkim_hdr_value = header.value.strip_signature();
            let headers = self.signed_headers(&signature.h, header.name, &dkim_hdr_value);
            let hh = match signature.a {
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                    signature.ch.hash_headers::<Sha256>(headers)
                }
                Algorithm::RsaSha1 => signature.ch.hash_headers::<Sha1>(headers),
            }
            .unwrap_or_default();

            // Obtain record
            let record = match resolver
                .txt_lookup::<DomainKey>(signature.domain_key())
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    self.arc_fail
                        .push(Header::new(header.name, header.value, err));
                    self.arc_pass.clear();
                    return;
                }
            };

            // Verify signature
            if let Err(err) = signature.verify(record.as_ref(), &hh) {
                self.arc_fail
                    .push(Header::new(header.name, header.value, err));
                self.arc_pass.clear();
                return;
            }

            // Validate ARC Seals
            for (pos, set) in self.arc_pass.iter().enumerate().rev() {
                // Obtain record
                let header = &set.seal;
                let seal = &header.header;
                let record = match resolver.txt_lookup::<DomainKey>(seal.domain_key()).await {
                    Ok(record) => record,
                    Err(err) => {
                        self.arc_fail
                            .push(Header::new(header.name, header.value, err));
                        self.arc_pass.clear();
                        return;
                    }
                };

                // Build Seal headers
                let seal_signature = header.value.strip_signature();
                let headers = self
                    .arc_pass
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
                    self.arc_fail
                        .push(Header::new(header.name, header.value, err));
                    self.arc_pass.clear();
                    return;
                }
            }
        }
    }

    pub fn dkim_result(&self) -> AuthResult {
        if !self.dkim_pass.is_empty() {
            AuthResult::Pass
        } else if let Some(header) = self.dkim_fail.last() {
            if matches!(header.header, Error::DNSFailure(_)) {
                AuthResult::TempFail(header.header.clone())
            } else {
                AuthResult::PermFail(header.header.clone())
            }
        } else {
            AuthResult::None
        }
    }

    pub fn arc_result(&self) -> AuthResult {
        if !self.arc_pass.is_empty() {
            AuthResult::Pass
        } else if let Some(header) = self.arc_fail.last() {
            if matches!(header.header, Error::DNSFailure(_)) {
                AuthResult::TempFail(header.header.clone())
            } else {
                AuthResult::PermFail(header.header.clone())
            }
        } else {
            AuthResult::None
        }
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

    use crate::{
        common::{parse::TxtRecordParser, AuthResult, AuthenticatedMessage},
        dkim::DomainKey,
        Resolver,
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
            println!("file {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, message) = test.split_once("\n\n").unwrap();
            let resolver = new_resolver(dns_records);
            let message = message.replace('\n', "\r\n");

            let mut verifier =
                AuthenticatedMessage::parse_(message.as_bytes(), 1667843664).unwrap();
            verifier.verify(&resolver).await;

            assert_eq!(verifier.dkim_result(), AuthResult::Pass);
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

            let mut verifier =
                AuthenticatedMessage::parse_(message.as_bytes(), 1667843664).unwrap();
            verifier.verify(&resolver).await;

            assert_eq!(verifier.arc_result(), AuthResult::Pass);
            assert_eq!(verifier.dkim_result(), AuthResult::Pass);
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
