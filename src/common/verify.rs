use std::borrow::Cow;

use rsa::PaddingScheme;
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    dkim::{
        self, parse::TryIntoRecord, verify::Verifier, Algorithm, Canonicalization, Flag, PublicKey,
        Record,
    },
    Error,
};

use super::{headers::Header, AuthPhase, AuthResult, AuthenticatedMessage};

impl<'x> AuthenticatedMessage<'x> {
    pub fn verify(&mut self, maybe_record: impl TryIntoRecord<'x>) {
        let maybe_record = maybe_record.try_into_record();

        match self.phase {
            AuthPhase::Dkim => {
                let header = self.dkim_headers.pop().unwrap();
                let record = match maybe_record {
                    Ok(record) => record,
                    Err(err) => {
                        self.set_dkim_error(header, err);
                        return;
                    }
                };
                let signature = &header.header;

                // Enforce t=s flag
                if !record.validate_auid(&signature.i, &signature.d) {
                    self.set_dkim_error(header, Error::FailedAUIDMatch);
                    return;
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
                        self.dkim_result = AuthResult::Pass(header.header);
                        self.phase = if !self.arc_sets.is_empty() {
                            AuthPhase::Ams
                        } else {
                            AuthPhase::Done
                        };
                    }
                    Err(err) => {
                        self.set_dkim_error(header, err);
                    }
                }
            }
            AuthPhase::Ams => {
                let header = &self.arc_sets.last().unwrap().signature;
                let record = match maybe_record {
                    Ok(record) => record,
                    Err(err) => {
                        self.set_arc_error(header.name, header.value, err);
                        return;
                    }
                };
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

                // Verify signature
                match signature.verify(record.as_ref(), &hh) {
                    Ok(_) => {
                        self.phase = AuthPhase::As(self.arc_sets.len() - 1);
                    }
                    Err(err) => {
                        self.set_arc_error(header.name, header.value, err);
                    }
                }
            }
            AuthPhase::As(pos) => {
                let header = &self.arc_sets[pos].seal;
                let record = match maybe_record {
                    Ok(record) => record,
                    Err(err) => {
                        self.set_arc_error(header.name, header.value, err);
                        return;
                    }
                };
                let seal = &header.header;

                // Build seal headers
                let cur_set = &self.arc_sets[pos];
                let seal_signature = cur_set.seal.value.strip_signature();
                let headers = self
                    .arc_sets
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
                        (cur_set.results.name, cur_set.results.value),
                        (cur_set.signature.name, cur_set.signature.value),
                        (cur_set.seal.name, &seal_signature),
                    ]);

                /*let mut headers = Vec::with_capacity((pos + 1) * 3);
                for set in self.arc_sets.iter().take(pos + 1) {
                    headers.push((set.results.name, Cow::from(set.results.value)));
                    headers.push((set.signature.name, Cow::from(set.signature.value)));
                    headers.push((set.seal.name, Cow::from(set.seal.value.strip_signature())));
                }
                let headers_iter = headers.iter().map(|(h, v)| (*h, v.as_ref()));*/

                let hh = match seal.a {
                    Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                        Canonicalization::Relaxed.hash_headers::<Sha256>(headers)
                    }
                    Algorithm::RsaSha1 => Canonicalization::Relaxed.hash_headers::<Sha1>(headers),
                }
                .unwrap_or_default();

                // Verify ARC seal
                match seal.verify(record.as_ref(), &hh) {
                    Ok(_) => {
                        if pos > 0 {
                            self.phase = AuthPhase::As(pos - 1);
                        } else {
                            self.arc_result = AuthResult::Pass(());
                            self.phase = AuthPhase::Done;
                        }
                    }
                    Err(err) => {
                        self.set_arc_error(header.name, header.value, err);
                    }
                }
            }
            AuthPhase::Done => (),
        }
    }

    fn set_dkim_error(&mut self, header: Header<'x, dkim::Signature>, err: Error) {
        let header = Header::new(header.name, header.value, err);
        self.dkim_result = if header.header != Error::DNSFailure {
            AuthResult::PermFail(header)
        } else {
            AuthResult::TempFail(header)
        };
        if self.dkim_headers.is_empty() {
            self.phase = if !self.arc_sets.is_empty() {
                AuthPhase::Ams
            } else {
                AuthPhase::Done
            };
        }
    }

    fn set_arc_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.arc_result = if err != Error::DNSFailure {
            AuthResult::PermFail(Header::new(name, value, err))
        } else {
            AuthResult::TempFail(Header::new(name, value, err))
        };
        self.phase = AuthPhase::Done;
    }

    pub fn next_entry(&self) -> Option<String> {
        let (s, d) = match self.phase {
            AuthPhase::Dkim => {
                let s = &self.dkim_headers.last().unwrap().header;
                (s.s.as_ref(), s.d.as_ref())
            }
            AuthPhase::Ams => {
                let s = &self.arc_sets.last().unwrap().signature.header;
                (s.s.as_ref(), s.d.as_ref())
            }
            AuthPhase::As(pos) => {
                let s = &self.arc_sets[pos].seal.header;
                (s.s.as_ref(), s.d.as_ref())
            }
            AuthPhase::Done => return None,
        };

        format!(
            "{}._domainkey.{}",
            std::str::from_utf8(s).unwrap_or_default(),
            std::str::from_utf8(d).unwrap_or_default()
        )
        .into()
    }
}

pub(crate) trait VerifySignature {
    fn b(&self) -> &[u8];
    fn a(&self) -> Algorithm;
    fn verify(&self, record: &Record, hh: &[u8]) -> crate::Result<()> {
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

impl Record {
    #[allow(clippy::while_let_on_iterator)]
    pub fn validate_auid(&self, i: &[u8], d: &[u8]) -> bool {
        // Enforce t=s flag
        if !i.is_empty() && self.has_flag(Flag::MatchDomain) {
            let mut auid = i.as_ref().iter();
            let mut domain = d.as_ref().iter();
            while let Some(&ch) = auid.next() {
                if ch == b'@' {
                    break;
                }
            }
            while let Some(ch) = auid.next() {
                if let Some(dch) = domain.next() {
                    if !ch.eq_ignore_ascii_case(dch) {
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

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs, path::PathBuf};

    use crate::common::{AuthResult, AuthenticatedMessage};

    #[test]
    fn dkim_verify() {
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
            let dns_records = dns_records
                .split('\n')
                .filter_map(|r| r.split_once(' ').map(|(a, b)| (a, b.as_bytes())))
                .collect::<HashMap<_, _>>();
            let message = message.replace('\n', "\r\n");

            let mut verifier = AuthenticatedMessage::new_(message.as_bytes(), 1667843664).unwrap();
            while let Some(domain) = verifier.next_entry() {
                verifier.verify(*dns_records.get(domain.as_str()).unwrap());
            }
            assert!(
                matches!(verifier.dkim_result, AuthResult::Pass(_)),
                "Failed: {:?}",
                verifier.dkim_result
            );
        }
    }

    #[test]
    fn arc_verify() {
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("arc");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            if !file_name.to_str().unwrap().contains("002") {
                continue;
            }
            println!("file {}", file_name.to_str().unwrap());

            let test = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let (dns_records, message) = test.split_once("\n\n").unwrap();
            let dns_records = dns_records
                .split('\n')
                .filter_map(|r| r.split_once(' ').map(|(a, b)| (a, b.as_bytes())))
                .collect::<HashMap<_, _>>();
            let message = message.replace('\n', "\r\n");

            let mut verifier = AuthenticatedMessage::new_(message.as_bytes(), 1667843664).unwrap();
            while let Some(domain) = verifier.next_entry() {
                verifier.verify(*dns_records.get(domain.as_str()).unwrap());
            }

            println!("DKIM: {:?}", verifier.dkim_result);
            println!("ARC: {:?}", verifier.arc_result);

            /*assert!(
                matches!(verifier.dkim_result, AuthResult::Pass(_)),
                "Failed: {:?}",
                verifier.dkim_result
            );*/
        }
    }
}
