use std::{iter::Enumerate, slice::Iter};

use rsa::PaddingScheme;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::{Algorithm, Canonicalization, HashAlgorithm, PublicKey, Record, Signature};

pub struct DKIMVerifier<'x> {
    headers: &'x [(&'x [u8], &'x [u8])],
    headers_iter: Enumerate<Iter<'x, (&'x [u8], &'x [u8])>>,
    headers_pos: usize,
    body: &'x [u8],
    body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
}

#[derive(Debug)]
pub struct Error<'x> {
    error: super::Error,
    header: &'x [u8],
}

impl<'x> DKIMVerifier<'x> {
    pub fn new(headers: &'x [(&'x [u8], &'x [u8])], body: &'x [u8]) -> Self {
        DKIMVerifier {
            headers,
            headers_iter: headers.iter().enumerate(),
            headers_pos: 0,
            body,
            body_hashes: Vec::new(),
        }
    }

    pub fn verify(&mut self, signature: &Signature, record: &Record) -> Result<(), Error> {
        // Canonicalize the message body and calculate its hash
        let raw_signature = self.headers[self.headers_pos];
        let bh = if let Some((_, _, _, bh)) = self.body_hashes.iter().find(|(c, h, l, _)| {
            c == &signature.cb
                && (matches!(
                    (signature.a, h),
                    (
                        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256,
                        HashAlgorithm::Sha256
                    ) | (Algorithm::RsaSha1, HashAlgorithm::Sha1)
                ) && l == &signature.l)
        }) {
            bh
        } else {
            let body = if signature.l == 0 || self.body.is_empty() {
                self.body
            } else {
                &self.body[..std::cmp::min(signature.l as usize, self.body.len())]
            };
            let (bh, h) = match signature.a {
                Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                    let mut hasher = Sha256::new();
                    signature
                        .cb
                        .canonicalize_body(body, &mut hasher)
                        .map_err(|err| Error::new(err.into(), raw_signature.1))?;
                    (hasher.finalize().to_vec(), HashAlgorithm::Sha256)
                }
                Algorithm::RsaSha1 => {
                    let mut hasher = Sha1::new();
                    signature
                        .cb
                        .canonicalize_body(body, &mut hasher)
                        .map_err(|err| Error::new(err.into(), raw_signature.1))?;
                    (hasher.finalize().to_vec(), HashAlgorithm::Sha1)
                }
            };
            self.body_hashes.push((signature.cb, h, signature.l, bh));
            &self.body_hashes.last().unwrap().3
        };

        // Check that the body hash matches
        if bh != &signature.bh {
            return Err(Error::new(
                super::Error::FailedBodyHashMatch,
                raw_signature.1,
            ));
        }

        // Create header iterator
        let mut last_header_pos: Vec<(&[u8], usize)> = Vec::new();
        let unsigned_dkim = strip_signature(raw_signature.1);
        let headers = signature
            .h
            .iter()
            .filter_map(|h| {
                let header_pos = if let Some((_, header_pos)) = last_header_pos
                    .iter_mut()
                    .find(|(lh, _)| lh.eq_ignore_ascii_case(h))
                {
                    header_pos
                } else {
                    last_header_pos.push((h, 0));
                    &mut last_header_pos.last_mut().unwrap().1
                };
                if let Some((last_pos, result)) = self
                    .headers
                    .iter()
                    .rev()
                    .enumerate()
                    .skip(*header_pos)
                    .find(|(_, (mh, _))| h.eq_ignore_ascii_case(mh))
                {
                    *header_pos = last_pos + 1;
                    Some(*result)
                } else {
                    *header_pos = self.headers.len();
                    None
                }
            })
            .chain([(raw_signature.0, unsigned_dkim.as_ref())]);

        // Canonicalize and hash headers
        let hh = match signature.a {
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                let mut hasher = Sha256::new();
                signature
                    .ch
                    .canonicalize_headers(headers, &mut hasher)
                    .map_err(|err| Error::new(err.into(), raw_signature.1))?;
                hasher.finalize().to_vec()
            }
            Algorithm::RsaSha1 => {
                let mut hasher = Sha1::new();
                signature
                    .ch
                    .canonicalize_headers(headers, &mut hasher)
                    .map_err(|err| Error::new(err.into(), raw_signature.1))?;
                hasher.finalize().to_vec()
            }
        };

        // Verify signature
        match (&signature.a, &record.p) {
            (Algorithm::RsaSha256, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                &hh,
                &signature.b,
            )
            .map_err(|_| Error::new(super::Error::FailedVerification, raw_signature.1)),

            (Algorithm::RsaSha1, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha1>(),
                &hh,
                &signature.b,
            )
            .map_err(|_| Error::new(super::Error::FailedVerification, raw_signature.1)),

            (Algorithm::Ed25519Sha256, PublicKey::Ed25519(public_key)) => public_key
                .verify_strict(
                    &hh,
                    &ed25519_dalek::Signature::from_bytes(&signature.b).map_err(|err| {
                        Error::new(super::Error::Ed25519Signature(err), raw_signature.1)
                    })?,
                )
                .map_err(|_| Error::new(super::Error::FailedVerification, raw_signature.1)),

            (_, PublicKey::Revoked) => {
                Err(Error::new(super::Error::RevokedPublicKey, raw_signature.1))
            }

            (_, _) => Err(Error::new(
                super::Error::IncompatibleAlgorithms,
                raw_signature.1,
            )),
        }
    }

    pub fn next_signature<'z>(&mut self) -> Option<Result<Signature<'z>, Error<'x>>> {
        for (pos, (name, value)) in &mut self.headers_iter {
            if name.eq_ignore_ascii_case(b"dkim-signature") {
                self.headers_pos = pos;
                return Signature::parse(value)
                    .map_err(|error| Error {
                        error,
                        header: value,
                    })
                    .into();
            }
        }

        None
    }
}

fn strip_signature(bytes: &[u8]) -> Vec<u8> {
    let mut unsigned_dkim = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().enumerate();
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
            b'\r' if pos == bytes.len() - 2 => (),
            b'\n' if pos == bytes.len() - 1 => (),
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

impl<'x> Error<'x> {
    pub fn new(error: super::Error, header: &'x [u8]) -> Self {
        Error { error, header }
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs, path::PathBuf};

    use crate::{common::headers::HeaderIterator, dkim::Record};

    use super::{strip_signature, DKIMVerifier};

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
                .filter_map(|r| r.split_once(' ').map(|(a, b)| (a.as_bytes(), b.as_bytes())))
                .collect::<HashMap<_, _>>();
            let message = message.replace('\n', "\r\n");

            let mut headers_it = HeaderIterator::new(message.as_bytes());
            let headers = (&mut headers_it).collect::<Vec<_>>();
            let body = headers_it
                .body_offset()
                .and_then(|pos| message.as_bytes().get(pos..))
                .unwrap_or_default();
            let mut verifier = DKIMVerifier::new(&headers, body);

            while let Some(signature) = verifier.next_signature() {
                let signature = signature.unwrap();
                let record = Record::parse(dns_records.get(signature.s.as_ref()).unwrap()).unwrap();
                verifier.verify(&signature, &record).unwrap();
            }
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
                String::from_utf8(strip_signature(value.as_bytes())).unwrap(),
                stripped_value
            );
        }
    }
}
