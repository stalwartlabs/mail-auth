/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    ChainBinding, Dkim2Signer, Done, MessageHash, MessageInstance, Signature, SignatureValue,
    recipe::Recipe,
};
use crate::SystemTime;
use crate::{
    AuthenticatedMessage, Error,
    common::{
        crypto::{HashAlgorithm, SigningKey},
        headers::{Header, Writable, Writer},
    },
    dkim2::canonicalize::CanonicalizedHeaderWriter,
};

#[allow(clippy::large_enum_variant)]
enum RecipeSource<'x> {
    None,
    Given(Recipe),
    Diff(AuthenticatedMessage<'x>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<A, R> {
    pub mail_from: A,
    pub rcpt_to: R,
}

impl<A, R> Envelope<A, R> {
    pub fn new(mail_from: A, rcpt_to: R) -> Self {
        Envelope { mail_from, rcpt_to }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hop<A, R, I> {
    Real(Envelope<A, R>),
    Imaginary { next_domain: I },
}

impl<A, R> Hop<A, R, String> {
    pub fn real(mail_from: A, rcpt_to: R) -> Self {
        Hop::Real(Envelope::new(mail_from, rcpt_to))
    }
}

impl<I> Hop<&'static str, [&'static str; 0], I> {
    pub fn imaginary(next_domain: I) -> Self {
        Hop::Imaginary { next_domain }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2Signed {
    pub message_instance: Option<MessageInstance>,
    pub signature: Signature,
}

impl Dkim2Signed {
    pub fn write(&self, writer: &mut impl Writer) {
        self.signature.write(writer);
        if let Some(instance) = &self.message_instance {
            instance.write(writer);
        }
    }

    pub fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write(&mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}

impl Dkim2Signer<Done> {
    /// Signs a message whose content has not changed (Originator or transparent
    /// Forwarder). Adds a DKIM2-Signature, and a Message-Instance only if none
    /// is present yet.
    pub fn sign<'x, M, A, R, I>(&self, message: M, hop: Hop<A, R, I>) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_at(message, hop, now())
    }

    /// Signs a message whose content changed, computing the recipe by diffing
    /// `original` against `modified` (the form to be sent).
    pub fn sign_revised<'x, O, M, A, R, I>(
        &self,
        original: O,
        modified: M,
        hop: Hop<A, R, I>,
    ) -> crate::Result<Dkim2Signed>
    where
        O: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_revised_at(original, modified, hop, now())
    }

    pub fn sign_revised_at<'x, O, M, A, R, I>(
        &self,
        original: O,
        modified: M,
        hop: Hop<A, R, I>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        O: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_internal(modified, hop, RecipeSource::Diff(original.try_into()?), now)
    }

    /// Signs a changed message using a caller-supplied recipe describing how to
    /// reconstruct the previous state from `modified`.
    pub fn sign_with_recipe<'x, M, A, R, I>(
        &self,
        modified: M,
        recipe: Recipe,
        hop: Hop<A, R, I>,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_with_recipe_at(modified, recipe, hop, now())
    }

    pub fn sign_at<'x, M, A, R, I>(
        &self,
        message: M,
        hop: Hop<A, R, I>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_internal(message, hop, RecipeSource::None, now)
    }

    pub fn sign_with_recipe_at<'x, M, A, R, I>(
        &self,
        modified: M,
        recipe: Recipe,
        hop: Hop<A, R, I>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_internal(modified, hop, RecipeSource::Given(recipe), now)
    }

    fn sign_internal<'x, M, A, R, I>(
        &self,
        message: M,
        hop: Hop<A, R, I>,
        recipe_source: RecipeSource<'x>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        let parsed = message.try_into()?;

        let content_changed = !matches!(recipe_source, RecipeSource::None);
        let recipe = match recipe_source {
            RecipeSource::None => None,
            RecipeSource::Given(recipe) => Some(recipe),
            RecipeSource::Diff(original) => Some(Recipe::diff(&original, &parsed)),
        };

        let hash_algorithm = HashAlgorithm::Sha256;

        let instances = parsed.dkim2_instances.as_slice();
        let signatures = parsed.dkim2_signatures.as_slice();

        let highest_m = instances.last().map(|h| h.header.m).unwrap_or(0);
        let highest_i = signatures.last().map(|h| h.header.i).unwrap_or(0);

        let new_instance = if instances.is_empty() || content_changed {
            let header_hash = hash_algorithm
                .headers_hash(parsed.headers.iter().copied())
                .as_ref()
                .to_vec();
            let body_hash = hash_algorithm
                .body_hash(parsed.raw_body())
                .as_ref()
                .to_vec();

            Some(MessageInstance {
                m: highest_m
                    .checked_add(1)
                    .ok_or(Error::Dkim2(super::Dkim2Error::SequenceOverflow))?,
                hashes: vec![MessageHash {
                    name: HashAlgorithm::Sha256.into(),
                    header_hash,
                    body_hash,
                }],
                recipe,
            })
        } else {
            None
        };

        let new_m = new_instance.as_ref().map(|mi| mi.m).unwrap_or(highest_m);
        let next_i = highest_i
            .checked_add(1)
            .ok_or(Error::Dkim2(super::Dkim2Error::SequenceOverflow))?;

        let chain = match hop {
            Hop::Real(envelope) => ChainBinding::Envelope {
                mail_from: to_reverse_path(envelope.mail_from.as_ref()),
                rcpt_to: envelope
                    .rcpt_to
                    .into_iter()
                    .map(|rcpt| to_reverse_path(rcpt.as_ref()))
                    .collect(),
            },
            Hop::Imaginary { next_domain } => ChainBinding::NextDomain(next_domain.into()),
        };

        let mut signature = Signature {
            i: next_i,
            m: new_m,
            t: now,
            d: self.domain.clone(),
            s: self
                .keys
                .iter()
                .map(|entry| SignatureValue {
                    selector: entry.selector.clone(),
                    a: entry.key.algorithm(),
                    b: Vec::new(),
                })
                .collect(),
            chain,
            n: self.nonce.clone(),
            flags: self.flags.clone(),
        };

        let mut input = Vec::with_capacity(256);
        SignatureInput {
            instances,
            signatures,
            new_signature: &signature,
            new_instance: new_instance.as_ref(),
        }
        .write(&mut input);

        for (index, entry) in self.keys.iter().enumerate() {
            signature.s[index].b = entry.key.sign(input.as_slice())?;
        }

        Ok(Dkim2Signed {
            message_instance: new_instance,
            signature,
        })
    }
}

struct SignatureInput<'x> {
    instances: &'x [Header<'x, MessageInstance>],
    signatures: &'x [Header<'x, Signature>],
    new_signature: &'x Signature,
    new_instance: Option<&'x MessageInstance>,
}

impl<'x> Writable for SignatureInput<'x> {
    fn write(self, writer: &mut impl Writer) {
        for header in self.instances {
            let mut w = CanonicalizedHeaderWriter::new(writer, header.name);
            w.write(header.value);
            w.finalize();
        }

        if let Some(instance) = self.new_instance {
            let mut w = CanonicalizedHeaderWriter::new(writer, b"Message-Instance");
            instance.write_value(&mut w);
            w.finalize();
        }

        for header in self.signatures {
            let mut w = CanonicalizedHeaderWriter::new(writer, header.name);
            w.write(header.value);
            w.finalize();
        }

        let mut w = CanonicalizedHeaderWriter::new(writer, b"DKIM2-Signature");
        self.new_signature.write_value(&mut w, true);
        w.finalize();
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Wraps an address into RFC5321 reverse-path
pub(super) fn to_reverse_path(addr: &str) -> String {
    let addr = addr.trim();
    if addr.starts_with('<') && addr.ends_with('>') {
        addr.to_string()
    } else {
        format!("<{addr}>")
    }
}

#[cfg(test)]
mod test {
    use super::{Dkim2Signer, Hop};
    use crate::{
        common::crypto::{DkimKey, Ed25519Key, RsaKey, Sha256},
        dkim2::Dkim2Signed,
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
    use std::{borrow::Cow, path::PathBuf};

    const TIMESTAMP: u64 = 1740000000;

    fn normalize_crlf(message: &[u8]) -> Cow<'_, [u8]> {
        let mut needs_fix = false;
        let mut iter = message.iter().peekable();
        while let Some(&ch) = iter.next() {
            match ch {
                b'\r' => {
                    if iter.peek() != Some(&&b'\n') {
                        needs_fix = true;
                        break;
                    }
                    iter.next();
                }
                b'\n' => {
                    needs_fix = true;
                    break;
                }
                _ => {}
            }
        }

        if !needs_fix {
            return Cow::Borrowed(message);
        }

        let mut out = Vec::with_capacity(message.len() + 16);
        for ch in message {
            match ch {
                b'\r' => {}
                b'\n' => out.extend_from_slice(b"\r\n"),
                _ => out.push(*ch),
            }
        }
        Cow::Owned(out)
    }

    fn resource(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources/dkim2");
        for part in parts {
            path.push(part);
        }
        path
    }

    fn load_ed25519(domain: &str, selector: &str) -> Ed25519Key {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    }

    fn load_rsa(domain: &str, selector: &str) -> RsaKey<Sha256> {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(&pem).unwrap()).unwrap()
    }

    fn prepend(signed: &Dkim2Signed, message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(message.len() + 512);
        signed.write(&mut out);
        out.extend_from_slice(message);
        out
    }

    fn run_vector<K: Into<DkimKey>>(
        key: K,
        domain: &str,
        selector: &str,
        email: &str,
        mail_from: &str,
        rcpt_to: &[&str],
        expected_file: &str,
    ) {
        let input = std::fs::read(resource(&["emails", email])).unwrap();
        let signer = Dkim2Signer::from_key(key).domain(domain).selector(selector);
        let signed = signer
            .sign_internal(
                &input,
                Hop::real(mail_from, rcpt_to),
                super::RecipeSource::None,
                TIMESTAMP,
            )
            .unwrap();
        let normalized = normalize_crlf(&input);
        let produced = prepend(&signed, normalized.as_ref());

        if std::env::var("REGEN_DKIM2").is_ok() {
            std::fs::write(resource(&["expected", expected_file]), &produced).unwrap();
            return;
        }

        let mut expected = std::fs::read(resource(&["expected", expected_file])).unwrap();
        if expected.ends_with(b"\r") {
            expected.push(b'\n');
        }
        assert_eq!(
            String::from_utf8_lossy(&produced),
            String::from_utf8_lossy(&expected),
            "vector {expected_file}"
        );
    }

    #[test]
    fn sign_golden_single_hop() {
        let recipient: &[&str] = &["recipient@example.com"];

        run_vector(
            load_ed25519("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "ed25519",
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-ed25519.eml",
        );
        run_vector(
            load_rsa("test1.dkim2.com", "sel1"),
            "test1.dkim2.com",
            "sel1",
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-rsa2048.eml",
        );
        run_vector(
            load_rsa("test1.dkim2.com", "sel2"),
            "test1.dkim2.com",
            "sel2",
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-sel2.eml",
        );
        run_vector(
            load_rsa("test1.dkim2.com", "sel3"),
            "test1.dkim2.com",
            "sel3",
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-sel3.eml",
        );
        run_vector(
            load_ed25519("test2.dkim2.com", "ed25519"),
            "test2.dkim2.com",
            "ed25519",
            "multiheader.eml",
            "sender@test2.dkim2.com",
            recipient,
            "multiheader-ed25519.eml",
        );
        run_vector(
            load_ed25519("test3.dkim2.com", "ed25519"),
            "test3.dkim2.com",
            "ed25519",
            "trailingblank.eml",
            "sender@test3.dkim2.com",
            recipient,
            "trailingblank-ed25519.eml",
        );
        run_vector(
            load_ed25519("test4.dkim2.com", "ed25519"),
            "test4.dkim2.com",
            "ed25519",
            "emptybody.eml",
            "sender@test4.dkim2.com",
            recipient,
            "emptybody-ed25519.eml",
        );
        run_vector(
            load_ed25519("test5.dkim2.com", "ed25519"),
            "test5.dkim2.com",
            "ed25519",
            "multirecipient.eml",
            "sender@test5.dkim2.com",
            &[
                "alice@example.com",
                "bob@example.com",
                "charlie@example.com",
            ],
            "multirecipient-ed25519.eml",
        );
        run_vector(
            load_ed25519("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "ed25519",
            "simple.eml",
            "<>",
            recipient,
            "dsn-ed25519.eml",
        );
        run_vector(
            load_ed25519("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "ed25519",
            "dupheaders.eml",
            "sender@test1.dkim2.com",
            recipient,
            "dupheaders-ed25519.eml",
        );
    }

    #[test]
    fn sign_sequence_overflow_returns_error_not_panic() {
        let pkcs8 = Ed25519Key::generate_pkcs8().unwrap();
        let key = Ed25519Key::from_pkcs8_der(&pkcs8).unwrap();
        let signer = Dkim2Signer::from_key(key).domain("ex.com").selector("sel");

        let msg = concat!(
            "DKIM2-Signature: i=4294967295; m=4294967295; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:ed25519-sha256:QQ==;\r\n",
            "Message-Instance: m=4294967295; h=sha256:QQ==:Qg==;\r\n",
            "From: a@ex.com\r\n",
            "\r\n",
            "body\r\n",
        );
        let result = signer.sign_at(msg.as_bytes(), Hop::real("a@ex.com", ["b@x.com"]), 1000);
        assert!(result.is_err(), "sequence overflow must be a clean error");
    }
}
