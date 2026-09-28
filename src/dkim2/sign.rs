/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM2 signing (§9): the [`Dkim2Signer`] signing methods, the [`Hop`] and
//! [`Envelope`] a signature binds to, and the resulting [`Dkim2Signed`].

use super::{
    ChainBinding, Dkim2Signer, MessageHash, MessageInstance, Signature, SignatureValue,
    recipe::Recipe,
};
use crate::SystemTime;
use crate::dkim2::BodyRecipe;
use crate::{
    AuthenticatedMessage, Error,
    crypto::{HashAlgorithm, SigningKey},
    dkim2::canonicalize::CanonicalizedHeaderWriter,
    headers::{Header, Writable, Writer},
    signer::Ready,
};

/// SMTP envelope of a message transaction.
///
/// Passed to [`MessageAuthenticator::verify_dkim2`](crate::MessageAuthenticator::verify_dkim2)
/// and [`MessageAuthenticator::verify_dkim2_dsn`](crate::MessageAuthenticator::verify_dkim2_dsn)
/// as the envelope the message was received with, and wrapped by
/// [`Hop::Real`] as the envelope a signed message is sent with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<A, R>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    /// `MAIL FROM` address, with or without angle brackets; `<>` for a null
    /// reverse-path.
    pub mail_from: A,
    /// `RCPT TO` addresses, with or without angle brackets.
    pub rcpt_to: R,
}

impl<A, R> Envelope<A, R>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    /// Creates an envelope from the `MAIL FROM` address and the `RCPT TO`
    /// addresses.
    pub fn new(mail_from: A, rcpt_to: R) -> Self {
        Envelope { mail_from, rcpt_to }
    }
}

/// Next hop of a signed message, which a signature binds to for the chain
/// of custody (§9.2 and §9.3).
///
/// Build it with [`Hop::real`] or [`Hop::imaginary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hop<A, R, I>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
    I: Into<String>,
{
    /// The message is sent over SMTP with this envelope. The signature
    /// records it in the `mf=` and `rt=` tags.
    Real(Envelope<A, R>),
    /// The message moves to another domain without an SMTP transaction. The
    /// signature records the next domain in the `nd=` tag.
    Imaginary {
        /// Domain (`d=`) that the next signature must use.
        next_domain: I,
    },
}

impl<A, R> Hop<A, R, String>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    /// Creates a hop for an SMTP transaction with this `MAIL FROM` and
    /// these `RCPT TO` addresses.
    ///
    /// Addresses without angle brackets are wrapped in them when signed. Use
    /// `"<>"` as `mail_from` for a null reverse-path, as in a DSN.
    pub fn real(mail_from: A, rcpt_to: R) -> Self {
        Hop::Real(Envelope::new(mail_from, rcpt_to))
    }
}

impl<I> Hop<&'static str, [&'static str; 0], I>
where
    I: Into<String>,
{
    /// Creates an imaginary hop that hands the message to `next_domain`
    /// without an SMTP transaction, for example between two domains hosted
    /// on the same system (§9.3).
    ///
    /// The next signature must be made by `next_domain`, and a chain cannot
    /// end with an imaginary hop: the verifier rejects a most recent
    /// signature that carries `nd=`.
    pub fn imaginary(next_domain: I) -> Self {
        Hop::Imaginary { next_domain }
    }
}

/// Header fields produced by a [`Dkim2Signer`] signing method.
///
/// Prepend them to the signed message with [`write`](Self::write) or
/// [`to_header`](Self::to_header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dkim2Signed {
    /// New `Message-Instance` header field, or `None` when the message
    /// already has one that describes its current content, or when the
    /// caller supplies the instance
    /// ([`sign_with_message_instance`](Dkim2Signer::sign_with_message_instance)).
    pub message_instance: Option<MessageInstance>,
    /// New `DKIM2-Signature` header field.
    pub signature: Signature,
}

impl Dkim2Signed {
    /// Writes the `DKIM2-Signature` header field and then, when present, the
    /// `Message-Instance` header field, each unfolded and terminated by
    /// CRLF.
    pub fn write(&self, writer: &mut impl Writer) {
        self.signature.write(writer);
        if let Some(instance) = &self.message_instance {
            instance.write(writer);
        }
    }

    /// Returns the header fields written by [`write`](Self::write) as a
    /// string.
    pub fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write(&mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}

impl Dkim2Signer<Ready> {
    /// Signs a message whose content has not changed, as an Originator or a
    /// Forwarder that does not modify the message.
    ///
    /// `message` is the raw message, including any DKIM2 header fields added
    /// by earlier hops. `hop` is the next hop the signature binds to. The
    /// result always holds a new `DKIM2-Signature`, and holds a new
    /// `Message-Instance` (`m=1`) only if the message has none yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the message cannot be parsed,
    /// [`Dkim2Error::SequenceOverflow`](super::Dkim2Error::SequenceOverflow)
    /// if the next `i=` would exceed `u32::MAX`, or the signing key's error
    /// if signing fails.
    pub fn sign<'x, M, A, R, I>(&self, message: M, hop: Hop<A, R, I>) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_at(message, hop, now())
    }

    /// Signs a message whose content changed, as a Reviser.
    ///
    /// `original` is the message as received. `modified` is the message to
    /// be sent, which keeps the DKIM2 header fields of `original`. The recipe
    /// that recreates `original` from `modified` is computed with
    /// [`Recipe::diff`]. If the signed content changed, the result holds a
    /// new `Message-Instance` with the next `m=`, the new hashes and the
    /// recipe; otherwise it holds only the `DKIM2-Signature`, as with
    /// [`sign`](Self::sign).
    ///
    /// # Errors
    ///
    /// Same as [`sign`](Self::sign); either message can fail to parse.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{
    ///     crypto::Ed25519Key,
    ///     dkim2::{Dkim2Signer, Hop},
    /// };
    ///
    /// # fn main() -> mail_auth::Result<()> {
    /// # let pkcs8: &[u8] = &[];
    /// # let received: &[u8] = &[];
    /// # let modified: &[u8] = &[];
    /// let signed = Dkim2Signer::from_key(Ed25519Key::from_pkcs8_der(pkcs8)?)
    ///     .domain("list.example.org")
    ///     .selector("ed25519")
    ///     .sign_revised(
    ///         received,
    ///         modified,
    ///         Hop::real("list-bounces@list.example.org", ["member@example.net"]),
    ///     )?;
    ///
    /// let mut outgoing = Vec::new();
    /// signed.write(&mut outgoing);
    /// outgoing.extend_from_slice(modified);
    /// # Ok(())
    /// # }
    /// ```
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

    pub(crate) fn sign_revised_at<'x, O, M, A, R, I>(
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
        let modified = modified.try_into()?;
        let new_instance = MessageInstance::from_message(&modified, Some(&original.try_into()?));

        self.sign_internal(&modified, hop, new_instance.as_ref(), now)
            .map(|signature| Dkim2Signed {
                message_instance: new_instance,
                signature,
            })
    }

    /// Signs a changed message with a caller-supplied recipe.
    ///
    /// `recipe` recreates the previous revision from `modified`, which keeps
    /// the DKIM2 header fields of the received message. The result holds a
    /// new `Message-Instance` with the next `m=`, the hashes of `modified`
    /// and `recipe`.
    ///
    /// # Errors
    ///
    /// Same as [`sign`](Self::sign).
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

    /// Signs a message with a caller-supplied `Message-Instance`.
    ///
    /// `instance` is signed as the newest `Message-Instance` of `modified`;
    /// with `None`, only the instances already present are signed. The
    /// returned [`Dkim2Signed::message_instance`] is always `None`: the caller
    /// writes `instance` to the message itself, next to the returned
    /// `DKIM2-Signature`.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`Dkim2Error::SequenceOverflow`](super::Dkim2Error::SequenceOverflow)
    /// if the next `i=` would exceed `u32::MAX`, or the signing key's error
    /// if signing fails.
    pub fn sign_with_message_instance<'x, A, R, I>(
        &self,
        modified: &AuthenticatedMessage<'x>,
        instance: Option<&MessageInstance>,
        hop: Hop<A, R, I>,
    ) -> crate::Result<Dkim2Signed>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_internal(modified, hop, instance, now())
            .map(|signature| Dkim2Signed {
                message_instance: None,
                signature,
            })
    }

    pub(crate) fn sign_at<'x, M, A, R, I>(
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
        let message = message.try_into()?;
        let new_instance = MessageInstance::from_message(&message, None);

        self.sign_internal(&message, hop, new_instance.as_ref(), now)
            .map(|signature| Dkim2Signed {
                message_instance: new_instance,
                signature,
            })
    }

    pub(crate) fn sign_with_recipe_at<'x, M, A, R, I>(
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
        let message = modified.try_into()?;
        let new_instance = MessageInstance::from_recipe(&message, Some(recipe));

        self.sign_internal(&message, hop, new_instance.as_ref(), now)
            .map(|signature| Dkim2Signed {
                message_instance: new_instance,
                signature,
            })
    }

    fn sign_internal<'x, A, R, I>(
        &self,
        parsed: &AuthenticatedMessage<'x>,
        hop: Hop<A, R, I>,
        new_instance: Option<&MessageInstance>,
        now: u64,
    ) -> crate::Result<Signature>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        let instances = parsed.dkim2_instances.as_slice();
        let signatures = parsed.dkim2_signatures.as_slice();

        let highest_m = instances.last().map(|h| h.header.m).unwrap_or(0);
        let highest_i = signatures.last().map(|h| h.header.i).unwrap_or(0);

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
            new_instance,
        }
        .write(&mut input);

        for (index, entry) in self.keys.iter().enumerate() {
            signature.s[index].b = entry.key.sign(input.as_slice())?;
        }

        Ok(signature)
    }
}

impl MessageInstance {
    /// Builds the `Message-Instance` a signer adds to `message`, if one is
    /// needed (§9.1).
    ///
    /// Without `original`, returns an instance with `m=1` if `message` has no
    /// `Message-Instance` yet, and `None` otherwise. With `original` (the
    /// message before modification), computes [`Recipe::diff`] and returns
    /// a new instance carrying the recipe when the signed content changed,
    /// or when `message` has no instance yet. The instance number is one
    /// more than the highest existing `m=` and the hashes are SHA-256.
    pub fn from_message(
        message: &AuthenticatedMessage<'_>,
        original: Option<&AuthenticatedMessage<'_>>,
    ) -> Option<Self> {
        Self::from_recipe(
            message,
            original
                .map(|original| Recipe::diff(original, message))
                .filter(|r| !r.headers.is_empty() || r.body != BodyRecipe::None),
        )
    }

    /// Builds a `Message-Instance` for `message` carrying `recipe`.
    ///
    /// Returns `None` only when `recipe` is `None` and `message` already has
    /// a `Message-Instance`. The instance number is one more than the highest
    /// existing `m=` and the hashes are SHA-256 hashes of `message`.
    pub fn from_recipe(message: &AuthenticatedMessage<'_>, recipe: Option<Recipe>) -> Option<Self> {
        let instances = message.dkim2_instances.as_slice();

        (instances.is_empty() || recipe.is_some()).then(|| MessageInstance {
            m: instances
                .last()
                .map(|h| h.header.m)
                .unwrap_or(0)
                .saturating_add(1),
            hashes: vec![MessageHash {
                name: HashAlgorithm::Sha256.into(),
                header_hash: HashAlgorithm::Sha256
                    .headers_hash(message.headers.iter().copied())
                    .as_ref()
                    .to_vec(),
                body_hash: HashAlgorithm::Sha256
                    .body_hash(message.raw_body())
                    .as_ref()
                    .to_vec(),
            }],
            recipe,
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

/// Wraps an address in angle brackets to form an RFC 5321 path, unless it
/// already has them.
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
        crypto::{DkimKey, Ed25519Key, RsaKey, Sha256},
        dkim2::{Dkim2Signed, MessageInstance},
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

    #[test]
    fn sign_with_message_instance_leaves_instance_to_caller() {
        let raw = normalize_crlf(&std::fs::read(resource(&["emails", "simple.eml"])).unwrap())
            .into_owned();
        let message = crate::AuthenticatedMessage::parse(&raw).unwrap();
        let instance = MessageInstance::from_message(&message, None);
        assert_eq!(instance.as_ref().map(|instance| instance.m), Some(1));

        let signed = Dkim2Signer::from_key(load_ed25519("test1.dkim2.com", "ed25519"))
            .domain("test1.dkim2.com")
            .selector("ed25519")
            .sign_with_message_instance(
                &message,
                instance.as_ref(),
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            )
            .unwrap();
        assert!(signed.message_instance.is_none());
        assert_eq!((signed.signature.i, signed.signature.m), (1, 1));
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
        let input_raw = std::fs::read(resource(&["emails", email])).unwrap();
        let input = input_raw.as_slice().try_into().unwrap();
        let signer = Dkim2Signer::from_key(key).domain(domain).selector(selector);
        let instance = MessageInstance::from_message(&input, None);
        let signed = signer
            .sign_internal(
                &input,
                Hop::real(mail_from, rcpt_to),
                instance.as_ref(),
                TIMESTAMP,
            )
            .map(|signature| Dkim2Signed {
                message_instance: instance,
                signature,
            })
            .unwrap();
        let normalized = normalize_crlf(&input_raw);
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
