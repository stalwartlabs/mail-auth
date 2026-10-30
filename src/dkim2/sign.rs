/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM2 signing (§12): the [`Dkim2Signer`] signing methods, the [`Hop`] and
//! [`Envelope`] a signature binds to, and the resulting [`Dkim2Signed`].

use super::{
    ChainBinding, Dkim2Error, Dkim2Hash, Dkim2Output, Dkim2Signer, Flag, MessageHash,
    MessageInstance, Signature, SignatureValue,
    parse::{MAX_SIGNATURE_VALUES, is_domain, is_textstring},
    recipe::Recipe,
    verify::{StateHashes, check_custody, check_mail_from_domain, from_domain, is_from_authentic},
};
use crate::SystemTime;
use crate::dkim2::BodyRecipe;
use crate::{
    AuthenticatedMessage, Error,
    crypto::SigningKey,
    dkim2::canonicalize::{CanonicalizedHeaderWriter, Digests, body_digests, header_digests},
    dns::to_a_label,
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
/// of custody (§12.2 and §12.3).
///
/// Build it with [`Hop::real`] or [`Hop::imaginary`], and mark a real hop
/// that is one of several copies with [`Hop::exploded`].
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
    /// As [`Hop::Real`], for one of several copies of a message that an
    /// intermediary sends to more than one address (§12.5). The signature
    /// gets the `exploded` flag even when this envelope has a single `RCPT
    /// TO`, except on the first signature (`i=1`), where the flag is not
    /// allowed and is left out.
    Exploded(Envelope<A, R>),
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
    /// Addresses without angle brackets are wrapped in them when signed, and
    /// U-label domains are recorded as A-labels (§18). Use `"<>"` as
    /// `mail_from` for a null reverse-path, as in a DSN.
    pub fn real(mail_from: A, rcpt_to: R) -> Self {
        Hop::Real(Envelope::new(mail_from, rcpt_to))
    }
}

impl<A, R, I> Hop<A, R, I>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
    I: Into<String>,
{
    /// Marks a real hop as one of several copies of an exploded message
    /// (§12.5), turning [`Hop::Real`] into [`Hop::Exploded`]. Other hops are
    /// returned unchanged.
    pub fn exploded(self) -> Self {
        match self {
            Hop::Real(envelope) => Hop::Exploded(envelope),
            hop => hop,
        }
    }
}

impl<I> Hop<&'static str, [&'static str; 0], I>
where
    I: Into<String>,
{
    /// Creates an imaginary hop that hands the message to `next_domain`
    /// without an SMTP transaction, for example between two domains hosted
    /// on the same system (§12.3).
    ///
    /// The next signature must be made by `next_domain`, and a chain cannot
    /// end with an imaginary hop: the verifier rejects a most recent
    /// signature that carries `nd=`. The message is then not a Fully
    /// Verified DKIM2 Message, so the signer adding the next signature needs
    /// [`Dkim2Signer::out_of_band_arrangement`].
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
    /// by earlier hops. `hop` is the next hop the signature binds to.
    /// `verified` is the [`Dkim2Output`] of a full verification of `message`
    /// that passed (§12): required when the message already has DKIM2 header
    /// fields, unless the signer has an
    /// [`out_of_band_arrangement`](Self::out_of_band_arrangement); pass
    /// `None` for a new message. The result always holds a new
    /// `DKIM2-Signature`, and holds a new `Message-Instance` (`m=1`) only if
    /// the message has none yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the message cannot be parsed,
    /// [`Dkim2Error::NotFullyVerified`] if the validity proof is missing or
    /// does not match the message, [`Dkim2Error::FromNotAuthentic`] if the
    /// message is new (or its `From` changed) and its `From` domain is not
    /// the signing domain or a subdomain of it (§12.4), [`Dkim2Error::HeaderHashMismatch`] or
    /// [`Dkim2Error::BodyHashMismatch`] if the message changed since its most
    /// recent `Message-Instance` (use [`sign_revised`](Self::sign_revised)),
    /// [`Dkim2Error::SignatureSyntax`] if the signing domain, the `nd=`
    /// domain or a selector is not an RFC 5321 domain (U-labels are mapped to
    /// A-labels first), [`Dkim2Error::SignatureTagMissing`] for a [`Hop`]
    /// without `RCPT TO` addresses, [`Dkim2Error::SignatureSyntax`] for an
    /// empty or null `RCPT TO` address, a chain of custody, `mf=`/`d=`, selector,
    /// nonce or `exploded` flag error for a signature that would not be valid
    /// (§12.2 to §12.5),
    /// [`Dkim2Error::SequenceOverflow`] if the next `i=` would exceed
    /// `u32::MAX`, or the signing key's error if signing fails.
    pub fn sign<'x, M, A, R, I>(
        &self,
        message: M,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_at(message, hop, verified, now())
    }

    /// Signs a message whose content changed, as a Reviser.
    ///
    /// `original` is the message as received and `verified` the passing full
    /// verification of it (see [`sign`](Self::sign)). `modified` is the
    /// message to be sent, which keeps the DKIM2 header fields of
    /// `original`. The recipe that recreates `original` from `modified` is
    /// computed with [`Recipe::diff`]. If the signed content changed, the
    /// result holds a new `Message-Instance` with the next `m=`, the new
    /// hashes and the recipe; otherwise it holds only the `DKIM2-Signature`,
    /// as with [`sign`](Self::sign).
    ///
    /// # Errors
    ///
    /// Same as [`sign`](Self::sign); either message can fail to parse.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{
    ///     AuthenticatedMessage, MessageAuthenticator,
    ///     crypto::Ed25519Key,
    ///     dkim2::{Dkim2Signer, Envelope, Hop},
    /// };
    ///
    /// # async fn run() -> mail_auth::Result<()> {
    /// # let pkcs8: &[u8] = &[];
    /// # let received: &[u8] = &[];
    /// # let modified: &[u8] = &[];
    /// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
    /// let message = AuthenticatedMessage::parse(received).unwrap();
    /// let verified = authenticator
    ///     .verify_dkim2(&message, Envelope::new("sender@example.com", ["list@example.org"]))
    ///     .await;
    ///
    /// let signed = Dkim2Signer::from_key(Ed25519Key::from_pkcs8_der(pkcs8)?)
    ///     .domain("example.org")
    ///     .selector("ed25519")
    ///     .sign_revised(
    ///         received,
    ///         modified,
    ///         Hop::real("list-bounces@example.org", ["member@example.net"]),
    ///         Some(&verified),
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
        verified: Option<&Dkim2Output<'_>>,
    ) -> crate::Result<Dkim2Signed>
    where
        O: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_revised_at(original, modified, hop, verified, now())
    }

    pub(crate) fn sign_revised_at<'x, O, M, A, R, I>(
        &self,
        original: O,
        modified: M,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
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
        let new_instance =
            MessageInstance::from_message(&modified, Some(&original.try_into()?), &self.hashes)?;

        self.sign_internal(&modified, hop, new_instance.as_ref(), verified, now)
            .map(|signature| Dkim2Signed {
                message_instance: new_instance,
                signature,
            })
    }

    /// Signs a changed message with a caller-supplied recipe.
    ///
    /// `recipe` recreates the previous revision from `modified`, which keeps
    /// the DKIM2 header fields of the received message; `verified` is the
    /// passing full verification of the received message (see
    /// [`sign`](Self::sign)). The result holds a new `Message-Instance` with
    /// the next `m=`, the hashes of `modified` and `recipe`.
    ///
    /// # Errors
    ///
    /// Same as [`sign`](Self::sign), and [`Dkim2Error::RecipeSyntax`] if
    /// `recipe` fails [`Recipe::validate`].
    pub fn sign_with_recipe<'x, M, A, R, I>(
        &self,
        modified: M,
        recipe: Recipe,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        self.sign_with_recipe_at(modified, recipe, hop, verified, now())
    }

    /// Signs a message with a caller-supplied `Message-Instance`.
    ///
    /// `instance` is signed as the newest `Message-Instance` of `modified`;
    /// with `None`, only the instances already present are signed. The
    /// returned [`Dkim2Signed::message_instance`] is always `None`: the caller
    /// writes `instance` to the message itself, next to the returned
    /// `DKIM2-Signature`. `verified` is as in [`sign`](Self::sign).
    ///
    /// # Errors
    ///
    /// Same as [`sign`](Self::sign), except that parsing cannot fail;
    /// [`Dkim2Error::InstanceSyntax`] if `instance` is not numbered one more
    /// than the highest existing `m=`, [`Dkim2Error::HeaderHashMismatch`] or
    /// [`Dkim2Error::BodyHashMismatch`] if its hashes do not match
    /// `modified`, and [`Dkim2Error::RecipeSyntax`] if its recipe fails
    /// [`Recipe::validate`].
    pub fn sign_with_message_instance<'x, A, R, I>(
        &self,
        modified: &AuthenticatedMessage<'x>,
        instance: Option<&MessageInstance>,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
    ) -> crate::Result<Dkim2Signed>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        if let Some(instance) = instance {
            let expected = modified
                .dkim2_instances
                .last()
                .map_or(0, |h| h.header.m)
                .checked_add(1)
                .ok_or(Error::Dkim2(Dkim2Error::SequenceOverflow))?;
            if instance.m != expected {
                return Err(Error::Dkim2(Dkim2Error::InstanceSyntax(instance.m)));
            }
            StateHashes::default()
                .check(instance, &modified.headers, Some(modified.raw_body()))
                .map_err(|failure| Error::Dkim2(failure.into_error()))?;
        }
        self.sign_internal(modified, hop, instance, verified, now())
            .map(|signature| Dkim2Signed {
                message_instance: None,
                signature,
            })
    }

    pub(crate) fn sign_at<'x, M, A, R, I>(
        &self,
        message: M,
        hop: Hop<A, R, I>,
        verified: Option<&Dkim2Output<'_>>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        let message = message.try_into()?;
        let new_instance = MessageInstance::from_message(&message, None, &self.hashes)?;

        self.sign_internal(&message, hop, new_instance.as_ref(), verified, now)
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
        verified: Option<&Dkim2Output<'_>>,
        now: u64,
    ) -> crate::Result<Dkim2Signed>
    where
        M: TryInto<AuthenticatedMessage<'x>, Error = Error>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        recipe.validate()?;
        let message = modified.try_into()?;
        let new_instance = MessageInstance::from_recipe(&message, Some(recipe), &self.hashes);

        self.sign_internal(&message, hop, new_instance.as_ref(), verified, now)
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
        verified: Option<&Dkim2Output<'_>>,
        now: u64,
    ) -> crate::Result<Signature>
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
        I: Into<String>,
    {
        let instances = parsed.dkim2_instances.as_slice();
        let signatures = parsed.dkim2_signatures.as_slice();

        if (!signatures.is_empty() || !instances.is_empty() || parsed.has_dkim2_errors)
            && !self.out_of_band
            && !verified.is_some_and(|output| output.is_proof_for(parsed))
        {
            return Err(Error::Dkim2(Dkim2Error::NotFullyVerified));
        }

        let highest_m = instances.last().map(|h| h.header.m).unwrap_or(0);
        let highest_i = signatures.last().map(|h| h.header.i).unwrap_or(0);

        let new_m = new_instance.as_ref().map(|mi| mi.m).unwrap_or(highest_m);
        let next_i = highest_i
            .checked_add(1)
            .ok_or(Error::Dkim2(Dkim2Error::SequenceOverflow))?;

        let domain = signing_domain(&self.domain, next_i)?;
        if self
            .keys
            .iter()
            .any(|entry| !is_domain(entry.selector.as_bytes()))
        {
            return Err(Error::Dkim2(Dkim2Error::SignatureSyntax(next_i)));
        }
        if let Some(recipe) = new_instance.and_then(|instance| instance.recipe.as_ref()) {
            recipe.validate()?;
        }
        let from_changed = new_instance
            .and_then(|instance| instance.recipe.as_ref())
            .is_some_and(|recipe| {
                recipe
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case("from"))
            });
        if (signatures.is_empty() || from_changed)
            && require_authentic_from()
            && !is_from_authentic(from_domain(&parsed.headers).as_deref(), &domain)
        {
            return Err(Error::Dkim2(Dkim2Error::FromNotAuthentic(next_i)));
        }

        if new_instance.is_none()
            && let Some(highest) = instances.last()
            && !verified.is_some_and(|output| output.covers(parsed.raw_message))
        {
            StateHashes::default()
                .check(&highest.header, &parsed.headers, Some(parsed.raw_body()))
                .map_err(|failure| Error::Dkim2(failure.into_error()))?;
        }

        let mut flags = Vec::with_capacity(self.flags.len() + 1);
        for flag in &self.flags {
            let flag = match flag {
                Flag::Unknown(name) if is_textstring(name.as_bytes()) => Flag::parse(name),
                Flag::Unknown(_) => {
                    return Err(Error::Dkim2(Dkim2Error::SignatureSyntax(next_i)));
                }
                known => known.clone(),
            };
            if !flags.contains(&flag) {
                flags.push(flag);
            }
        }
        let (hop, exploded) = match hop {
            Hop::Exploded(envelope) => (Hop::Real(envelope), true),
            hop => (hop, false),
        };
        let chain = match hop {
            Hop::Real(envelope) | Hop::Exploded(envelope) => {
                let rcpt_to = envelope
                    .rcpt_to
                    .into_iter()
                    .map(|rcpt| to_reverse_path(rcpt.as_ref()))
                    .collect::<Vec<_>>();
                if rcpt_to.is_empty() {
                    return Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                        i: next_i,
                        tag: "rt",
                    }));
                } else if !rcpt_to.iter().all(|rcpt| is_forward_path(rcpt)) {
                    return Err(Error::Dkim2(Dkim2Error::SignatureSyntax(next_i)));
                }
                if next_i > 1 && (exploded || rcpt_to.len() > 1) && !flags.contains(&Flag::Exploded)
                {
                    flags.push(Flag::Exploded);
                }
                ChainBinding::Envelope {
                    mail_from: to_reverse_path(envelope.mail_from.as_ref()),
                    rcpt_to,
                }
            }
            Hop::Imaginary { next_domain } => {
                ChainBinding::NextDomain(signing_domain(&next_domain.into(), next_i)?)
            }
        };

        let mut signature = Signature {
            i: next_i,
            m: new_m,
            t: now,
            d: domain,
            s: self
                .keys
                .iter()
                .map(|entry| SignatureValue {
                    selector: entry.selector.clone(),
                    a: entry.key.algorithm().into(),
                    b: Vec::new(),
                    group: entry.group,
                })
                .collect(),
            chain,
            n: self.nonce.clone(),
            flags,
        };
        self.check_signature(&signature, signatures.last().map(|h| &h.header))
            .map_err(Error::Dkim2)?;

        let mut input = Vec::with_capacity(256 * (instances.len() + signatures.len() + 2));
        SignatureInput {
            instances,
            signatures,
            new_signature: &signature,
            new_instance,
        }
        .write(&mut input);

        for (value, entry) in signature.s.iter_mut().zip(&self.keys) {
            value.b = entry.key.sign(input.as_slice())?;
        }

        Ok(signature)
    }

    fn check_signature(
        &self,
        signature: &Signature,
        previous: Option<&Signature>,
    ) -> Result<(), Dkim2Error> {
        if signature.i == 1 && signature.flags.contains(&Flag::Exploded) {
            return Err(Dkim2Error::SignatureTagUnexpected {
                i: signature.i,
                tag: "f",
            });
        } else if signature.n.as_ref().is_some_and(|nonce| {
            nonce.len() > MAX_NONCE_LEN
                || !nonce.bytes().all(|ch| ch.is_ascii_graphic() && ch != b';')
        }) {
            return Err(Dkim2Error::SignatureSyntax(signature.i));
        }

        if signature.s.len() > MAX_SIGNATURE_VALUES {
            return Err(Dkim2Error::TooManySelectors(signature.i));
        }
        for (pos, value) in signature.s.iter().enumerate() {
            if signature
                .s
                .iter()
                .skip(pos + 1)
                .any(|other| value.selector.eq_ignore_ascii_case(&other.selector))
            {
                return Err(Dkim2Error::DuplicateSelector(signature.i));
            }
        }

        check_mail_from_domain(signature)?;
        previous.map_or(Ok(()), |previous| check_custody(previous, signature))
    }
}

#[inline(always)]
fn require_authentic_from() -> bool {
    #[cfg(test)]
    {
        test_authentic_from::required()
    }
    #[cfg(not(test))]
    {
        true
    }
}

#[cfg(test)]
pub(crate) mod test_authentic_from {
    use std::cell::Cell;

    thread_local! {
        static REQUIRED: Cell<bool> = const { Cell::new(true) };
    }

    pub(super) fn required() -> bool {
        REQUIRED.with(Cell::get)
    }

    pub(crate) struct LenientFrom;

    impl LenientFrom {
        pub(crate) fn new() -> Self {
            REQUIRED.with(|r| r.set(false));
            LenientFrom
        }
    }

    impl Drop for LenientFrom {
        fn drop(&mut self) {
            REQUIRED.with(|r| r.set(true));
        }
    }
}

fn is_forward_path(path: &str) -> bool {
    path.strip_prefix('<')
        .and_then(|inner| inner.strip_suffix('>'))
        .filter(|inner| {
            !inner.contains(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '<' | '>'))
        })
        .and_then(|inner| inner.rsplit_once('@'))
        .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
}

fn signing_domain(domain: &str, i: u32) -> crate::Result<String> {
    let domain = to_a_label(domain.trim());
    if is_domain(domain.as_bytes()) {
        Ok(domain.into_owned())
    } else {
        Err(Error::Dkim2(Dkim2Error::SignatureSyntax(i)))
    }
}

const MAX_NONCE_LEN: usize = 64;

impl MessageInstance {
    /// Builds the `Message-Instance` a signer adds to `message`, if one is
    /// needed (§12.1).
    ///
    /// Without `original`, returns an instance with `m=1` if `message` has no
    /// `Message-Instance` yet, and `None` otherwise. With `original` (the
    /// message before modification), computes [`Recipe::diff`] and returns
    /// a new instance carrying the recipe when the signed content changed,
    /// or when `message` has no instance yet. The instance number is one
    /// more than the highest existing `m=` and the hashes use `hashes`.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::HeaderNotRepresentable`] when [`Recipe::diff`]
    /// cannot record a changed header field.
    pub fn from_message(
        message: &AuthenticatedMessage<'_>,
        original: Option<&AuthenticatedMessage<'_>>,
        hashes: &[Dkim2Hash],
    ) -> crate::Result<Option<Self>> {
        let recipe = original
            .map(|original| Recipe::diff(original, message))
            .transpose()?
            .filter(|r| !r.headers.is_empty() || r.body != BodyRecipe::None);
        Ok(Self::from_recipe(message, recipe, hashes))
    }

    /// Builds a `Message-Instance` for `message` carrying `recipe`.
    ///
    /// Returns `None` only when `recipe` is `None` and `message` already has
    /// a `Message-Instance`. The instance number is one more than the highest
    /// existing `m=` and the hashes of `message` use `hashes`.
    pub fn from_recipe(
        message: &AuthenticatedMessage<'_>,
        recipe: Option<Recipe>,
        hashes: &[Dkim2Hash],
    ) -> Option<Self> {
        let instances = message.dkim2_instances.as_slice();

        if !instances.is_empty() && recipe.is_none() {
            return None;
        }
        let mut wanted = [false; Dkim2Hash::COUNT];
        for hash in hashes {
            if let Some(slot) = wanted.get_mut(hash.index()) {
                *slot = true;
            }
        }
        let header_hashes = header_digests(message.headers.iter().copied(), wanted);
        let body_hashes = body_digests(message.raw_body(), wanted);
        let digest = |digests: &Digests, hash: Dkim2Hash| {
            digests
                .get(hash.index())
                .and_then(Option::as_ref)
                .map(|digest| digest.as_ref().to_vec())
                .unwrap_or_default()
        };

        Some(MessageInstance {
            m: instances
                .last()
                .map(|h| h.header.m)
                .unwrap_or(0)
                .saturating_add(1),
            hashes: hashes
                .iter()
                .map(|hash| MessageHash {
                    name: (*hash).into(),
                    header_hash: digest(&header_hashes, *hash),
                    body_hash: digest(&body_hashes, *hash),
                    group: 0,
                })
                .collect(),
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
/// already has them, and maps a U-label domain to A-labels (§18).
pub(super) fn to_reverse_path(addr: &str) -> String {
    let addr = addr.trim();
    let path = addr
        .strip_prefix('<')
        .and_then(|addr| addr.strip_suffix('>'))
        .unwrap_or(addr);
    match path.rsplit_once('@') {
        Some((local, domain)) if !domain.is_ascii() => {
            format!("<{local}@{}>", to_a_label(domain))
        }
        _ => format!("<{path}>"),
    }
}

#[cfg(test)]
mod test {
    use super::{Dkim2Signer, Hop};
    use crate::{
        crypto::{Algorithm, DkimKey, Ed25519Key, MlDsa44Key, RsaKey, Sha256},
        dkim2::{Dkim2Hash, Dkim2Signed, MessageInstance},
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
        let instance = MessageInstance::from_message(&message, None, &[Dkim2Hash::Sha256]).unwrap();
        assert_eq!(instance.as_ref().map(|instance| instance.m), Some(1));

        let signed = Dkim2Signer::from_key(load_ed25519("test1.dkim2.com", "ed25519"))
            .domain("test1.dkim2.com")
            .selector("ed25519")
            .sign_with_message_instance(
                &message,
                instance.as_ref(),
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                None,
            )
            .unwrap();
        assert!(signed.message_instance.is_none());
        assert_eq!((signed.signature.i, signed.signature.m), (1, 1));
    }

    // A caller-supplied instance must be the next m= and describe the message; recipes are validated.
    #[test]
    fn sign_with_message_instance_checks_instance() {
        use crate::dkim2::{BodyRecipe, Dkim2Error, HeaderRecipe, Recipe, Step};

        let raw = normalize_crlf(&std::fs::read(resource(&["emails", "simple.eml"])).unwrap())
            .into_owned();
        let message = crate::AuthenticatedMessage::parse(&raw).unwrap();
        let signer = Dkim2Signer::from_key(load_ed25519("test1.dkim2.com", "ed25519"))
            .domain("test1.dkim2.com")
            .selector("ed25519");
        let hop = || Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]);
        let instance = MessageInstance::from_message(&message, None, &[Dkim2Hash::Sha256])
            .unwrap()
            .unwrap();
        let err = |instance: &MessageInstance| match signer
            .sign_with_message_instance(&message, Some(instance), hop(), None)
            .unwrap_err()
        {
            crate::Error::Dkim2(error) => error,
            other => panic!("unexpected {other:?}"),
        };

        assert_eq!(
            err(&MessageInstance {
                m: 2,
                ..instance.clone()
            }),
            Dkim2Error::InstanceSyntax(2)
        );
        let mut wrong = instance.clone();
        wrong.hashes[0].body_hash[0] ^= 1;
        assert_eq!(
            err(&wrong),
            Dkim2Error::BodyHashMismatch {
                m: 1,
                hash: Dkim2Hash::Sha256
            }
        );
        let padded = MessageInstance {
            recipe: Some(Recipe {
                headers: vec![HeaderRecipe {
                    name: "from ".to_string(),
                    steps: vec![Step::Data(vec!["x@test1.dkim2.com".to_string()])],
                }],
                body: BodyRecipe::None,
            }),
            ..instance.clone()
        };
        assert_eq!(err(&padded), Dkim2Error::RecipeSyntax);
        signer
            .sign_with_message_instance(&message, Some(&instance), hop(), None)
            .unwrap();
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
        run_signer_vector(
            Dkim2Signer::from_key(key).domain(domain).selector(selector),
            email,
            mail_from,
            rcpt_to,
            expected_file,
        );
    }

    fn run_signer_vector(
        signer: Dkim2Signer<crate::signer::Ready>,
        email: &str,
        mail_from: &str,
        rcpt_to: &[&str],
        expected_file: &str,
    ) {
        let input_raw = std::fs::read(resource(&["emails", email])).unwrap();
        let input = input_raw.as_slice().try_into().unwrap();
        let instance = MessageInstance::from_message(&input, None, &signer.hashes).unwrap();
        let signed = signer
            .sign_internal(
                &input,
                Hop::real(mail_from, rcpt_to),
                instance.as_ref(),
                None,
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
        if signed
            .signature
            .s
            .iter()
            .any(|value| value.a == Algorithm::MlDsa44.into())
        {
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

    // SHA-512 hashes and ML-DSA-44; ML-DSA signatures are randomized and checked by the verifier tests.
    #[test]
    fn sign_golden_dkim2_07() {
        let recipient: &[&str] = &["recipient@example.com"];
        let ed25519 = || {
            Dkim2Signer::from_key(load_ed25519("test1.dkim2.com", "ed25519"))
                .domain("test1.dkim2.com")
                .selector("ed25519")
        };
        run_signer_vector(
            ed25519().hashes([Dkim2Hash::Sha512]),
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-sha512.eml",
        );
        run_signer_vector(
            ed25519().hashes([Dkim2Hash::Sha256, Dkim2Hash::Sha512]),
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-sha256-sha512.eml",
        );
        let pem = std::fs::read(resource(&[
            "keys",
            "mldsa44._domainkey.test1.dkim2.com.pem",
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        run_signer_vector(
            Dkim2Signer::from_key(MlDsa44Key::from_pkcs8_der(der.secret_pkcs8_der()).unwrap())
                .domain("test1.dkim2.com")
                .selector("mldsa44"),
            "simple.eml",
            "sender@test1.dkim2.com",
            recipient,
            "simple-mldsa44.eml",
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
        let signer = Dkim2Signer::from_key(key)
            .domain("ex.com")
            .selector("sel")
            .out_of_band_arrangement();

        let msg = concat!(
            "DKIM2-Signature: i=4294967295; m=4294967295; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:ed25519-sha256:QQ==;\r\n",
            "Message-Instance: m=4294967295; h=sha256:QQ==:Qg==;\r\n",
            "From: a@ex.com\r\n",
            "\r\n",
            "body\r\n",
        );
        let result = signer.sign_at(
            msg.as_bytes(),
            Hop::real("a@ex.com", ["b@x.com"]),
            None,
            1000,
        );
        assert_eq!(
            result.unwrap_err(),
            crate::Error::Dkim2(crate::dkim2::Dkim2Error::SequenceOverflow)
        );
    }
}
