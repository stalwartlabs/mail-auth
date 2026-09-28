/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DomainKeys Identified Mail version 2 (DKIM2).
//!
//! Every hop that relays a message adds a `DKIM2-Signature` header field. A
//! hop that changes the message also adds a `Message-Instance` header field
//! with hashes of the new content and a recipe that recreates the previous
//! content. Each signature binds the SMTP envelope (`MAIL FROM` and `RCPT TO`)
//! used by its hop, or names the domain of the next signer, so a verifier can
//! follow the chain of custody from the originator to the last hop.
//!
//! Implemented specifications:
//!
//! - [draft-ietf-dkim-dkim2-spec-04](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/):
//!   DKIM2 Signatures. Section references (`§`) in this module point to this draft.
//! - [draft-chuang-dkim2-dns](https://datatracker.ietf.org/doc/draft-chuang-dkim2-dns/):
//!   DKIM2 DNS Records.
//!
//! Sign with [`Dkim2Signer`]. Verify a message with
//! [`MessageAuthenticator::verify_dkim2`](crate::MessageAuthenticator::verify_dkim2)
//! and an inbound delivery status notification with
//! [`MessageAuthenticator::verify_dkim2_dsn`](crate::MessageAuthenticator::verify_dkim2_dsn).

use crate::{
    crypto::{Algorithm, DkimKey, HashAlgorithm},
    signer::NeedDomain,
};

pub mod builder;
pub mod canonicalize;
pub mod dsn;
pub mod headers;
pub mod output;
pub mod parse;
pub mod recipe;
pub mod sign;
pub mod verify;

#[cfg(test)]
mod tests;

pub use dsn::{Dkim2Dsn, Dkim2DsnFailure, Dkim2DsnOutput};
pub use output::{ChainLink, Dkim2Output, Dkim2Result};
pub use recipe::{BodyRecipe, HeaderRecipe, Recipe, Step};
pub use sign::{Dkim2Signed, Envelope, Hop};

/// DKIM2 message signer (§9).
///
/// Built in typestate steps. [`Dkim2Signer::from_key`] takes the first
/// private key, [`domain`](Dkim2Signer::domain) sets the signing domain (`d=`)
/// and [`selector`](Dkim2Signer::selector) sets the selector of the first key,
/// which yields a `Dkim2Signer<`[`Ready`](crate::signer::Ready)`>`. Only a
/// ready signer can sign. Optional settings on a ready signer:
/// [`additional_key`](Dkim2Signer::additional_key) adds one more signature
/// under another selector and algorithm, [`flags`](Dkim2Signer::flags) sets
/// the `f=` tag and [`nonce`](Dkim2Signer::nonce) sets the `n=` tag.
///
/// The signing methods ([`sign`](Dkim2Signer::sign),
/// [`sign_revised`](Dkim2Signer::sign_revised),
/// [`sign_with_recipe`](Dkim2Signer::sign_with_recipe) and
/// [`sign_with_message_instance`](Dkim2Signer::sign_with_message_instance))
/// return a [`Dkim2Signed`] holding the header fields to prepend to the
/// message.
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{
///     crypto::{Ed25519Key, RsaKey, Sha256},
///     dkim2::{Dkim2Signer, Flag, Hop},
/// };
/// use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let rsa_pem = "";
/// # let ed25519_pkcs8: &[u8] = &[];
/// # let message = "From: sender@example.com\r\n\r\nHello\r\n";
/// let rsa_key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(rsa_pem.as_bytes())?)?;
/// let signed = Dkim2Signer::from_key(rsa_key)
///     .domain("example.com")
///     .selector("rsa-sel")
///     .additional_key(Ed25519Key::from_pkcs8_der(ed25519_pkcs8)?, "ed-sel")
///     .flags([Flag::DoNotModify])
///     .sign(
///         message.as_bytes(),
///         Hop::real("sender@example.com", ["recipient@example.org"]),
///     )?;
///
/// let signed_message = format!("{}{}", signed.to_header(), message);
/// # Ok(())
/// # }
/// ```
pub struct Dkim2Signer<State = NeedDomain> {
    _state: std::marker::PhantomData<State>,
    pub(crate) keys: Vec<KeyEntry>,
    pub(crate) domain: String,
    pub(crate) flags: Vec<Flag>,
    pub(crate) nonce: Option<String>,
}

pub(crate) struct KeyEntry {
    pub(crate) key: DkimKey,
    pub(crate) selector: String,
}

/// A parsed `DKIM2-Signature` header field (§8).
///
/// Produced by [`Signature::parse`] when a message is parsed into an
/// [`AuthenticatedMessage`](crate::AuthenticatedMessage), and by the
/// [`Dkim2Signer`] signing methods in [`Dkim2Signed::signature`]. Verified
/// signatures are exposed through [`ChainLink::signature`].
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    /// `i=`: sequence number of this signature in the chain, starting at 1
    /// for the originator (§8.1).
    pub i: u32,
    /// `m=`: highest `Message-Instance` revision number (`m=`) present when
    /// this signature was created (§8.2).
    pub m: u32,
    /// `t=`: signature creation time, in seconds since the UNIX epoch (§8.4).
    pub t: u64,
    /// `d=`: signing domain, used to look up the public key (§8.8).
    pub d: String,
    /// `s=`: one signature value per selector and algorithm (§8.9).
    pub s: Vec<SignatureValue>,
    /// `mf=` and `rt=` (the SMTP envelope of the hop), or `nd=` (the domain
    /// of the next signer) (§8.5 to §8.7).
    pub chain: ChainBinding,
    /// `n=`: opaque nonce meaningful only to the signer, at most 64
    /// characters (§8.3).
    pub n: Option<String>,
    /// `f=`: flags reporting what the signer did or requesting behaviour
    /// from later hops (§8.10).
    pub flags: Vec<Flag>,
}

/// One entry of the `s=` tag of a `DKIM2-Signature` (§8.9).
///
/// A signature carries one entry per signing key, which gives algorithmic
/// dexterity: each entry names its own selector and algorithm.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignatureValue {
    /// Selector under which the public key is published, queried as
    /// `<selector>._domainkey.<d>`.
    pub selector: String,
    /// Signing algorithm (`rsa-sha256` or `ed25519-sha256`).
    pub a: Algorithm,
    /// Raw signature bytes (base64-decoded).
    pub b: Vec<u8>,
}

/// How a `DKIM2-Signature` links to the next hop in the chain of custody
/// (§8.5 to §8.7, §9.2 and §9.3).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ChainBinding {
    /// The SMTP envelope used when the signer sent the message (`mf=` and
    /// `rt=`). Addresses are RFC 5321 paths including the angle brackets;
    /// `mail_from` is `<>` for a null reverse-path.
    Envelope {
        /// `mf=`: the `MAIL FROM` reverse-path.
        mail_from: String,
        /// `rt=`: the `RCPT TO` forward-paths.
        rcpt_to: Vec<String>,
    },
    /// `nd=`: domain of the next `DKIM2-Signature`, used for an imaginary hop
    /// where the message changes domain without an SMTP transaction.
    NextDomain(String),
}

impl Default for ChainBinding {
    fn default() -> Self {
        ChainBinding::Envelope {
            mail_from: String::new(),
            rcpt_to: Vec::new(),
        }
    }
}

/// A value of the `f=` tag of a `DKIM2-Signature` (§8.10).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flag {
    /// `donotmodify`: the signer requests that the message not be modified.
    /// The verifier reports [`Dkim2Error::Modified`] if a later instance
    /// changed it.
    DoNotModify,
    /// `donotexplode`: the signer requests that the message not be sent to
    /// more than one recipient. The verifier reports [`Dkim2Error::Exploded`]
    /// if a later signature carries the `exploded` flag.
    DoNotExplode,
    /// `feedback`: the signer requests feedback about how the message is
    /// handled.
    Feedback,
    /// `feedhere`: feedback should be relayed through this hop instead of
    /// being sent directly to the requestor.
    FeedHere,
    /// `exploded`: the signer is sending this message to more than one
    /// recipient.
    Exploded,
    /// Any other flag, kept verbatim. Unknown flags are ignored by the
    /// verifier.
    Unknown(String),
}

impl Flag {
    /// Returns the flag as it appears in the `f=` tag.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Flag::DoNotModify => b"donotmodify",
            Flag::DoNotExplode => b"donotexplode",
            Flag::Feedback => b"feedback",
            Flag::FeedHere => b"feedhere",
            Flag::Exploded => b"exploded",
            Flag::Unknown(value) => value.as_bytes(),
        }
    }
}

/// A parsed `Message-Instance` header field (§7).
///
/// Records the hashes of the message content at one revision and, for a
/// revision made by a Reviser, the recipe that recreates the previous
/// revision. Produced by [`MessageInstance::parse`] when a message is parsed,
/// by [`MessageInstance::from_message`] and [`MessageInstance::from_recipe`],
/// and by the signers in [`Dkim2Signed::message_instance`].
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MessageInstance {
    /// `m=`: revision number, starting at 1 for the originator (§7.1).
    pub m: u32,
    /// `h=`: header and body hashes of this revision, one entry per hash
    /// algorithm (§7.3).
    pub hashes: Vec<MessageHash>,
    /// `r=`: recipe that recreates the previous revision from this one, or
    /// `None` if the tag is absent (§7.2).
    pub recipe: Option<Recipe>,
}

/// One entry of the `h=` tag of a `Message-Instance` (§7.3 and §6).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MessageHash {
    /// Hash algorithm, or `None` if the hash name is not supported.
    pub name: Option<HashAlgorithm>,
    /// Raw digest of the header fields hash (§6.2).
    pub header_hash: Vec<u8>,
    /// Raw digest of the body hash (§6.1).
    pub body_hash: Vec<u8>,
}

impl Signature {
    /// Returns the signing domain (`d=`).
    pub fn domain(&self) -> &str {
        &self.d
    }
}

/// Reason a DKIM2 header field failed to parse or a DKIM2 chain failed
/// verification.
///
/// Carried as [`Error::Dkim2`](crate::Error::Dkim2) inside a
/// [`Dkim2Result`] or returned by the parsing and signing functions. The
/// `u32` payload is the `i=` of the signature or the `m=` of the instance
/// involved. The [`Display`](std::fmt::Display) text is based on the
/// human-readable strings of §11.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dkim2Error {
    /// No `Message-Instance` with this `m=`, or the instance numbering has a
    /// gap.
    InstanceMissing(u32),
    /// The `Message-Instance` has a syntax error or a repeated tag.
    InstanceSyntax(u32),
    /// A required `Message-Instance` tag is missing.
    InstanceTagMissing {
        /// Revision number (`m=`) of the instance.
        m: u32,
        /// Name of the missing tag.
        tag: &'static str,
    },
    /// No signature covers the `Message-Instance` with this `m=`.
    InstanceNotSigned(u32),
    /// The highest `Message-Instance` is not the one named by the highest
    /// signature's `m=`.
    InstanceAboveSignature(u32),
    /// No `DKIM2-Signature` with this `i=`.
    SignatureMissing(u32),
    /// The `DKIM2-Signature` has a syntax error, a repeated tag, an
    /// undecodable value, a nonce longer than 64 characters, or an address
    /// without angle brackets.
    SignatureSyntax(u32),
    /// A required `DKIM2-Signature` tag is missing.
    SignatureTagMissing {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Name of the missing tag.
        tag: &'static str,
    },
    /// A `DKIM2-Signature` tag is not allowed in this position, such as
    /// `nd=` together with `mf=`/`rt=`, or `nd=` on the most recent signature.
    SignatureTagUnexpected {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Name of the unexpected tag.
        tag: &'static str,
    },
    /// The signature sequence numbering has a gap.
    SequenceGap,
    /// A new signature or instance number would exceed `u32::MAX`.
    SequenceOverflow,
    /// The message has more than 50 `DKIM2-Signature` or `Message-Instance`
    /// header fields.
    ChainTooLong,
    /// The signature timestamp (`t=`) is more than 14 days old.
    SignatureExpired(u32),
    /// `mf=` does not match the SMTP `MAIL FROM`, or the signer is not a
    /// recipient (`rt=`) of the previous hop.
    MailFromMismatch(u32),
    /// An SMTP `RCPT TO` address is not listed in `rt=`.
    RcptToMismatch(u32),
    /// The `mf=` domain is neither `d=` nor a subdomain of it (§8.8).
    MailFromDomainMismatch(u32),
    /// `d=` differs from the `nd=` of the previous signature.
    NextDomainMismatch(u32),
    /// The `nd=` signature's `d=` does not match any `rt=` domain of the
    /// previous signature.
    CustodyBreak(u32),
    /// The public key lookup failed with a temporary DNS error.
    PublicKeyFetch(u32),
    /// The public key record does not exist or could not be parsed.
    PublicKeyMissing(u32),
    /// The selector has more than one public key record.
    PublicKeyMultiple(u32),
    /// The public key is invalid, such as an RSA key shorter than 1024 bits.
    PublicKeySyntax(u32),
    /// The public key type does not match the `s=` algorithm.
    PublicKeyAlgorithmMismatch(u32),
    /// The public key record has an empty `p=` tag (revoked key).
    PublicKeyRevoked(u32),
    /// A signature value in `s=` did not verify.
    IncorrectSignature(u32),
    /// The signature has no `s=` entry with a supported algorithm.
    NoValidAlgorithm(u32),
    /// The header fields hash does not match the `Message-Instance` with
    /// this `m=`, or its recipe could not be applied.
    HeaderHashMismatch(u32),
    /// The body hash does not match the `Message-Instance` with this `m=`.
    BodyHashMismatch(u32),
    /// The message was modified despite a `donotmodify` request, or
    /// [`Recipe::apply`] found a recipe that declares the previous body
    /// unreconstructable (`verify_dkim2` reports that case as
    /// [`HeaderHashMismatch`](Self::HeaderHashMismatch)).
    Modified,
    /// The message was sent to several recipients despite a `donotexplode`
    /// request.
    Exploded,
    /// A recipe (`r=` tag) could not be serialized to or parsed from JSON.
    RecipeSyntax,
}

impl std::fmt::Display for Dkim2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dkim2Error::InstanceMissing(m) => write!(f, "Message-Instance m={m} missing"),
            Dkim2Error::InstanceSyntax(m) => write!(f, "Message-Instance m={m} syntax error"),
            Dkim2Error::InstanceTagMissing { m, tag } => {
                write!(f, "Message-Instance m={m} tag={tag} missing")
            }
            Dkim2Error::InstanceNotSigned(m) => write!(f, "Message-Instance m={m} is not signed"),
            Dkim2Error::InstanceAboveSignature(m) => {
                write!(
                    f,
                    "Message-Instance m={m} is higher than any DKIM2-Signature"
                )
            }
            Dkim2Error::SignatureMissing(i) => write!(f, "DKIM2-Signature i={i} missing"),
            Dkim2Error::SignatureSyntax(i) => write!(f, "DKIM2-Signature i={i} syntax error"),
            Dkim2Error::SignatureTagMissing { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} missing")
            }
            Dkim2Error::SignatureTagUnexpected { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} was unexpected")
            }
            Dkim2Error::SequenceGap => write!(f, "DKIM2 sequence numbering has a gap"),
            Dkim2Error::SequenceOverflow => {
                write!(f, "DKIM2 sequence numbering would overflow")
            }
            Dkim2Error::ChainTooLong => write!(f, "Too many DKIM2 header fields"),
            Dkim2Error::SignatureExpired(i) => write!(f, "DKIM2-Signature i={i} signature expired"),
            Dkim2Error::MailFromMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM did not match")
            }
            Dkim2Error::RcptToMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} RCPT TO did not match")
            }
            Dkim2Error::MailFromDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM and d= do not match")
            }
            Dkim2Error::NextDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} nd= does not match")
            }
            Dkim2Error::CustodyBreak(i) => {
                write!(
                    f,
                    "DKIM2-Signature i={i} d= and previous RCPT TO do not match"
                )
            }
            Dkim2Error::PublicKeyFetch(i) => {
                write!(f, "DKIM2-Signature i={i} public key could not be fetched")
            }
            Dkim2Error::PublicKeyMissing(i) => {
                write!(f, "DKIM2-Signature i={i} public key does not exist")
            }
            Dkim2Error::PublicKeyMultiple(i) => {
                write!(f, "DKIM2-Signature i={i} public key has multiple records")
            }
            Dkim2Error::PublicKeySyntax(i) => {
                write!(f, "DKIM2-Signature i={i} public key has a syntax error")
            }
            Dkim2Error::PublicKeyAlgorithmMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} public key algorithm mismatch")
            }
            Dkim2Error::PublicKeyRevoked(i) => {
                write!(f, "DKIM2-Signature i={i} public key has been revoked")
            }
            Dkim2Error::IncorrectSignature(i) => {
                write!(f, "DKIM2-Signature i={i} incorrect signature")
            }
            Dkim2Error::NoValidAlgorithm(i) => {
                write!(f, "DKIM2-Signature i={i} has no valid signature algorithms")
            }
            Dkim2Error::HeaderHashMismatch(m) => {
                write!(f, "Message-Instance m={m} header hash mismatch")
            }
            Dkim2Error::BodyHashMismatch(m) => {
                write!(f, "Message-Instance m={m} body hash mismatch")
            }
            Dkim2Error::RecipeSyntax => write!(f, "Message-Instance recipe syntax error"),
            Dkim2Error::Modified => {
                write!(f, "Message has been modified despite a donotmodify request")
            }
            Dkim2Error::Exploded => {
                write!(
                    f,
                    "Message has been exploded despite a donotexplode request"
                )
            }
        }
    }
}
