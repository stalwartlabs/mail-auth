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
//! - [draft-ietf-dkim-dkim2-spec-08](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/):
//!   DKIM2 Signatures. Section references (`§`) in this module point to this draft.
//! - [draft-ietf-dkim-dkim2-dns](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-dns/):
//!   DKIM2 DNS Records. Pure ML-DSA-44 keys are published with `k=mldsa44`,
//!   which the DNS draft does not define yet.
//!
//! Sign with [`Dkim2Signer`]. Verify a message with
//! [`MessageAuthenticator::verify_dkim2`](crate::MessageAuthenticator::verify_dkim2)
//! (or check that it is Provisionally Verified with
//! [`MessageAuthenticator::verify_dkim2_provisionally`](crate::MessageAuthenticator::verify_dkim2_provisionally))
//! and an inbound delivery status notification with
//! [`MessageAuthenticator::verify_dkim2_dsn`](crate::MessageAuthenticator::verify_dkim2_dsn).

use crate::{
    crypto::{Algorithm, DkimKey, HashAlgorithm},
    signer::NeedDomain,
};

pub mod builder;
pub mod canonicalize;
pub mod dsn;
mod error;
pub mod headers;
pub mod output;
pub mod parse;
pub mod recipe;
pub mod sign;
pub mod verify;

#[cfg(test)]
mod tests;

pub use dsn::{Dkim2Dsn, Dkim2DsnFailure, Dkim2DsnOutput};
pub use error::Dkim2Error;
pub use output::{ChainLink, Dkim2Output, Dkim2Result, Verification};
pub use recipe::{BodyRecipe, HeaderRecipe, Recipe, Step};
pub use sign::{Dkim2Signed, Envelope, Hop};

/// DKIM2 message signer (§12).
///
/// Built in typestate steps. [`Dkim2Signer::from_key`] takes the first
/// private key, [`domain`](Dkim2Signer::domain) sets the signing domain (`d=`)
/// and [`selector`](Dkim2Signer::selector) sets the selector of the first key,
/// which yields a `Dkim2Signer<`[`Ready`](crate::signer::Ready)`>`. Only a
/// ready signer can sign. Optional settings on a ready signer:
/// [`additional_key`](Dkim2Signer::additional_key) adds an alternative
/// signature under another selector (`|`),
/// [`hybrid_key`](Dkim2Signer::hybrid_key) adds a signature that must pass
/// together with the previous one (`,`), [`hashes`](Dkim2Signer::hashes)
/// selects the `Message-Instance` hash algorithms, [`flags`](Dkim2Signer::flags)
/// sets the `f=` tag, [`nonce`](Dkim2Signer::nonce) sets the `n=` tag and
/// [`out_of_band_arrangement`](Dkim2Signer::out_of_band_arrangement) allows
/// signing messages that are not Fully Verified DKIM2 Messages.
///
/// The signing methods ([`sign`](Dkim2Signer::sign),
/// [`sign_revised`](Dkim2Signer::sign_revised),
/// [`sign_with_recipe`](Dkim2Signer::sign_with_recipe) and
/// [`sign_with_message_instance`](Dkim2Signer::sign_with_message_instance))
/// return a [`Dkim2Signed`] holding the header fields to prepend to the
/// message. A message that already carries DKIM2 header fields is signed only
/// with the [`Dkim2Output`] of a full verification that passed (§12).
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
///     .flags([Flag::Feedback])
///     .sign(
///         message.as_bytes(),
///         Hop::real("sender@example.com", ["recipient@example.org"]),
///         None,
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
    pub(crate) hashes: Vec<Dkim2Hash>,
    pub(crate) flags: Vec<Flag>,
    pub(crate) nonce: Option<String>,
    pub(crate) out_of_band: bool,
}

pub(crate) struct KeyEntry {
    pub(crate) key: DkimKey,
    pub(crate) selector: String,
    pub(crate) group: u32,
}

/// A parsed `DKIM2-Signature` header field (§10).
///
/// Produced by [`Signature::parse`] when a message is parsed into an
/// [`AuthenticatedMessage`](crate::AuthenticatedMessage), and by the
/// [`Dkim2Signer`] signing methods in [`Dkim2Signed::signature`]. Verified
/// signatures are exposed through [`ChainLink::signature`].
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    /// `i=`: sequence number of this signature in the chain, starting at 1
    /// for the originator (§10.1).
    pub i: u32,
    /// `m=`: highest `Message-Instance` revision number (`m=`) present when
    /// this signature was created (§10.2).
    pub m: u32,
    /// `t=`: signature creation time, in seconds since the UNIX epoch (§10.4).
    pub t: u64,
    /// `d=`: signing domain, used to look up the public key (§10.8).
    pub d: String,
    /// `s=`: one signature value per selector, ordered by
    /// [`group`](SignatureValue::group) (§10.9).
    pub s: Vec<SignatureValue>,
    /// `mf=` and `rt=` (the SMTP envelope of the hop), or `nd=` (the domain
    /// of the next signer) (§10.5 to §10.7).
    pub chain: ChainBinding,
    /// `n=`: opaque nonce meaningful only to the signer, at most 64
    /// printable ASCII characters (§10.3).
    pub n: Option<String>,
    /// `f=`: flags reporting what the signer did or requesting behaviour
    /// from later hops (§10.10).
    pub flags: Vec<Flag>,
}

/// One entry of the `s=` tag of a `DKIM2-Signature` (§10.9).
///
/// A signature carries one entry per signing key, which gives algorithmic
/// agility: each entry names its own selector and algorithm. Entries that
/// share a [`group`](Self::group) are separated by `,` and all of them must
/// pass; groups are separated by `|` and the signature passes if any group
/// does.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignatureValue {
    /// Selector under which the public key is published, queried as
    /// `<selector>._domainkey.<d>`.
    pub selector: String,
    /// Signing algorithm (`rsa-sha256`, `ed25519-sha256` or `mldsa44`), or
    /// the name of one this crate does not implement.
    pub a: AlgorithmName,
    /// Raw signature bytes (base64-decoded).
    pub b: Vec<u8>,
    /// Index of the `|`-separated group the entry belongs to, starting at 0.
    /// Entries of one group are contiguous.
    pub group: u32,
}

/// The algorithm name of a [`SignatureValue`]: an algorithm this crate
/// implements, or the name of one it does not, which never passes (§14.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmName {
    /// A supported algorithm.
    Known(Algorithm),
    /// An unsupported algorithm, kept verbatim.
    Unknown(Box<str>),
}

impl AlgorithmName {
    /// Returns the algorithm name as it appears in the `s=` tag.
    pub fn as_str(&self) -> &str {
        match self {
            AlgorithmName::Known(algorithm) => algorithm.name(),
            AlgorithmName::Unknown(name) => name,
        }
    }

    /// Returns the supported algorithm, or `None` for an unknown name.
    pub fn known(&self) -> Option<Algorithm> {
        match self {
            AlgorithmName::Known(algorithm) => Some(*algorithm),
            AlgorithmName::Unknown(_) => None,
        }
    }
}

impl From<Algorithm> for AlgorithmName {
    fn from(algorithm: Algorithm) -> Self {
        AlgorithmName::Known(algorithm)
    }
}

/// How a `DKIM2-Signature` links to the next hop in the chain of custody
/// (§10.5 to §10.7, §12.2 and §12.3).
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

/// A value of the `f=` tag of a `DKIM2-Signature` (§10.10). Flag names are
/// case-sensitive.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flag {
    /// `feedback`: the signer requests feedback about how the message is
    /// handled.
    Feedback,
    /// `feedhere`: feedback should be relayed through this hop instead of
    /// being sent directly to the requestor.
    FeedHere,
    /// `exploded`: the signer is sending this message to more than one
    /// recipient (§12.5). Not allowed on the first signature (`i=1`).
    Exploded,
    /// Any other flag, kept verbatim. Unknown flags have no effect.
    Unknown(String),
}

impl Flag {
    /// Returns the flag as it appears in the `f=` tag.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Flag::Feedback => b"feedback",
            Flag::FeedHere => b"feedhere",
            Flag::Exploded => b"exploded",
            Flag::Unknown(value) => value.as_bytes(),
        }
    }
}

/// A parsed `Message-Instance` header field (§9).
///
/// Records the hashes of the message content at one revision and, for a
/// revision made by a Reviser, the recipe that recreates the previous
/// revision. Produced by [`MessageInstance::parse`] when a message is parsed,
/// by [`MessageInstance::from_message`] and [`MessageInstance::from_recipe`],
/// and by the signers in [`Dkim2Signed::message_instance`].
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MessageInstance {
    /// `m=`: revision number, starting at 1 for the originator (§9.1).
    pub m: u32,
    /// `h=`: header and body hashes of this revision, one entry per hash
    /// algorithm, ordered by [`group`](MessageHash::group) (§9.3).
    pub hashes: Vec<MessageHash>,
    /// `r=`: recipe that recreates the previous revision from this one, or
    /// `None` if the tag is absent (§9.2).
    pub recipe: Option<Recipe>,
}

/// A hash algorithm defined for DKIM2 `Message-Instance` hashes (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dkim2Hash {
    /// SHA-256 (`sha256`).
    Sha256,
    /// SHA-512 (`sha512`).
    Sha512,
}

impl Dkim2Hash {
    /// Parses a hash name. Names are case-sensitive (§2.14).
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map!(name, Dkim2Hash,
            b"sha256" => Dkim2Hash::Sha256,
            b"sha512" => Dkim2Hash::Sha512,
        )
        .copied()
    }

    /// Returns the hash name used in the `h=` tag.
    pub fn name(&self) -> &'static str {
        self.algorithm().name()
    }

    /// Returns the matching run-time hash algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            Dkim2Hash::Sha256 => HashAlgorithm::Sha256,
            Dkim2Hash::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

/// The hash name of a [`MessageHash`]: an algorithm this crate implements, or
/// the name of one it does not, which never passes (§14.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashName {
    /// A supported algorithm.
    Known(Dkim2Hash),
    /// An unsupported algorithm, kept verbatim.
    Unknown(Box<str>),
}

impl HashName {
    /// Returns the hash name as it appears in the `h=` tag.
    pub fn as_str(&self) -> &str {
        match self {
            HashName::Known(hash) => hash.name(),
            HashName::Unknown(name) => name,
        }
    }

    /// Returns the supported algorithm, or `None` for an unknown name.
    pub fn known(&self) -> Option<Dkim2Hash> {
        match self {
            HashName::Known(hash) => Some(*hash),
            HashName::Unknown(_) => None,
        }
    }
}

impl From<Dkim2Hash> for HashName {
    fn from(hash: Dkim2Hash) -> Self {
        HashName::Known(hash)
    }
}

/// One entry of the `h=` tag of a `Message-Instance` (§9.3 and §6).
///
/// Entries that share a [`group`](Self::group) are separated by `,` and all
/// of them must pass; groups are separated by `|` and the hashes pass if any
/// group does.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MessageHash {
    /// Hash algorithm name.
    pub name: HashName,
    /// Raw digest of the header fields hash (§6.2).
    pub header_hash: Vec<u8>,
    /// Raw digest of the body hash (§6.1).
    pub body_hash: Vec<u8>,
    /// Index of the `|`-separated group the entry belongs to, starting at 0.
    /// Entries of one group are contiguous.
    pub group: u32,
}

impl Signature {
    /// Returns the signing domain (`d=`).
    pub fn domain(&self) -> &str {
        &self.d
    }
}
