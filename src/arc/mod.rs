/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Authenticated Received Chain (ARC).
//!
//! Implements verification and sealing of ARC sets as specified in
//! [RFC 8617](https://datatracker.ietf.org/doc/html/rfc8617). RFC 8617 is
//! being reclassified as
//! [Historic](https://datatracker.ietf.org/doc/draft-ietf-dmarc-arc-to-historic/)
//! and DKIM2 ([`crate::dkim2`]) is its successor. This module is opt-in: it
//! is only compiled with the `arc` feature.
//!
//! Verify an incoming chain with
//! [`MessageAuthenticator::verify_arc`](crate::MessageAuthenticator::verify_arc),
//! which returns an [`ArcOutput`], then add a new set with [`ArcSealer`].

/// Type-state builder methods of [`ArcSealer`].
pub mod builder;
/// Serialization of ARC headers and the
/// [`HeaderWriter`](crate::headers::HeaderWriter) implementation of
/// [`SealedSet`].
pub mod headers;
/// Verification result types: [`ArcOutput`] and [`ArcResult`].
pub mod output;
/// Parsers for the `ARC-Message-Signature`, `ARC-Seal` and
/// `ARC-Authentication-Results` header values.
pub mod parse;
/// Sealing of a message with [`ArcSealer::seal`] (RFC 8617, Section 5.1).
pub mod seal;
/// Chain validation (RFC 8617, Section 5.2).
pub mod verify;

pub use output::{ArcOutput, ArcResult};

use crate::{
    AuthenticationResults,
    crypto::{Algorithm, Sha256, SigningKey},
    dkim::{Canonicalization, VerifySignature},
    headers::Header,
    signer::NeedDomain,
};

/// An ARC-specific error, carried as [`Error::Arc`](crate::Error::Arc).
///
/// Produced while parsing ARC headers, verifying a chain or sealing a
/// message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ArcError {
    /// The message has more than 50 ARC sets (RFC 8617, Section 4.2.1).
    ChainTooLong,
    /// An `i=` tag is outside 1 to 50, or the instances of the chain are not
    /// the sequence 1, 2, 3 and so on. Holds the offending or expected
    /// instance.
    InvalidInstance(u32),
    /// The `cv=` tag of an `ARC-Seal` is missing or malformed, is not `none`
    /// on instance 1 or not `pass` on later instances, or a chain with
    /// `cv=fail` was given to [`ArcSealer::seal`].
    InvalidChainValidation,
    /// An `ARC-Seal` carries an `h=` tag, which RFC 8617 Section 4.1.3
    /// forbids.
    HasHeaderTag,
    /// The chain is incomplete: the numbers of `ARC-Seal`,
    /// `ARC-Message-Signature` and `ARC-Authentication-Results` headers
    /// differ, or an ARC header could not be parsed.
    BrokenChain,
    /// The body hash of the newest `ARC-Message-Signature` does not match the
    /// message body.
    BodyHashMismatch,
    /// The `x=` expiration time of the newest `ARC-Message-Signature` has
    /// passed.
    SignatureExpired,
    /// An `ARC-Message-Signature` has an `l=` body length tag and the message
    /// was parsed in strict mode, which rejects such signatures.
    BodyLengthTag,
}

impl std::fmt::Display for ArcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArcError::InvalidInstance(i) => write!(f, "Invalid 'i={i}' value found in ARC header"),
            ArcError::InvalidChainValidation => {
                write!(f, "Invalid 'cv=' value found in ARC header")
            }
            ArcError::HasHeaderTag => write!(f, "Invalid 'h=' tag present in ARC-Seal"),
            ArcError::BrokenChain => write!(f, "Broken or missing ARC chain"),
            ArcError::ChainTooLong => write!(f, "Too many ARC headers"),
            ArcError::BodyHashMismatch => {
                write!(f, "Calculated body hash does not match signature hash")
            }
            ArcError::SignatureExpired => write!(f, "Signature expired"),
            ArcError::BodyLengthTag => write!(f, "Insecure 'l=' tag found in Signature"),
        }
    }
}

/// An ARC sealer (RFC 8617, Section 5.1).
///
/// Adds a new ARC set (`ARC-Seal`, `ARC-Message-Signature` and
/// `ARC-Authentication-Results`) to a message. Built from a SHA-256 signing
/// key with [`ArcSealer::from_key`], then configured in a fixed order that
/// the type state enforces:
/// `ArcSealer::from_key(key).domain(..).selector(..).headers(..)` yields an
/// `ArcSealer<_, signer::Ready>`. Only a `Ready` sealer can seal, and only a
/// `Ready` sealer accepts the optional settings (`expiration`,
/// `body_length`, `header_canonicalization`, `body_canonicalization`).
///
/// Defaults: `relaxed/relaxed` canonicalization, no expiration (`x=`
/// omitted) and no body length (`l=` omitted). The algorithm is taken from
/// the key.
///
/// [`ArcSealer::seal`] takes the message, the `Authentication-Results` of
/// the receiving host and the [`ArcOutput`] of
/// [`MessageAuthenticator::verify_arc`](crate::MessageAuthenticator::verify_arc),
/// and returns a [`SealedSet`] that writes the three ARC headers through
/// [`HeaderWriter`](crate::headers::HeaderWriter).
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{
///     AuthenticatedMessage, AuthenticationResults, MessageAuthenticator,
///     arc::ArcSealer, crypto::Ed25519Key, headers::HeaderWriter,
/// };
///
/// # async fn run(authenticator: &MessageAuthenticator, raw_message: &str) -> mail_auth::Result<()> {
/// # let pkcs8_der: Vec<u8> = Vec::new();
/// let message = AuthenticatedMessage::parse(raw_message.as_bytes()).unwrap();
/// let arc_output = authenticator.verify_arc(&message).await;
/// let dkim_output = authenticator.verify_dkim(&message).await;
/// let auth_results = AuthenticationResults::new("mx.example.org")
///     .with_dkim_results(&dkim_output, "sender@example.com")
///     .with_arc_result(&arc_output, "192.0.2.1".parse().unwrap());
///
/// if arc_output.can_be_sealed() {
///     let key = Ed25519Key::from_pkcs8_der(&pkcs8_der)?;
///     let set = ArcSealer::from_key(key)
///         .domain("example.org")
///         .selector("arc")
///         .headers(["From", "To", "Subject", "DKIM-Signature"])
///         .seal(&message, &auth_results, &arc_output)?;
///     let sealed = format!("{}{}", set.to_header(), raw_message);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArcSealer<T: SigningKey<Hasher = Sha256>, State = NeedDomain> {
    _state: std::marker::PhantomData<State>,
    pub(crate) key: T,
    pub(crate) signature: Signature,
    pub(crate) seal: Seal,
}

/// An `ARC-Message-Signature` (RFC 8617, Section 4.1.2).
///
/// Parsed from an incoming header with [`Signature::parse`] (reachable
/// through [`ChainLink::signature`]) or produced by [`ArcSealer::seal`] in a
/// [`SealedSet`]. The tags follow DKIM (RFC 6376, Section 3.5), with `i=`
/// holding the ARC instance instead of an identity. Each field is named
/// after its tag.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    /// `i=`: ARC instance number, 1 to 50.
    pub i: u32,
    /// `a=`: signing algorithm.
    pub a: Algorithm,
    /// `d=`: signing domain.
    pub d: String,
    /// `s=`: selector; the key is fetched from `<s>._domainkey.<d>`.
    pub s: String,
    /// `b=`: signature bytes (base64-decoded).
    pub b: Vec<u8>,
    /// `bh=`: hash of the canonicalized body (base64-decoded).
    pub bh: Vec<u8>,
    /// `h=`: names of the signed header fields, in signing order.
    pub h: Vec<String>,
    /// `z=`: copied header fields (quoted-printable decoded), for diagnostics.
    pub z: Vec<String>,
    /// `l=`: number of body bytes covered by the body hash; `0` when absent
    /// (whole body).
    pub l: u64,
    /// `x=`: expiration time in seconds since the Unix epoch; `0` when absent.
    pub x: u64,
    /// `t=`: signing time in seconds since the Unix epoch; `0` when absent.
    pub t: u64,
    /// Header canonicalization, first half of `c=`.
    pub ch: Canonicalization,
    /// Body canonicalization, second half of `c=`.
    pub cb: Canonicalization,
}

/// An `ARC-Seal` (RFC 8617, Section 4.1.3).
///
/// Parsed from an incoming header with [`Seal::parse`] (reachable through
/// [`ChainLink::seal`]) or produced by [`ArcSealer::seal`] in a
/// [`SealedSet`]. The seal signs every ARC header of the chain up to and
/// including its own instance, always with `relaxed` header
/// canonicalization. Each field is named after its tag.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Seal {
    /// `i=`: ARC instance number, 1 to 50.
    pub i: u32,
    /// `a=`: signing algorithm.
    pub a: Algorithm,
    /// `b=`: signature bytes (base64-decoded).
    pub b: Vec<u8>,
    /// `d=`: signing domain.
    pub d: String,
    /// `s=`: selector; the key is fetched from `<s>._domainkey.<d>`.
    pub s: String,
    /// `t=`: signing time in seconds since the Unix epoch; `0` when absent.
    pub t: u64,
    /// `cv=`: chain validation status of the previous sets when this seal
    /// was added.
    pub cv: ChainValidation,
}

/// An `ARC-Authentication-Results` header (RFC 8617, Section 4.1.1).
///
/// Parsed from an incoming header with [`ArcAuthResults::parse`] and
/// reachable through [`ChainLink::results`]. Only the instance tag is
/// parsed; the recorded results are kept verbatim in the header value.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArcAuthResults {
    /// `i=`: ARC instance number, 1 to 50.
    pub i: u32,
}

/// A freshly sealed ARC set, returned by [`ArcSealer::seal`].
///
/// Write it in front of the message with
/// [`HeaderWriter`](crate::headers::HeaderWriter): it emits the
/// `ARC-Seal`, `ARC-Message-Signature` and `ARC-Authentication-Results`
/// headers, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSet<'x> {
    /// The new `ARC-Message-Signature`.
    pub signature: Signature,
    /// The new `ARC-Seal`.
    pub seal: Seal,
    /// The results written as the new `ARC-Authentication-Results`.
    pub results: &'x AuthenticationResults<'x>,
}

/// One ARC set of an incoming chain.
///
/// Returned, oldest first, by [`ArcOutput::chain`]. Each field keeps the raw
/// header name and value next to the parsed tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink<'x> {
    /// The `ARC-Message-Signature` of this instance.
    pub signature: Header<'x, &'x Signature>,
    /// The `ARC-Seal` of this instance.
    pub seal: Header<'x, &'x Seal>,
    /// The `ARC-Authentication-Results` of this instance.
    pub results: Header<'x, &'x ArcAuthResults>,
}

/// The `cv=` tag of an `ARC-Seal` (RFC 8617, Section 4.4).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum ChainValidation {
    /// `cv=none`: no previous chain; required on instance 1.
    #[default]
    None,
    /// `cv=fail`: the previous chain did not validate; no further sets may
    /// be added.
    Fail,
    /// `cv=pass`: the previous chain validated.
    Pass,
}

impl VerifySignature for Signature {
    fn signature(&self) -> &[u8] {
        &self.b
    }

    fn algorithm(&self) -> Algorithm {
        self.a
    }

    fn selector(&self) -> &str {
        &self.s
    }

    fn domain(&self) -> &str {
        &self.d
    }
}

impl VerifySignature for Seal {
    fn signature(&self) -> &[u8] {
        &self.b
    }

    fn algorithm(&self) -> Algorithm {
        self.a
    }

    fn selector(&self) -> &str {
        &self.s
    }

    fn domain(&self) -> &str {
        &self.d
    }
}
