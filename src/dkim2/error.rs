/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::Dkim2Hash;
use std::fmt::{Display, Formatter};

/// Reason a DKIM2 header field failed to parse, a DKIM2 chain failed
/// verification or a message could not be signed.
///
/// Carried as [`Error::Dkim2`](crate::Error::Dkim2) inside a
/// [`Dkim2Result`](super::Dkim2Result) or returned by the parsing and signing
/// functions. The `i` payloads are the `i=` of the signature involved and the
/// `m` payloads the `m=` of the instance involved. The
/// [`Display`] text is the human-readable string of §14 without the
/// `PERMERROR:`/`FAIL:` prefix, which [`Dkim2Result`](super::Dkim2Result)
/// conveys.
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
    /// The `Message-Instance` has a higher `m=` than any signature.
    InstanceNotSigned(u32),
    /// The `Message-Instance` lists the same hash algorithm twice.
    InstanceDuplicateHash(u32),
    /// The recipe (`r=` tag) of the `Message-Instance` is not valid JSON.
    InvalidJson(u32),
    /// The recipe (`r=` tag) of the `Message-Instance` is valid JSON but does
    /// not follow the recipe rules (§5).
    InvalidRecipe {
        /// Revision number (`m=`) of the instance.
        m: u32,
        /// The start of the recipe JSON, at most 64 bytes.
        value: Box<str>,
    },
    /// An `h=` hash name is not an algorithm this crate implements.
    UnknownHash {
        /// Revision number (`m=`) of the instance.
        m: u32,
        /// The unknown hash name.
        name: Box<str>,
    },
    /// No `|`-separated group of `h=` hashes passed.
    NoHashGroupPassed(u32),
    /// No `DKIM2-Signature` with this `i=`, for example a message with a
    /// `Message-Instance` but no signature.
    SignatureMissing(u32),
    /// The `DKIM2-Signature` has a syntax error, a repeated tag, an
    /// undecodable value, an invalid nonce, an address without angle
    /// brackets, or an `m=` lower than that of the previous signature.
    SignatureSyntax(u32),
    /// A required `DKIM2-Signature` tag is missing.
    SignatureTagMissing {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Name of the missing tag.
        tag: &'static str,
    },
    /// A `DKIM2-Signature` tag is not allowed in this position, such as
    /// `nd=` together with `mf=`/`rt=`, `nd=` on the most recent signature,
    /// or the `exploded` flag (`f=`) on the first signature.
    SignatureTagUnexpected {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Name of the unexpected tag.
        tag: &'static str,
    },
    /// The `s=` tag names the same selector twice.
    DuplicateSelector(u32),
    /// The `s=` tag has more than eight entries, a local limit on the public
    /// key lookups a signature can cause.
    TooManySelectors(u32),
    /// The signature sequence numbering does not run from 1 without gaps;
    /// carries the first missing `i=`.
    SequenceGap(u32),
    /// A new signature or instance number would exceed `u32::MAX`.
    SequenceOverflow,
    /// The message has more than 50 `DKIM2-Signature` or `Message-Instance`
    /// header fields.
    ChainTooLong,
    /// The signature timestamp (`t=`) is more than 14 days old.
    SignatureExpired(u32),
    /// The signature timestamp (`t=`) is more than one day in the future.
    SignatureFromFuture(u32),
    /// The SMTP `MAIL FROM` does not match `mf=` of the most recent
    /// signature.
    MailFromMismatch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// The SMTP `MAIL FROM` value.
        value: Box<str>,
    },
    /// An SMTP `RCPT TO` address is not listed in `rt=` of the most recent
    /// signature.
    RcptToMismatch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// The SMTP `RCPT TO` value.
        value: Box<str>,
    },
    /// The `mf=` domain is neither `d=` nor a subdomain of it (§10.8).
    MailFromDomainMismatch(u32),
    /// `d=` differs from the `nd=` of the previous signature.
    NextDomainMismatch(u32),
    /// The `mf=` domain does not relaxed-match any `rt=` recipient of the
    /// previous signature (§7.1).
    CustodyMailFromMismatch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Sequence number (`i=`) of the previous signature.
        previous: u32,
    },
    /// No `rt=` recipient of the previous signature relaxed-matches `d=`,
    /// for a signature with a null `mf=` or with `nd=` (§7.1).
    CustodyDomainMismatch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Sequence number (`i=`) of the previous signature.
        previous: u32,
    },
    /// The public key lookup failed with a temporary DNS error.
    PublicKeyFetch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The public key record does not exist.
    PublicKeyMissing {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The selector has more than one TXT record.
    PublicKeyMultiple {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The public key record has a syntax error.
    PublicKeySyntax {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The public key is malformed: an Ed25519 key that is not 32 octets, an
    /// ML-DSA-44 key that is not 1312 octets, an RSA key that cannot be
    /// decoded or is shorter than 1024 bits (§14.5).
    PublicKeyMalformed {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The public key type (`k=`) does not match the `s=` algorithm.
    PublicKeyAlgorithmMismatch {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// The public key record has an empty `p=` tag (revoked key).
    PublicKeyRevoked {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the key.
        selector: Box<str>,
    },
    /// An `s=` signature value does not verify.
    IncorrectSignature {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the entry that failed.
        selector: Box<str>,
    },
    /// An `s=` entry names an algorithm this crate does not implement.
    UnknownAlgorithm {
        /// Sequence number (`i=`) of the signature.
        i: u32,
        /// Selector of the entry.
        selector: Box<str>,
    },
    /// No `|`-separated group of `s=` signatures passed.
    NoSignatureGroupPassed(u32),
    /// The header fields hash does not match the `Message-Instance`.
    HeaderHashMismatch {
        /// Revision number (`m=`) of the instance.
        m: u32,
        /// Hash algorithm that did not match.
        hash: Dkim2Hash,
    },
    /// The body hash does not match the `Message-Instance`.
    BodyHashMismatch {
        /// Revision number (`m=`) of the instance.
        m: u32,
        /// Hash algorithm that did not match.
        hash: Dkim2Hash,
    },
    /// A `Message-Instance` with this `m=` has a null body recipe, so the
    /// body hashes of the instances below it cannot be checked and the
    /// message is not a Fully Verified DKIM2 Message (§13).
    NullBodyRecipe(u32),
    /// A `From` header field is not Authentic (§11): its domain does not
    /// relaxed-match `d=` of the signature that covers it, or it has no
    /// single address with a domain name.
    FromNotAuthentic(u32),
    /// [`Recipe::diff`](super::Recipe::diff) found a changed header field
    /// value with a bare CR or LF outside folding, which a recipe cannot
    /// recreate.
    HeaderNotRepresentable,
    /// [`Recipe::apply`](super::Recipe::apply) found a body recipe that
    /// declares the previous body unreconstructable (`"b": null`).
    BodyUnreconstructable,
    /// A recipe could not be serialized to or parsed from JSON, or does not
    /// follow the recipe schema (§5).
    RecipeSyntax,
    /// The message to sign already has DKIM2 header fields but no passing
    /// full verification of it was supplied, and the signer has no
    /// out-of-band arrangement (§12).
    NotFullyVerified,
}

impl Display for Dkim2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Dkim2Error::InstanceMissing(m) => write!(f, "Message-Instance m={m} missing"),
            Dkim2Error::InstanceSyntax(m) => write!(f, "Message-Instance m={m} syntax error"),
            Dkim2Error::InstanceTagMissing { m, tag } => {
                write!(f, "Message-Instance m={m} tag={tag} missing")
            }
            Dkim2Error::InstanceNotSigned(m) => write!(f, "Message-Instance m={m} is not signed"),
            Dkim2Error::InstanceDuplicateHash(m) => {
                write!(f, "Message-Instance m={m} has a duplicate hash algorithm")
            }
            Dkim2Error::InvalidJson(m) => {
                write!(f, "Message-Instance m={m} contains invalid JSON")
            }
            Dkim2Error::InvalidRecipe { m, value } => {
                write!(f, "Message-Instance m={m} Recipe {value} is invalid")
            }
            Dkim2Error::UnknownHash { m, name } => {
                write!(f, "Message-Instance m={m} algorithm {name} unknown")
            }
            Dkim2Error::NoHashGroupPassed(m) => {
                write!(f, "Message-Instance m={m} no group of hashes passed")
            }
            Dkim2Error::SignatureMissing(i) => write!(f, "DKIM2-Signature i={i} missing"),
            Dkim2Error::SignatureSyntax(i) => write!(f, "DKIM2-Signature i={i} syntax error"),
            Dkim2Error::SignatureTagMissing { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} missing")
            }
            Dkim2Error::SignatureTagUnexpected { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} was unexpected")
            }
            Dkim2Error::DuplicateSelector(i) => {
                write!(f, "DKIM2-Signature i={i} has a duplicate selector")
            }
            Dkim2Error::TooManySelectors(i) => {
                write!(f, "DKIM2-Signature i={i} has more selectors than allowed")
            }
            Dkim2Error::SequenceGap(i) => write!(f, "DKIM2-Signature i={i} missing"),
            Dkim2Error::SequenceOverflow => {
                write!(f, "DKIM2 sequence numbering would overflow")
            }
            Dkim2Error::ChainTooLong => write!(f, "Too many DKIM2 header fields"),
            Dkim2Error::SignatureExpired(i) => write!(f, "DKIM2-Signature i={i} signature expired"),
            Dkim2Error::SignatureFromFuture(i) => {
                write!(f, "DKIM2-Signature i={i} signature is from the future")
            }
            Dkim2Error::MailFromMismatch { i, value } => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM {value} did not match")
            }
            Dkim2Error::RcptToMismatch { i, value } => {
                write!(f, "DKIM2-Signature i={i} RCPT TO {value} did not match")
            }
            Dkim2Error::MailFromDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM and d= do not match")
            }
            Dkim2Error::NextDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} nd= does not match")
            }
            Dkim2Error::CustodyMailFromMismatch { i, previous } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} mf= does not match the rt= of i={previous}"
                )
            }
            Dkim2Error::CustodyDomainMismatch { i, previous } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} d= does not match the rt= of i={previous}"
                )
            }
            Dkim2Error::PublicKeyFetch { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} could not be fetched"
                )
            }
            Dkim2Error::PublicKeyMissing { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} does not exist"
                )
            }
            Dkim2Error::PublicKeyMultiple { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} has multiple records"
                )
            }
            Dkim2Error::PublicKeySyntax { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} has a syntax error"
                )
            }
            Dkim2Error::PublicKeyMalformed { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} is malformed"
                )
            }
            Dkim2Error::PublicKeyAlgorithmMismatch { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} algorithm mismatch"
                )
            }
            Dkim2Error::PublicKeyRevoked { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} public key {selector} has been revoked"
                )
            }
            Dkim2Error::IncorrectSignature { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} selector {selector} incorrect signature"
                )
            }
            Dkim2Error::UnknownAlgorithm { i, selector } => {
                write!(
                    f,
                    "DKIM2-Signature i={i} selector {selector} algorithm unknown"
                )
            }
            Dkim2Error::NoSignatureGroupPassed(i) => {
                write!(f, "DKIM2-Signature i={i} no group of signatures passed")
            }
            Dkim2Error::HeaderHashMismatch { m, hash } => {
                write!(
                    f,
                    "Message-Instance m={m} header hash {} mismatch",
                    hash.name()
                )
            }
            Dkim2Error::BodyHashMismatch { m, hash } => {
                write!(
                    f,
                    "Message-Instance m={m} body hash {} mismatch",
                    hash.name()
                )
            }
            Dkim2Error::NullBodyRecipe(m) => {
                write!(
                    f,
                    "Message-Instance m={m} has a null Recipe, earlier body hashes cannot be checked"
                )
            }
            Dkim2Error::FromNotAuthentic(i) => {
                write!(f, "DKIM2-Signature i={i} matching From is not authentic")
            }
            Dkim2Error::HeaderNotRepresentable => {
                write!(
                    f,
                    "Changed header field has a bare CR or LF and cannot be recorded in a recipe"
                )
            }
            Dkim2Error::BodyUnreconstructable => {
                write!(f, "Message body cannot be reconstructed (null body recipe)")
            }
            Dkim2Error::RecipeSyntax => write!(f, "Message-Instance recipe syntax error"),
            Dkim2Error::NotFullyVerified => {
                write!(f, "Message is not a Fully Verified DKIM2 Message")
            }
        }
    }
}
