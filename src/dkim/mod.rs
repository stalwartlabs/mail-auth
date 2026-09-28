/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM1 signing and verification.
//!
//! Implements DomainKeys Identified Mail as specified by:
//!
//! - RFC 6376: DomainKeys Identified Mail (DKIM) Signatures.
//! - RFC 8301: Cryptographic Algorithm and Key Usage Update to DKIM.
//! - RFC 8463: A New Cryptographic Signature Method for DKIM (Ed25519-SHA256).
//! - RFC 6651: Extensions to DKIM for Failure Reporting (`r=` tag and
//!   `_report._domainkey` records).
//! - RFC 6541: DKIM Authorized Third-Party Signatures (ATPS).
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).
//! - RFC 5672: DKIM Signatures, Update.
//! - RFC 4686, RFC 5016, RFC 5585, RFC 5863 and RFC 6377: threat analysis,
//!   requirements, service overview, operations and mailing list guidance.
//!
//! Messages are signed with [`DkimSigner`], which produces a [`Signature`]
//! that is written as a `DKIM-Signature` header. Messages are verified with
//! [`MessageAuthenticator::verify_dkim`](crate::MessageAuthenticator::verify_dkim),
//! which returns one [`DkimOutput`] per signature.

use crate::{
    crypto::{Algorithm, HashAlgorithm, SigningKey},
    signer::NeedDomain,
};

pub mod builder;
pub mod canonicalize;
#[cfg(feature = "generate")]
pub mod generate;
pub mod headers;
pub mod output;
pub mod parse;
pub mod record;
pub mod sign;
pub mod streaming;
pub mod verify;

pub use output::{DkimOutput, DkimResult};
pub use record::{AtpsRecord, DkimReportRecord, DomainKey, VerifySignature};
pub(crate) use record::{
    Flag, RR_DNS, RR_EXPIRATION, RR_OTHER, RR_POLICY, RR_SIGNATURE, RR_UNKNOWN_TAG,
    RR_VERIFICATION, Service,
};
pub use streaming::DkimSigningStream;

/// A DKIM canonicalization algorithm (RFC 6376, Section 3.4).
///
/// Selected separately for the header and the body through the `c=` tag of
/// a `DKIM-Signature` header (`c=<header>/<body>`). Signers default to
/// `relaxed`; when `c=` is absent from a parsed signature, `simple` applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Canonicalization {
    /// `relaxed` (RFC 6376, Sections 3.4.2 and 3.4.4): tolerates common
    /// whitespace changes and header name case changes.
    #[default]
    Relaxed,
    /// `simple` (RFC 6376, Sections 3.4.1 and 3.4.3): tolerates almost no
    /// modification; only trailing empty body lines are ignored.
    Simple,
}

/// A DKIM1 specific failure, carried by [`Error::Dkim`](crate::Error::Dkim).
///
/// Produced while parsing a `DKIM-Signature` header or a `_domainkey` key
/// record, and while verifying a signature.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DkimError {
    /// The `v=` tag of the signature is not `1` (RFC 6376, Section 3.5).
    UnsupportedVersion,
    /// The `a=` tag names an algorithm this crate does not implement
    /// (supported: `rsa-sha256`, `rsa-sha1` and `ed25519-sha256`).
    UnsupportedAlgorithm,
    /// The `c=` tag names an unknown canonicalization algorithm.
    UnsupportedCanonicalization,
    /// The `k=` tag of the key record names an unknown key type (supported:
    /// `rsa` and `ed25519`).
    UnsupportedKeyType,
    /// The body hash computed from the message does not match the `bh=` tag
    /// (RFC 6376, Section 6.1.3).
    BodyHashMismatch,
    /// The domain of the `i=` tag is not `d=` or a subdomain of it, or the key
    /// record has `t=s` and the domains are not identical (RFC 6376,
    /// Section 3.5).
    AuidMismatch,
    /// The key record has an empty `p=` tag, meaning the key was revoked
    /// (RFC 6376, Section 3.6.1).
    PublicKeyRevoked,
    /// The `x=` expiration time has passed, or is not later than `t=`
    /// (RFC 6376, Section 3.5).
    SignatureExpired,
    /// An `l=` body length tag was present and strict parsing ignores such
    /// signatures, since content can be appended after the signed length.
    BodyLengthTag,
}

impl std::fmt::Display for DkimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimError::UnsupportedVersion => write!(f, "Unsupported version in DKIM Signature"),
            DkimError::UnsupportedAlgorithm => {
                write!(f, "Unsupported algorithm in DKIM Signature")
            }
            DkimError::UnsupportedCanonicalization => {
                write!(f, "Unsupported canonicalization method in DKIM Signature")
            }
            DkimError::UnsupportedKeyType => write!(f, "Unsupported key type in DKIM DNS record"),
            DkimError::BodyHashMismatch => {
                write!(f, "Calculated body hash does not match signature hash")
            }
            DkimError::AuidMismatch => write!(f, "AUID does not match domain name"),
            DkimError::PublicKeyRevoked => {
                write!(f, "Public key for this signature has been revoked")
            }
            DkimError::SignatureExpired => write!(f, "Signature expired"),
            DkimError::BodyLengthTag => write!(f, "Insecure 'l=' tag found in Signature"),
        }
    }
}

/// A DKIM1 message signer (RFC 6376, Section 5).
///
/// Built from a signing key with [`DkimSigner::from_key`], then configured
/// in a fixed order that the type state enforces:
/// `DkimSigner::from_key(key).domain(..).selector(..).headers(..)` yields a
/// `DkimSigner<_, signer::Ready>`. Only a `Ready` signer can sign, and only a
/// `Ready` signer accepts the optional settings (`atps`, `atps_hash`,
/// `identity`, `expiration`, `body_length`, `reporting`,
/// `header_canonicalization`, `body_canonicalization`).
///
/// Defaults: `relaxed/relaxed` canonicalization, no expiration (`x=`
/// omitted), no body length (`l=` omitted), no failure reports requested
/// (`r=` omitted), no ATPS and no `i=` tag. The algorithm is taken from the
/// key.
///
/// Signing returns a [`Signature`]; write it in front of the message as a
/// `DKIM-Signature` header with
/// [`HeaderWriter`](crate::headers::HeaderWriter).
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{crypto::Ed25519Key, dkim::DkimSigner, headers::HeaderWriter};
///
/// # fn main() -> mail_auth::Result<()> {
/// # let pkcs8_der: Vec<u8> = Vec::new();
/// let message = b"From: bill@example.com\r\nTo: jdoe@example.com\r\n\
///     Subject: TPS Report\r\n\r\nHello.\r\n";
/// let key = Ed25519Key::from_pkcs8_der(&pkcs8_der)?;
/// let signature = DkimSigner::from_key(key)
///     .domain("example.com")
///     .selector("ed")
///     .headers(["From", "To", "Subject"])
///     .sign(message)?;
/// let signed = format!(
///     "{}{}",
///     signature.to_header(),
///     std::str::from_utf8(message).unwrap_or_default()
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DkimSigner<T: SigningKey, State = NeedDomain> {
    _state: std::marker::PhantomData<State>,
    pub(crate) key: T,
    pub(crate) template: Signature,
}

impl<T: SigningKey, State> DkimSigner<T, State> {
    /// Returns the signature template configured so far.
    ///
    /// The template holds the tags that will be copied into every produced
    /// signature. Before signing, `x` holds the validity period in seconds
    /// (not an absolute time) and `l` is `1` when body length signing is
    /// enabled; both are resolved when a message is signed.
    pub fn template(&self) -> &Signature {
        &self.template
    }
}

/// A DKIM1 signature: the tag list of a `DKIM-Signature` header (RFC 6376,
/// Section 3.5).
///
/// Obtained by parsing a header value with [`Signature::parse`], from a
/// verified message through [`DkimOutput::signature`], or as the result of
/// signing with [`DkimSigner`]. It is written back as a header through
/// [`HeaderWriter`](crate::headers::HeaderWriter) or [`Signature::write`].
/// Each field is named after its tag.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    /// `v=`: signature version; `1`, or `0` when the tag is absent from a
    /// parsed header.
    pub v: u32,
    /// `a=`: signing algorithm (RFC 6376, RFC 8301, RFC 8463).
    pub a: Algorithm,
    /// `d=`: signing domain identifier (SDID), the domain claiming
    /// responsibility for the message.
    pub d: String,
    /// `s=`: selector; the key record is looked up at
    /// `<s>._domainkey.<d>`.
    pub s: String,
    /// `b=`: signature data, base64 decoded.
    pub b: Vec<u8>,
    /// `bh=`: hash of the canonicalized body, base64 decoded.
    pub bh: Vec<u8>,
    /// `h=`: names of the signed header fields, in signing order.
    pub h: Vec<String>,
    /// `z=`: copied header fields, as `name:value` strings with quoted
    /// printable decoded (diagnostic only).
    pub z: Vec<String>,
    /// `i=`: agent or user identifier (AUID); empty when absent.
    pub i: String,
    /// `l=`: body length in octets covered by the body hash; `0` means the
    /// tag is absent and the whole body is signed.
    pub l: u64,
    /// `x=`: signature expiration, in seconds since the UNIX epoch; `0`
    /// means no expiration.
    pub x: u64,
    /// `t=`: signing time, in seconds since the UNIX epoch; `0` when absent.
    pub t: u64,
    /// `r=y`: the signer requests failure reports (RFC 6651, Section 3.1).
    pub r: bool,
    /// `atps=`: the domain authorizing this third-party signature (RFC 6541,
    /// Section 4.1).
    pub atps: Option<String>,
    /// `atpsh=`: hash algorithm applied to `d=` when building the ATPS query
    /// name; `None` means `atpsh=none`, where `d=` is used verbatim
    /// (RFC 6541, Section 4.1).
    pub atpsh: Option<HashAlgorithm>,
    /// Header canonicalization, the first half of the `c=` tag.
    pub ch: Canonicalization,
    /// Body canonicalization, the second half of the `c=` tag.
    pub cb: Canonicalization,
}

impl From<HashAlgorithm> for u64 {
    fn from(v: HashAlgorithm) -> Self {
        v as u64
    }
}

impl From<Algorithm> for HashAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
            Algorithm::RsaSha1 => HashAlgorithm::Sha1,
        }
    }
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

impl Signature {
    /// Returns the agent or user identifier (the `i=` tag), or an empty
    /// string when the tag is absent.
    pub fn identity(&self) -> &str {
        &self.i
    }
}
