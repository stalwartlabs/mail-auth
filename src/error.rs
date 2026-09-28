/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::crypto::CryptoError;
#[cfg(not(feature = "dns-doh"))]
use hickory_resolver::proto::op::ResponseCode;
use std::{fmt::Display, io};

/// A DNS lookup failure, carried by [`Error::Dns`].
///
/// Verifiers map these errors to result codes: [`DnsError::Resolver`] becomes
/// a `temperror` result, while [`DnsError::RecordNotFound`] and
/// [`DnsError::InvalidRecordType`] become `none` or `permerror` depending on
/// the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The query could not be completed (network failure, timeout, server
    /// failure). The string holds the resolver's error message. Treated as a
    /// transient error.
    Resolver(String),
    /// The query completed but returned no records of the requested type.
    /// Holds the DNS response code (`NXDOMAIN` or `NOERROR` with an empty
    /// answer section).
    #[cfg(not(feature = "dns-doh"))]
    RecordNotFound(ResponseCode),
    /// The query completed but returned no records of the requested type.
    /// Holds the numeric DNS response code (3 for `NXDOMAIN`).
    #[cfg(feature = "dns-doh")]
    RecordNotFound(u16),
    /// Records were returned, but none of them could be parsed as the expected
    /// record type (for example, a TXT record without `v=spf1` when an SPF
    /// record was requested).
    InvalidRecordType,
}

/// The error type for every fallible operation in this crate.
///
/// Verifiers do not return this type directly; they embed it in their result
/// enums (for example `DkimResult::Fail(Error)`) to explain why a check did not
/// pass. Parsers, signers and DNS lookup helpers return it through [`Result`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A header, DNS record or key could not be parsed.
    Parse,
    /// A required tag or parameter was missing from a header or record.
    MissingParameters,
    /// None of the headers selected for signing are present in the message,
    /// so there is nothing to sign.
    NoHeadersFound,
    /// A Base64 value could not be decoded.
    Base64,
    /// An identifier did not align with the domain it had to match (for
    /// example, `iprev` forward lookups that do not return the client
    /// address, or a DMARC identifier alignment failure).
    NotAligned,
    /// An I/O error. The string holds the underlying error message.
    Io(String),
    /// A signing or verification failure reported by the cryptography backend.
    Crypto(CryptoError),
    /// A DNS lookup failure.
    Dns(DnsError),
    /// A DKIM specific failure (RFC 6376).
    Dkim(crate::dkim::DkimError),
    /// An ARC specific failure (RFC 8617).
    #[cfg(feature = "arc")]
    Arc(crate::arc::ArcError),
    /// A DKIM2 specific failure (draft-ietf-dkim-dkim2-spec).
    Dkim2(crate::dkim2::Dkim2Error),
}

/// A [`std::result::Result`] with the error type fixed to [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse => write!(f, "Parse error"),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::NoHeadersFound => write!(f, "No headers found"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Base64 => write!(f, "Base64 encode or decode error."),
            Error::NotAligned => write!(f, "Policy not aligned"),
            Error::Crypto(e) => e.fmt(f),
            Error::Dns(e) => e.fmt(f),
            Error::Dkim(e) => e.fmt(f),
            #[cfg(feature = "arc")]
            Error::Arc(e) => e.fmt(f),
            Error::Dkim2(e) => e.fmt(f),
        }
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Resolver(err) => write!(f, "DNS resolution error: {err}"),
            DnsError::RecordNotFound(code) => write!(f, "DNS record not found: {code}"),
            DnsError::InvalidRecordType => write!(f, "Invalid record"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::Crypto(CryptoError::Library(err.to_string()))
    }
}
