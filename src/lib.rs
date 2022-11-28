/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    cell::Cell,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::SystemTime,
};

use arc::Set;
use common::{headers::Header, lru::LruCache};
use dkim::{Atps, Canonicalization, DomainKey, HashAlgorithm};
use dmarc::DMARC;
use rsa::RsaPrivateKey;
use spf::{Macro, SPF};
use trust_dns_resolver::{proto::op::ResponseCode, TokioAsyncResolver};

pub mod arc;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod report;
pub mod spf;

#[derive(Debug)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::Keypair),
    None,
}
#[derive(Debug)]
pub struct Resolver {
    pub(crate) resolver: TokioAsyncResolver,
    pub(crate) cache_txt: LruCache<String, Txt>,
    pub(crate) cache_mx: LruCache<String, Arc<Vec<MX>>>,
    pub(crate) cache_ipv4: LruCache<String, Arc<Vec<Ipv4Addr>>>,
    pub(crate) cache_ipv6: LruCache<String, Arc<Vec<Ipv6Addr>>>,
    pub(crate) cache_ptr: LruCache<IpAddr, Arc<Vec<String>>>,
    pub(crate) host_domain: String,
    pub(crate) verify_policy: Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum Txt {
    SPF(Arc<SPF>),
    SPFMacro(Arc<Macro>),
    DomainKey(Arc<DomainKey>),
    DMARC(Arc<DMARC>),
    Atps(Arc<Atps>),
    Error(Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MX {
    exchange: String,
    preference: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Relaxed,
    Strict,
    VeryStrict,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<String>,
    pub(crate) body: &'x [u8],
    pub(crate) body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub(crate) dkim_headers: Vec<Header<'x, crate::Result<dkim::Signature<'x>>>>,
    pub(crate) ams_headers: Vec<Header<'x, crate::Result<arc::Signature<'x>>>>,
    pub(crate) as_headers: Vec<Header<'x, crate::Result<arc::Seal<'x>>>>,
    pub(crate) aar_headers: Vec<Header<'x, crate::Result<arc::Results>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Authentication-Results header
pub struct AuthenticationResults<'x> {
    pub(crate) hostname: &'x str,
    pub(crate) auth_results: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Received-SPF header
pub struct ReceivedSPF {
    pub(crate) received_spf: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DKIMResult {
    Pass,
    Neutral(crate::Error),
    Fail(crate::Error),
    PermError(crate::Error),
    TempError(crate::Error),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DKIMOutput<'x> {
    result: DKIMResult,
    signature: Option<&'x dkim::Signature<'x>>,
    report: Option<String>,
    is_atps: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ARCOutput<'x> {
    result: DKIMResult,
    set: Vec<Set<'x>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SPFResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SPFOutput {
    result: SPFResult,
    report: Option<String>,
    explanation: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DMARCOutput {
    result: DMARCResult,
    domain: String,
    policy: dmarc::Policy,
    record: Option<Arc<DMARC>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DMARCResult {
    Pass,
    Fail(crate::Error),
    TempError(crate::Error),
    PermError(crate::Error),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Version {
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    CryptoError(String),
    Io(String),
    Base64,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCanonicalization,
    UnsupportedKeyType,
    FailedBodyHashMatch,
    FailedVerification,
    FailedAUIDMatch,
    RevokedPublicKey,
    IncompatibleAlgorithms,
    SignatureExpired,

    DNSError,
    DNSRecordNotFound(ResponseCode),

    ARCChainTooLong,
    ARCInvalidInstance(u32),
    ARCInvalidCV,
    ARCHasHeaderTag,
    ARCBrokenChain,

    DMARCNotAligned,

    InvalidRecordType,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError => write!(f, "Parse error"),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::NoHeadersFound => write!(f, "No headers found"),
            Error::CryptoError(err) => write!(f, "Cryptography layer error: {}", err),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Base64 => write!(f, "Base64 encode or decode error."),
            Error::UnsupportedVersion => write!(f, "Unsupported version in DKIM Signature."),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm in DKIM Signature."),
            Error::UnsupportedCanonicalization => {
                write!(f, "Unsupported canonicalization method in DKIM Signature.")
            }
            Error::UnsupportedKeyType => {
                write!(f, "Unsupported key type in DKIM DNS record.")
            }
            Error::FailedBodyHashMatch => {
                write!(f, "Calculated body hash does not match signature hash.")
            }
            Error::RevokedPublicKey => write!(f, "Public key for this signature has been revoked."),
            Error::IncompatibleAlgorithms => write!(
                f,
                "Incompatible algorithms used in signature and DKIM DNS record."
            ),
            Error::FailedVerification => write!(f, "Signature verification failed."),
            Error::SignatureExpired => write!(f, "Signature expired."),
            Error::FailedAUIDMatch => write!(f, "AUID does not match domain name."),
            Error::ARCInvalidInstance(i) => {
                write!(f, "Invalid 'i={}' value found in ARC header.", i)
            }
            Error::ARCInvalidCV => write!(f, "Invalid 'cv=' value found in ARC header."),
            Error::ARCHasHeaderTag => write!(f, "Invalid 'h=' tag present in ARC-Seal."),
            Error::ARCBrokenChain => write!(f, "Broken or missing ARC chain."),
            Error::ARCChainTooLong => write!(f, "Too many ARC headers."),
            Error::InvalidRecordType => write!(f, "Invalid record."),
            Error::DNSError => write!(f, "DNS resolution error."),
            Error::DNSRecordNotFound(code) => write!(f, "DNS record not found: {}.", code),
            Error::DMARCNotAligned => write!(f, "DMARC policy not aligned."),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

thread_local!(static COUNTER: Cell<u64>  = Cell::new(0));

pub(crate) fn is_within_pct(pct: u8) -> bool {
    pct == 100
        || COUNTER.with(|c| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .wrapping_add(c.replace(c.get() + 1))
                .wrapping_mul(11400714819323198485u64)
        }) % 100
            < pct as u64
}
