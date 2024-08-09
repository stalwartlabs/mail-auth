/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#![doc = include_str!("../README.md")]

use std::{
    cell::Cell,
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::SystemTime,
};

use arc::Set;
use common::{crypto::HashAlgorithm, headers::Header, lru::LruCache, verify::DomainKey};
use dkim::{Atps, Canonicalization, DomainKeyReport};
use dmarc::Dmarc;
use hickory_resolver::{
    proto::{error::ProtoError, op::ResponseCode},
    TokioAsyncResolver,
};
use mta_sts::{MtaSts, TlsRpt};
use parking_lot::Mutex;
use spf::{Macro, Spf};

pub mod arc;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod mta_sts;
pub mod report;
pub mod spf;

pub use flate2;
pub use hickory_resolver;
pub use zip;

pub struct Resolver {
    pub(crate) resolver: TokioAsyncResolver,
    pub(crate) cache_txt: LruCache<String, Txt>,
    pub(crate) cache_mx: LruCache<String, Arc<Vec<MX>>>,
    pub(crate) cache_ipv4: LruCache<String, Arc<Vec<Ipv4Addr>>>,
    pub(crate) cache_ipv6: LruCache<String, Arc<Vec<Ipv6Addr>>>,
    pub(crate) cache_ptr: LruCache<IpAddr, Arc<Vec<String>>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum IpLookupStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    //Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    #[default]
    Ipv4thenIpv6,
}

#[derive(Clone)]
pub enum Txt {
    Spf(Arc<Spf>),
    SpfMacro(Arc<Macro>),
    DomainKey(Arc<DomainKey>),
    DomainKeyReport(Arc<DomainKeyReport>),
    Dmarc(Arc<Dmarc>),
    Atps(Arc<Atps>),
    MtaSts(Arc<MtaSts>),
    TlsRpt(Arc<TlsRpt>),
    Error(Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MX {
    pub exchanges: Vec<String>,
    pub preference: u16,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedMessage<'x> {
    pub headers: Vec<(&'x [u8], &'x [u8])>,
    pub from: Vec<String>,
    pub raw_message: &'x [u8],
    pub body_offset: usize,
    pub body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub dkim_headers: Vec<Header<'x, crate::Result<dkim::Signature>>>,
    pub ams_headers: Vec<Header<'x, crate::Result<arc::Signature>>>,
    pub as_headers: Vec<Header<'x, crate::Result<arc::Seal>>>,
    pub aar_headers: Vec<Header<'x, crate::Result<arc::Results>>>,
    pub received_headers_count: usize,
    pub date_header_present: bool,
    pub message_id_header_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Authentication-Results header
pub struct AuthenticationResults<'x> {
    pub(crate) hostname: &'x str,
    pub(crate) auth_results: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Received-SPF header
pub struct ReceivedSpf {
    pub(crate) received_spf: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DkimResult {
    Pass,
    Neutral(crate::Error),
    Fail(crate::Error),
    PermError(crate::Error),
    TempError(crate::Error),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DkimOutput<'x> {
    result: DkimResult,
    signature: Option<&'x dkim::Signature>,
    report: Option<String>,
    is_atps: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArcOutput<'x> {
    result: DkimResult,
    set: Vec<Set<'x>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpfOutput {
    result: SpfResult,
    domain: String,
    report: Option<String>,
    explanation: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DmarcOutput {
    spf_result: DmarcResult,
    dkim_result: DmarcResult,
    domain: String,
    policy: dmarc::Policy,
    record: Option<Arc<Dmarc>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DmarcResult {
    Pass,
    Fail(crate::Error),
    TempError(crate::Error),
    PermError(crate::Error),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IprevOutput {
    pub result: IprevResult,
    pub ptr: Option<Arc<Vec<String>>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IprevResult {
    Pass,
    Fail(crate::Error),
    TempError(crate::Error),
    PermError(crate::Error),
    None,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum Version {
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
    FailedAuidMatch,
    RevokedPublicKey,
    IncompatibleAlgorithms,
    SignatureExpired,
    SignatureLength,
    DnsError(String),
    DnsRecordNotFound(ResponseCode),
    ArcChainTooLong,
    ArcInvalidInstance(u32),
    ArcInvalidCV,
    ArcHasHeaderTag,
    ArcBrokenChain,
    NotAligned,
    InvalidRecordType,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError => write!(f, "Parse error"),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::NoHeadersFound => write!(f, "No headers found"),
            Error::CryptoError(err) => write!(f, "Cryptography layer error: {err}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Base64 => write!(f, "Base64 encode or decode error."),
            Error::UnsupportedVersion => write!(f, "Unsupported version in DKIM Signature"),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm in DKIM Signature"),
            Error::UnsupportedCanonicalization => {
                write!(f, "Unsupported canonicalization method in DKIM Signature")
            }
            Error::UnsupportedKeyType => {
                write!(f, "Unsupported key type in DKIM DNS record")
            }
            Error::FailedBodyHashMatch => {
                write!(f, "Calculated body hash does not match signature hash")
            }
            Error::RevokedPublicKey => write!(f, "Public key for this signature has been revoked"),
            Error::IncompatibleAlgorithms => write!(
                f,
                "Incompatible algorithms used in signature and DKIM DNS record"
            ),
            Error::FailedVerification => write!(f, "Signature verification failed"),
            Error::SignatureExpired => write!(f, "Signature expired"),
            Error::SignatureLength => write!(f, "Insecure 'l=' tag found in Signature"),
            Error::FailedAuidMatch => write!(f, "AUID does not match domain name"),
            Error::ArcInvalidInstance(i) => {
                write!(f, "Invalid 'i={i}' value found in ARC header")
            }
            Error::ArcInvalidCV => write!(f, "Invalid 'cv=' value found in ARC header"),
            Error::ArcHasHeaderTag => write!(f, "Invalid 'h=' tag present in ARC-Seal"),
            Error::ArcBrokenChain => write!(f, "Broken or missing ARC chain"),
            Error::ArcChainTooLong => write!(f, "Too many ARC headers"),
            Error::InvalidRecordType => write!(f, "Invalid record"),
            Error::DnsError(err) => write!(f, "DNS resolution error: {err}"),
            Error::DnsRecordNotFound(code) => write!(f, "DNS record not found: {code}"),
            Error::NotAligned => write!(f, "Policy not aligned"),
        }
    }
}

impl Display for SpfResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SpfResult::Pass => "Pass",
            SpfResult::Fail => "Fail",
            SpfResult::SoftFail => "SoftFail",
            SpfResult::Neutral => "Neutral",
            SpfResult::TempError => "TempError",
            SpfResult::PermError => "PermError",
            SpfResult::None => "None",
        })
    }
}

impl Display for IprevResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IprevResult::Pass => f.write_str("pass"),
            IprevResult::Fail(err) => write!(f, "fail; {err}"),
            IprevResult::TempError(err) => write!(f, "temp error; {err}"),
            IprevResult::PermError(err) => write!(f, "perm error; {err}"),
            IprevResult::None => f.write_str("none"),
        }
    }
}

impl Display for DkimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimResult::Pass => f.write_str("pass"),
            DkimResult::Fail(err) => write!(f, "fail; {err}"),
            DkimResult::Neutral(err) => write!(f, "neutral; {err}"),
            DkimResult::TempError(err) => write!(f, "temp error; {err}"),
            DkimResult::PermError(err) => write!(f, "perm error; {err}"),
            DkimResult::None => f.write_str("none"),
        }
    }
}

impl Display for DmarcResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmarcResult::Pass => f.write_str("pass"),
            DmarcResult::Fail(err) => write!(f, "fail; {err}"),
            DmarcResult::TempError(err) => write!(f, "temp error; {err}"),
            DmarcResult::PermError(err) => write!(f, "perm error; {err}"),
            DmarcResult::None => f.write_str("none"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<ProtoError> for Error {
    fn from(err: ProtoError) -> Self {
        Error::DnsError(err.to_string())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

#[cfg(feature = "ed25519-dalek")]
impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

impl Default for SpfOutput {
    fn default() -> Self {
        Self {
            result: SpfResult::None,
            domain: Default::default(),
            report: Default::default(),
            explanation: Default::default(),
        }
    }
}

thread_local!(static COUNTER: Cell<u64>  = const { Cell::new(0) });

/// Generates a random value between 0 and 100.
/// Returns true if the generated value is within the requested
/// sampling percentage specified in a SPF, DKIM or DMARC policy.
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

impl Clone for Resolver {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            cache_txt: Mutex::new(self.cache_txt.lock().clone()),
            cache_mx: Mutex::new(self.cache_mx.lock().clone()),
            cache_ipv4: Mutex::new(self.cache_ipv4.lock().clone()),
            cache_ipv6: Mutex::new(self.cache_ipv6.lock().clone()),
            cache_ptr: Mutex::new(self.cache_ptr.lock().clone()),
        }
    }
}
