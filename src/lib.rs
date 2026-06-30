/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![doc = include_str!("../README.md")]

#[cfg(feature = "arc")]
use arc::Set;
use common::{
    crypto::{CryptoError, HashAlgorithm},
    headers::Header,
    verify::DomainKey,
};
use dkim::{Atps, Canonicalization, DomainKeyReport};
use dmarc::Dmarc;
use hickory_resolver::{TokioResolver, proto::op::ResponseCode};
use mta_sts::{MtaSts, TlsRpt};
use spf::{Macro, Spf};
use std::{
    borrow::Borrow,
    cell::Cell,
    fmt::Display,
    hash::Hash,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Instant, SystemTime},
};

#[cfg(feature = "arc")]
pub mod arc;
pub mod common;
pub mod dkim;
pub mod dkim2;
pub mod dmarc;
pub mod mta_sts;
#[cfg(feature = "report")]
pub mod report;
pub mod spf;

pub use flate2;
pub use hickory_resolver;
#[cfg(feature = "report")]
pub use zip;

#[derive(Clone)]
pub struct MessageAuthenticator(pub TokioResolver);

pub struct Parameters<'x, P, TXT, MXX, IPV4, IPV6, PTR>
where
    TXT: ResolverCache<Box<str>, Txt>,
    MXX: ResolverCache<Box<str>, RecordSet<MX>>,
    IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>>,
    IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>>,
    PTR: ResolverCache<IpAddr, RecordSet<Box<str>>>,
{
    pub params: P,
    pub cache_txt: Option<&'x TXT>,
    pub cache_mx: Option<&'x MXX>,
    pub cache_ptr: Option<&'x PTR>,
    pub cache_ipv4: Option<&'x IPV4>,
    pub cache_ipv6: Option<&'x IPV6>,
}

pub trait ResolverCache<K, V>: Sized {
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    fn insert(&self, key: K, value: V, valid_until: Instant);
}

#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq)]
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
pub struct RecordSet<T> {
    pub rrset: Arc<[T]>,
    pub dnssec_status: DnssecStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MX {
    pub exchanges: Box<[Box<str>]>,
    pub preference: u16,
}

#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq)]
#[repr(u16)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    #[default]
    Indeterminate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatedMessage<'x> {
    pub headers: Vec<(&'x [u8], &'x [u8])>,
    pub from: Vec<String>,
    pub raw_message: &'x [u8],
    pub body_offset: u32,
    pub body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub dkim_headers: Vec<Header<'x, dkim::Signature>>,
    pub dkim2_signatures: Vec<Header<'x, dkim2::Signature>>,
    pub dkim2_instances: Vec<Header<'x, dkim2::MessageInstance>>,
    #[cfg(feature = "arc")]
    pub ams_headers: Vec<Header<'x, arc::Signature>>,
    #[cfg(feature = "arc")]
    pub as_headers: Vec<Header<'x, arc::Seal>>,
    #[cfg(feature = "arc")]
    pub aar_headers: Vec<Header<'x, arc::Results>>,
    pub received_headers_count: usize,
    pub date_header_present: bool,
    pub message_id_header_present: bool,
    pub errors: Vec<Header<'x, Error>>,
    pub has_dkim_errors: bool,
    #[cfg(feature = "arc")]
    pub has_arc_errors: bool,
    pub has_dkim2_errors: bool,
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
pub enum Dkim2Result {
    Pass,
    Fail(crate::Error),
    PermError(crate::Error),
    TempError(crate::Error),
    None,
}

impl From<Error> for Dkim2Result {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            Dkim2Result::TempError(err)
        } else {
            Dkim2Result::PermError(err)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DkimOutput<'x> {
    result: DkimResult,
    signature: Option<&'x dkim::Signature>,
    report: Option<String>,
    is_atps: bool,
}

#[cfg(feature = "arc")]
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
    pub ptr: Option<Arc<[Box<str>]>>,
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
pub enum DnsError {
    Resolver(String),
    RecordNotFound(ResponseCode),
    InvalidRecordType,
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

impl<'x> TryFrom<&'x [u8]> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x [u8]) -> std::prelude::v1::Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::ParseError)
    }
}

impl<'x> TryFrom<&'x Vec<u8>> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x Vec<u8>) -> std::prelude::v1::Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::ParseError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    Base64,
    NotAligned,
    Io(String),
    Crypto(CryptoError),
    Dns(DnsError),
    Dkim(crate::dkim::DkimError),
    #[cfg(feature = "arc")]
    Arc(crate::arc::ArcError),
    Dkim2(crate::dkim2::Dkim2Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError => write!(f, "Parse error"),
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

#[cfg(feature = "rsa")]
impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::Crypto(CryptoError::Library(err.to_string()))
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
