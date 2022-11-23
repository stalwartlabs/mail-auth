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
    borrow::Cow,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use arc::Set;
use common::{headers::Header, lru::LruCache};
use dkim::{Atps, DomainKey};
use dmarc::DMARC;
use spf::{Macro, SPF};
use trust_dns_resolver::{proto::op::ResponseCode, TokioAsyncResolver};

pub mod arc;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

#[derive(Debug)]
pub struct Resolver {
    pub(crate) resolver: TokioAsyncResolver,
    pub(crate) cache_txt: LruCache<String, Txt>,
    pub(crate) cache_mx: LruCache<String, Arc<Vec<MX>>>,
    pub(crate) cache_ipv4: LruCache<String, Arc<Vec<Ipv4Addr>>>,
    pub(crate) cache_ipv6: LruCache<String, Arc<Vec<Ipv6Addr>>>,
    pub(crate) cache_ptr: LruCache<IpAddr, Arc<Vec<String>>>,
    pub(crate) host_domain: Vec<u8>,
    pub(crate) verify_policy: Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub(crate) from: Vec<Cow<'x, str>>,
    pub(crate) dkim_pass: Vec<Header<'x, dkim::Signature<'x>>>,
    pub(crate) dkim_fail: Vec<Header<'x, crate::Error>>,
    pub(crate) arc_pass: Vec<Set<'x>>,
    pub(crate) arc_fail: Vec<Header<'x, crate::Error>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DKIMResult {
    None,
    PermFail(crate::Error),
    TempFail(crate::Error),
    Pass,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SPFResult {
    Pass,
    Fail(String),
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
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

    ARCInvalidInstance,
    ARCInvalidCV,
    ARCHasHeaderTag,
    ARCBrokenChain,

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
            Error::ARCInvalidInstance => write!(f, "Invalid 'i=' value found in ARC header."),
            Error::ARCInvalidCV => write!(f, "Invalid 'cv=' value found in ARC header."),
            Error::ARCHasHeaderTag => write!(f, "Invalid 'h=' tag present in ARC-Seal."),
            Error::ARCBrokenChain => write!(f, "Broken or missing ARC chain."),
            Error::InvalidRecordType => write!(f, "Invalid record."),
            Error::DNSError => write!(f, "DNS resolution error."),
            Error::DNSRecordNotFound(code) => write!(f, "DNS record not found: {}.", code),
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

#[cfg(test)]
mod tests {
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        AsyncResolver,
    };

    #[tokio::test]
    async fn it_works() {
        /*let resolver =
            AsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
                .unwrap();
        let c = resolver.ipv4_lookup("locura.bivo.org.").await.unwrap();

        println!(
            "{:#?}",
            c
        );*/
    }
}
