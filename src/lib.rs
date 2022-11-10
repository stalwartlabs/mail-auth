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
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use common::lru::LruCache;
use dkim::DomainKey;
use dmarc::DMARC;
use spf::{Macro, SPF};
use trust_dns_resolver::TokioAsyncResolver;

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
    pub(crate) cache_ptr: LruCache<IpAddr, Arc<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Txt {
    SPF(Arc<SPF>),
    SPFMacro(Arc<Macro>),
    DomainKey(Arc<DomainKey>),
    DMARC(Arc<DMARC>),
    Error(Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MX {
    exchange: String,
    preference: u16,
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
    RevokedPublicKey,
    IncompatibleAlgorithms,
    FailedVerification,
    SignatureExpired,
    FailedAUIDMatch,
    DNSFailure(String),

    ARCInvalidInstance,
    ARCInvalidCV,
    ARCHasHeaderTag,
    ARCBrokenChain,

    InvalidVersion,
    InvalidRecord,

    InvalidIp4,
    InvalidIp6,
    InvalidMacro,
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
            Error::InvalidVersion => write!(f, "Invalid version."),
            Error::InvalidRecord => write!(f, "Invalid record."),
            Error::InvalidIp4 => write!(f, "Invalid IPv4."),
            Error::InvalidIp6 => write!(f, "Invalid IPv6."),
            Error::InvalidMacro => write!(f, "Invalid SPF macro."),
            Error::DNSFailure(err) => write!(f, "DNS failure: {}", err),
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
        let resolver =
            AsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
                .unwrap();
        let c = resolver
            .reverse_lookup("135.181.195.209".parse().unwrap())
            .await
            .unwrap();

        println!(
            "{:#?}",
            c /*c.as_lookup().records()[0]
              .data()
              .unwrap()
              .as_txt()
              .unwrap()
              .to_string()*/
        );
    }
}
