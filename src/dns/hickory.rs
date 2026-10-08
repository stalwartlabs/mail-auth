/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Hickory DNS backend, enabled by the default `dns-hickory` feature.
//!
//! Queries go through a [`hickory_resolver::TokioResolver`] over UDP, TCP or
//! DNS-over-TLS (RFC 7858).

use super::{DnsEntry, QueryError, QueryResult};
use crate::{Error, Instant, MessageAuthenticator, authenticator::DEFAULT_MAX_NEGATIVE_TTL};
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig, ResolverOpts},
    net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    proto::{
        ProtoError,
        rr::{Name, RData},
    },
    system_conf::read_system_conf,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

impl MessageAuthenticator {
    /// Creates an authenticator that queries Cloudflare's public resolvers
    /// over DNS-over-TLS (RFC 7858). Requires the `ring` or `aws-lc-rs`
    /// feature.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_cloudflare_tls() -> Result<Self, NetError> {
        Self::new(ResolverConfig::tls(&CLOUDFLARE), ResolverOpts::default())
    }

    /// Creates an authenticator that queries Cloudflare's public resolvers
    /// over UDP and TCP.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    pub fn new_cloudflare() -> Result<Self, NetError> {
        Self::new(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            ResolverOpts::default(),
        )
    }

    /// Creates an authenticator that queries Google's public resolvers over
    /// UDP and TCP.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    pub fn new_google() -> Result<Self, NetError> {
        Self::new(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            ResolverOpts::default(),
        )
    }

    /// Creates an authenticator that queries Quad9's public resolvers over
    /// UDP and TCP.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    pub fn new_quad9() -> Result<Self, NetError> {
        Self::new(ResolverConfig::udp_and_tcp(&QUAD9), ResolverOpts::default())
    }

    /// Creates an authenticator that queries Quad9's public resolvers over
    /// DNS-over-TLS (RFC 7858). Requires the `ring` or `aws-lc-rs` feature.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_quad9_tls() -> Result<Self, NetError> {
        Self::new(ResolverConfig::tls(&QUAD9), ResolverOpts::default())
    }

    /// Creates an authenticator that uses the system resolver configuration
    /// (`/etc/resolv.conf` on Unix, the registry on Windows).
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the system configuration cannot be read or
    /// the resolver cannot be built.
    pub fn new_system_conf() -> Result<Self, NetError> {
        let (config, options) = read_system_conf()?;
        Self::new(config, options)
    }

    /// Creates an authenticator from an explicit hickory resolver
    /// configuration and options.
    ///
    /// # Errors
    ///
    /// Returns a [`NetError`] if the resolver cannot be built.
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> Result<Self, NetError> {
        Ok(MessageAuthenticator {
            resolver: TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()?,
            max_negative_ttl: DEFAULT_MAX_NEGATIVE_TTL,
        })
    }

    pub(crate) async fn query_txt(&self, key: &str) -> QueryResult<Vec<Vec<u8>>> {
        let lookup = self
            .resolver
            .txt_lookup(Name::from_str_relaxed::<&str>(key)?)
            .await?;
        let expires = lookup.valid_until();
        let mut entry: Vec<Vec<u8>> = Vec::new();
        for record in lookup.answers() {
            let RData::TXT(txt) = &record.data else {
                continue;
            };
            match txt.txt_data.len() {
                0 => {}
                1 => entry.push(txt.txt_data[0].to_vec()),
                _ => {
                    let mut data = Vec::with_capacity(255 * txt.txt_data.len());
                    for chunk in txt.txt_data.iter() {
                        data.extend_from_slice(chunk);
                    }
                    entry.push(data);
                }
            }
        }
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn query_mx(&self, key: &str) -> QueryResult<Vec<(u16, Box<str>)>> {
        let lookup = self
            .resolver
            .mx_lookup(Name::from_str_relaxed::<&str>(key)?)
            .await?;
        let expires = lookup.valid_until();
        let entry = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                let RData::MX(mx) = &r.data else {
                    return None;
                };
                Some((
                    mx.preference,
                    mx.exchange.to_lowercase().to_ascii().into_boxed_str(),
                ))
            })
            .collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn query_ipv4(&self, key: &str) -> QueryResult<Arc<[Ipv4Addr]>> {
        let lookup = self
            .resolver
            .ipv4_lookup(Name::from_str_relaxed::<&str>(key)?)
            .await?;
        let expires = lookup.valid_until();
        let entry: Arc<[Ipv4Addr]> = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                if let RData::A(a) = &r.data {
                    Some(a.0)
                } else {
                    None
                }
            })
            .collect::<Vec<Ipv4Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn query_ipv6(&self, key: &str) -> QueryResult<Arc<[Ipv6Addr]>> {
        let lookup = self
            .resolver
            .ipv6_lookup(Name::from_str_relaxed::<&str>(key)?)
            .await?;
        let expires = lookup.valid_until();
        let entry: Arc<[Ipv6Addr]> = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                if let RData::AAAA(aaaa) = &r.data {
                    Some(aaaa.0)
                } else {
                    None
                }
            })
            .collect::<Vec<Ipv6Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn query_ptr(&self, addr: IpAddr) -> QueryResult<Arc<[Box<str>]>> {
        let lookup = self.resolver.reverse_lookup(addr).await?;
        let expires: Instant = lookup.valid_until();
        let entry = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                let RData::PTR(ptr) = &r.data else {
                    return None;
                };
                if !ptr.is_empty() {
                    Some(ptr.to_lowercase().to_ascii().into_boxed_str())
                } else {
                    None
                }
            })
            .collect::<Arc<[Box<str>]>>();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn query_exists(&self, key: &str) -> crate::Result<bool> {
        match self
            .resolver
            .lookup_ip(Name::from_str_relaxed::<&str>(key)?)
            .await
        {
            Ok(result) => Ok(result.as_lookup().answers().iter().any(|r| {
                matches!(
                    &r.data.record_type(),
                    hickory_resolver::proto::rr::RecordType::A
                        | hickory_resolver::proto::rr::RecordType::AAAA
                )
            })),
            Err(err) if err.is_no_records_found() => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

impl From<ProtoError> for Error {
    fn from(_: ProtoError) -> Self {
        Error::Parse
    }
}

impl From<ProtoError> for QueryError {
    fn from(_: ProtoError) -> Self {
        QueryError::Other(Error::Parse)
    }
}

impl From<NetError> for QueryError {
    fn from(err: NetError) -> Self {
        match &err {
            NetError::Dns(DnsError::NoRecordsFound(no_records)) => QueryError::NotFound {
                code: no_records.response_code,
                negative_ttl: no_records.negative_ttl,
            },
            _ => QueryError::Other(Error::Dns(crate::DnsError::Resolver(err.to_string()))),
        }
    }
}

impl From<NetError> for Error {
    fn from(err: NetError) -> Self {
        QueryError::from(err).into()
    }
}

#[cfg(test)]
mod test {
    use super::Name;
    use crate::Error;

    #[test]
    fn invalid_name_is_permanent_error() {
        let err = Name::from_str_relaxed(format!("{}.example.org", "a".repeat(64))).unwrap_err();
        assert_eq!(Error::from(err), Error::Parse);
    }
}
