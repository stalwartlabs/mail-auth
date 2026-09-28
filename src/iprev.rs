/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Reverse IP address verification (`iprev`, RFC 8601 Section 3).
//!
//! The `iprev` check confirms that the SMTP client's IP address has a PTR
//! record whose name resolves back to the same address. Run it with
//! [`MessageAuthenticator::verify_iprev`] and report the outcome with
//! [`AuthenticationResults::with_iprev_result`](crate::AuthenticationResults::with_iprev_result).

use crate::dns::DnsCache;
use crate::{
    DnsError, Error, MessageAuthenticator,
    dns::{NoCache, Parameters},
};
use std::{fmt::Display, net::IpAddr, sync::Arc};

/// The outcome of an `iprev` check (RFC 8601 Section 3), produced by
/// [`MessageAuthenticator::verify_iprev`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IprevOutput {
    /// The `iprev` result.
    pub result: IprevResult,
    /// The host names returned by the PTR lookup, lowercased. `None` when the
    /// PTR lookup itself failed.
    pub ptr: Option<Arc<[Box<str>]>>,
}

/// An `iprev` result code, as defined in RFC 8601 Section 3.
///
/// The error carried by the failure variants explains the result and is
/// written as a comment in the `Authentication-Results` header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IprevResult {
    /// A PTR name resolved back to the client IP address.
    Pass,
    /// The PTR names were found, but none of them resolved back to the client
    /// IP address. Carries [`Error::NotAligned`].
    Fail(crate::Error),
    /// A DNS lookup failed with a transient error ([`DnsError::Resolver`]).
    /// The check may succeed if retried later.
    TempError(crate::Error),
    /// A DNS lookup failed permanently: no PTR record exists, a name was
    /// malformed or a forward lookup returned no records.
    PermError(crate::Error),
    /// No `iprev` check was performed. [`MessageAuthenticator::verify_iprev`]
    /// never returns this variant.
    None,
}

impl MessageAuthenticator {
    /// Verifies the reverse DNS of an SMTP client IP address (RFC 8601
    /// Section 3).
    ///
    /// `params` is the client IP address, either alone or wrapped in
    /// [`Parameters`] together with a DNS cache.
    ///
    /// The check performs these DNS lookups:
    ///
    /// 1. A PTR query for the IP address.
    /// 2. For each of the first two names returned, an A query (IPv4 client)
    ///    or AAAA query (IPv6 client).
    ///
    /// The result is:
    ///
    /// - [`IprevResult::Pass`] as soon as a forward lookup returns the client
    ///   address.
    /// - [`IprevResult::Fail`] with [`Error::NotAligned`] when every forward
    ///   lookup succeeded but none returned the client address, or when the PTR
    ///   answer was empty.
    /// - [`IprevResult::TempError`] or [`IprevResult::PermError`] when the PTR
    ///   lookup failed, or when no forward lookup matched and at least one of
    ///   them failed. Resolver errors ([`DnsError::Resolver`]) are temporary;
    ///   all other errors are permanent. The error of the last failed lookup is
    ///   reported.
    ///
    /// [`IprevOutput::ptr`] holds the PTR names whenever the PTR lookup
    /// succeeded.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{AuthenticationResults, IprevResult, MessageAuthenticator};
    /// use std::net::IpAddr;
    ///
    /// # async fn run() {
    /// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
    /// let remote_ip: IpAddr = "192.0.2.10".parse().unwrap();
    ///
    /// let iprev = authenticator.verify_iprev(remote_ip).await;
    /// if iprev.result() == &IprevResult::Pass {
    ///     println!("PTR names: {:?}", iprev.ptr);
    /// }
    ///
    /// let header = AuthenticationResults::new("mx.example.org")
    ///     .with_iprev_result(&iprev, remote_ip)
    ///     .to_string();
    /// # }
    /// ```
    pub async fn verify_iprev<'x, C>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, C>>,
    ) -> IprevOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        match self.ptr_lookup(params.input, params.ptr_cache()).await {
            Ok(ptr) => {
                let mut last_err = None;
                for host in ptr.records.iter().take(2) {
                    match &params.input {
                        IpAddr::V4(ip) => match self.ipv4_lookup(host, params.ipv4_cache()).await {
                            Ok(ips) => {
                                if ips.records.iter().any(|cip| cip == ip) {
                                    return IprevOutput {
                                        result: IprevResult::Pass,
                                        ptr: Some(ptr.records.clone()),
                                    };
                                }
                            }
                            Err(err) => {
                                last_err = err.into();
                            }
                        },
                        IpAddr::V6(ip) => match self.ipv6_lookup(host, params.ipv6_cache()).await {
                            Ok(ips) => {
                                if ips.records.iter().any(|cip| cip == ip) {
                                    return IprevOutput {
                                        result: IprevResult::Pass,
                                        ptr: Some(ptr.records.clone()),
                                    };
                                }
                            }
                            Err(err) => {
                                last_err = err.into();
                            }
                        },
                    }
                }

                IprevOutput {
                    result: if let Some(err) = last_err {
                        err.into()
                    } else {
                        IprevResult::Fail(Error::NotAligned)
                    },
                    ptr: Some(ptr.records.clone()),
                }
            }
            Err(err) => IprevOutput {
                result: err.into(),
                ptr: None,
            },
        }
    }
}

impl From<IpAddr> for Parameters<'_, IpAddr, NoCache> {
    fn from(params: IpAddr) -> Self {
        Parameters::new(params)
    }
}

impl IprevOutput {
    /// Returns the `iprev` result.
    pub fn result(&self) -> &IprevResult {
        &self.result
    }
}

impl From<Error> for IprevResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            IprevResult::TempError(err)
        } else {
            IprevResult::PermError(err)
        }
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
