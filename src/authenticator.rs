/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#[cfg(feature = "dns-doh")]
use crate::dns::DohResolver;
#[cfg(not(feature = "dns-doh"))]
use hickory_resolver::TokioResolver;
use std::time::Duration;

pub(crate) const DEFAULT_MAX_NEGATIVE_TTL: Duration = Duration::from_secs(3600);

/// Entry point for every verifier and DNS lookup in this crate.
///
/// A `MessageAuthenticator` wraps a DNS resolver and exposes the verifiers
/// (`verify_dkim`, `verify_dkim2`, `verify_arc`, `verify_spf`, `verify_dmarc`,
/// [`verify_iprev`](Self::verify_iprev)) together with the DNS lookup helpers
/// used by them. Cloning is cheap: clones share the underlying resolver.
///
/// With the default `dns-hickory` feature the resolver is a
/// [`hickory_resolver::TokioResolver`], built with [`new`](Self::new),
/// [`new_system_conf`](Self::new_system_conf) or one of the provider presets
/// such as [`new_cloudflare_tls`](Self::new_cloudflare_tls).
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
///
/// # async fn run(raw_message: &[u8]) {
/// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
/// let message = AuthenticatedMessage::parse(raw_message).unwrap();
/// let results = authenticator.verify_dkim(&message).await;
/// assert!(results.iter().all(|r| r.result() == &DkimResult::Pass));
/// # }
/// ```
#[derive(Clone)]
#[cfg(not(feature = "dns-doh"))]
pub struct MessageAuthenticator {
    pub(crate) resolver: TokioResolver,
    pub(crate) max_negative_ttl: Duration,
}

/// Entry point for every verifier and DNS lookup in this crate.
///
/// A `MessageAuthenticator` wraps a DNS resolver and exposes the verifiers
/// (`verify_dkim`, `verify_dkim2`, `verify_arc`, `verify_spf`, `verify_dmarc`,
/// [`verify_iprev`](Self::verify_iprev)) together with the DNS lookup helpers
/// used by them. Cloning is cheap: clones share the underlying HTTP client.
///
/// With the `dns-doh` feature the resolver is a [`DohResolver`] that sends
/// DNS-over-HTTPS queries (RFC 8484). Build one with
/// [`new_doh`](Self::new_doh), [`new_doh_wire`](Self::new_doh_wire) or a
/// provider preset such as [`new_doh_cloudflare`](Self::new_doh_cloudflare).
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
///
/// # async fn run(raw_message: &[u8]) {
/// let authenticator = MessageAuthenticator::new_doh_cloudflare();
/// let message = AuthenticatedMessage::parse(raw_message).unwrap();
/// let results = authenticator.verify_dkim(&message).await;
/// assert!(results.iter().all(|r| r.result() == &DkimResult::Pass));
/// # }
/// ```
#[derive(Clone)]
#[cfg(feature = "dns-doh")]
pub struct MessageAuthenticator {
    pub(crate) resolver: DohResolver,
    pub(crate) max_negative_ttl: Duration,
}

impl MessageAuthenticator {
    /// Returns the underlying hickory resolver, for issuing DNS queries that
    /// this crate does not wrap.
    #[cfg(not(feature = "dns-doh"))]
    pub fn resolver(&self) -> &TokioResolver {
        &self.resolver
    }

    /// Returns the underlying DNS-over-HTTPS resolver.
    #[cfg(feature = "dns-doh")]
    pub fn resolver(&self) -> &DohResolver {
        &self.resolver
    }

    /// Sets the longest time a negative answer (`NXDOMAIN` or NODATA) is
    /// kept in the DNS caches.
    pub fn with_max_negative_ttl(mut self, ttl: Duration) -> Self {
        self.max_negative_ttl = ttl;
        self
    }
}
