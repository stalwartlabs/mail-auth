/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DNS resolution and caching.
//!
//! Every verifier resolves DNS records through the backend wrapped by
//! [`MessageAuthenticator`](crate::MessageAuthenticator). Exactly one backend
//! is compiled in:
//!
//! - `dns-hickory` (default): UDP, TCP or DNS-over-TLS queries through
//!   [hickory-resolver](https://crates.io/crates/hickory-resolver). Not
//!   available on WebAssembly.
//! - `dns-doh`: DNS-over-HTTPS queries (RFC 8484) through `DohResolver`,
//!   using either the JSON API or the DNS wire format. Works on WebAssembly.
//!
//! Lookups can be cached. A cache is supplied per call by wrapping the
//! verifier input in [`Parameters`] with [`Parameters::with_cache`]. The cache
//! type implements [`DnsCache`], which hands out one [`ResolverCache`] per
//! record type (TXT, MX, A, AAAA and PTR). TXT records are cached already
//! parsed, as [`TxtRecord`] values. [`NoCache`] disables caching and is the
//! default.
//!
//! The lookup helpers on `MessageAuthenticator` (`txt_lookup`, `mx_lookup`,
//! `ipv4_lookup`, `ipv6_lookup`, `ip_lookup`, `ptr_lookup`, `exists`) are
//! public so that applications can reuse the resolver and caches for their
//! own queries.

use crate::Instant;
#[cfg(not(feature = "dns-doh"))]
use hickory_resolver::proto::op::ResponseCode;
use std::{borrow::Cow, net::IpAddr, sync::Arc};

pub mod cache;
#[cfg(feature = "dns-doh")]
mod doh;
#[cfg(not(feature = "dns-doh"))]
mod hickory;
mod lookup;
mod txt;

pub use cache::{DnsCache, NoCache, Parameters, ResolverCache};
#[cfg(feature = "dns-doh")]
pub use doh::DohResolver;
#[cfg(any(test, feature = "test"))]
pub use lookup::mock_resolve;
pub use txt::{TxtRecord, TxtRecordParser, UnwrapTxtRecord};

#[cfg(not(feature = "dns-doh"))]
pub(crate) const DNS_RCODE_NXDOMAIN: ResponseCode = ResponseCode::NXDomain;
#[cfg(feature = "dns-doh")]
pub(crate) const DNS_RCODE_NXDOMAIN: u16 = 3;

/// Address families queried by
/// [`MessageAuthenticator::ip_lookup`](crate::MessageAuthenticator::ip_lookup),
/// and in which order.
#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq)]
pub enum IpLookupStrategy {
    /// Only query for A (IPv4) records.
    Ipv4Only,
    /// Only query for AAAA (IPv6) records.
    Ipv6Only,
    /// Query for AAAA (IPv6) records; if that fails, query for A (IPv4)
    /// records.
    Ipv6thenIpv4,
    /// Query for A (IPv4) records; if that fails, query for AAAA (IPv6)
    /// records. This is the default.
    #[default]
    Ipv4thenIpv6,
}

/// The records returned by a DNS lookup, as stored in a [`ResolverCache`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSet<T> {
    /// The records in the answer, shared so that cache hits do not copy them.
    pub records: Arc<[T]>,
    /// DNSSEC validation state of the answer.
    pub dnssec_status: DnssecStatus,
}

/// A group of MX records (RFC 5321 Section 5.1) that share a preference
/// value.
///
/// [`MessageAuthenticator::mx_lookup`](crate::MessageAuthenticator::mx_lookup)
/// returns one `Mx` per distinct preference, sorted from the lowest (most
/// preferred) value to the highest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mx {
    /// Lowercased exchange host names with this preference, in answer order.
    pub exchanges: Box<[Box<str>]>,
    /// MX preference value; lower values are tried first.
    pub preference: u16,
}

/// DNSSEC validation state of a DNS answer (RFC 4035 Section 4.3).
///
/// The built-in backends do not validate DNSSEC and always report
/// [`DnssecStatus::Indeterminate`]. The other variants are available to
/// [`DnsCache`] implementations that fill records from a validating resolver.
#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq)]
#[repr(u16)]
pub enum DnssecStatus {
    /// The answer has a valid chain of trust to a trust anchor.
    Secure,
    /// The answer is provably not signed.
    Insecure,
    /// The answer is signed but failed validation.
    Bogus,
    /// The validation state is unknown. This is the default.
    #[default]
    Indeterminate,
}

/// A raw DNS answer together with the time at which it expires, as returned
/// by [`MessageAuthenticator::ipv4_lookup_raw`](crate::MessageAuthenticator::ipv4_lookup_raw)
/// and [`MessageAuthenticator::ipv6_lookup_raw`](crate::MessageAuthenticator::ipv6_lookup_raw).
pub struct DnsEntry<T> {
    /// The answer data.
    pub entry: T,
    /// When the answer expires, derived from the record TTLs.
    pub expires: Instant,
}

/// Returns `true` if `domain` looks like a valid host name for a DNS query.
///
/// The check requires every label to be at most 63 characters long (RFC 1035
/// Section 2.3.4), and the name to contain at least one dot and at least one
/// alphanumeric character. It does not check the total length. SPF uses it to
/// reject malformed domains before querying (RFC 7208 Section 4.3).
#[inline]
pub fn has_valid_labels(domain: &str) -> bool {
    let mut has_dots = false;
    let mut has_chars = false;
    let mut label_len = 0;
    for ch in domain.chars() {
        label_len += 1;

        if ch.is_alphanumeric() {
            has_chars = true;
        } else if ch == '.' {
            has_dots = true;
            label_len = 0;
        }

        if label_len > 63 {
            return false;
        }
    }
    has_chars && has_dots
}

pub(crate) fn to_a_label(domain: &str) -> Cow<'_, str> {
    if !domain.is_ascii() {
        idna::domain_to_ascii(domain)
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(domain))
    } else if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}

/// Conversion of a domain name to the fully qualified form used as a DNS
/// query and cache key.
///
/// Implemented for every `T: AsRef<str>`.
pub trait ToFqdn {
    /// Returns the name lowercased and with a trailing dot. Borrows when the
    /// name is already in that form.
    fn to_fqdn(&self) -> Cow<'_, str>;
}

impl<T: AsRef<str>> ToFqdn for T {
    fn to_fqdn(&self) -> Cow<'_, str> {
        let value = self.as_ref();
        let bytes = value.as_bytes();
        if matches!(bytes.last(), Some(b'.'))
            && !bytes
                .iter()
                .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii())
        {
            Cow::Borrowed(value)
        } else if value.is_ascii() {
            let mut fqdn = String::with_capacity(value.len() + 1);
            fqdn.push_str(value);
            fqdn.make_ascii_lowercase();
            if !matches!(bytes.last(), Some(b'.')) {
                fqdn.push('.');
            }
            Cow::Owned(fqdn)
        } else {
            let mut fqdn = value.to_lowercase();
            if !value.ends_with('.') {
                fqdn.push('.');
            }
            Cow::Owned(fqdn)
        }
    }
}

/// Conversion of an IP address to the label sequence of its reverse DNS name.
pub trait ToReverseName {
    /// Returns the address labels in reverse order, without the
    /// `in-addr.arpa` (RFC 1035 Section 3.5) or `ip6.arpa` (RFC 3596
    /// Section 2.5) suffix. IPv4 addresses produce decimal octets
    /// (`4.3.2.1` for `1.2.3.4`); IPv6 addresses produce one hexadecimal
    /// nibble per label.
    fn to_reverse_name(&self) -> String;
}

impl ToReverseName for IpAddr {
    fn to_reverse_name(&self) -> String {
        match self {
            IpAddr::V4(ip) => {
                let mut segments = String::with_capacity(15);
                let mut buf = [0u8; 3];
                for octet in ip.octets().iter().rev() {
                    if !segments.is_empty() {
                        segments.push('.');
                    }
                    for &digit in decimal_u8(*octet, &mut buf) {
                        segments.push(char::from(digit));
                    }
                }
                segments
            }
            IpAddr::V6(ip) => {
                let mut segments = String::with_capacity(63);
                for segment in ip.segments().iter().rev() {
                    for shift in [0u32, 4, 8, 12] {
                        if !segments.is_empty() {
                            segments.push('.');
                        }
                        segments.push(char::from(hex_nibble((segment >> shift) as u8)));
                    }
                }
                segments
            }
        }
    }
}

#[inline(always)]
pub(crate) fn hex_nibble(value: u8) -> u8 {
    b"0123456789abcdef"[(value & 0x0f) as usize]
}

#[inline(always)]
pub(crate) fn decimal_u8(value: u8, buf: &mut [u8; 3]) -> &[u8] {
    buf[0] = b'0' + value / 100;
    buf[1] = b'0' + (value / 10) % 10;
    buf[2] = b'0' + value % 10;
    let start = if value >= 100 {
        0
    } else if value >= 10 {
        1
    } else {
        2
    };
    &buf[start..]
}

#[cfg(test)]
mod test {
    use super::ToReverseName;
    use std::net::IpAddr;

    #[test]
    fn reverse_lookup_addr() {
        for (addr, expected) in [
            ("1.2.3.4", "4.3.2.1"),
            (
                "2001:db8::cb01",
                "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
            ),
            (
                "2a01:4f9:c011:b43c::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.3.4.b.1.1.0.c.9.f.4.0.1.0.a.2",
            ),
        ] {
            assert_eq!(addr.parse::<IpAddr>().unwrap().to_reverse_name(), expected);
        }
    }
}
