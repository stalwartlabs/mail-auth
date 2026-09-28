/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DNS cache traits and the per-call [`Parameters`] wrapper.
//!
//! The crate does not ship a cache implementation. Applications supply one by
//! implementing [`ResolverCache`] for their cache type and [`DnsCache`] for a
//! type that groups one cache per record type. The cache is then passed to a
//! verifier through [`Parameters::with_cache`]. Keys are fully qualified,
//! lowercased domain names (see [`ToFqdn`](super::ToFqdn)), or IP addresses
//! for PTR records.
//!
//! # Example
//!
//! ```rust,no_run
//! use mail_auth::{
//!     AuthenticatedMessage, DnsCache, MessageAuthenticator, Mx, Parameters, RecordSet,
//!     ResolverCache, TxtRecord,
//! };
//! use std::{
//!     borrow::Borrow,
//!     collections::HashMap,
//!     hash::Hash,
//!     net::{IpAddr, Ipv4Addr, Ipv6Addr},
//!     sync::Mutex,
//!     time::Instant,
//! };
//!
//! struct MapCache<K, V>(Mutex<HashMap<K, (V, Instant)>>);
//!
//! impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for MapCache<K, V> {
//!     fn get<Q>(&self, name: &Q) -> Option<V>
//!     where
//!         K: Borrow<Q>,
//!         Q: Hash + Eq + ?Sized,
//!     {
//!         let map = self.0.lock().unwrap();
//!         let (value, expires) = map.get(name)?;
//!         (*expires > Instant::now()).then(|| value.clone())
//!     }
//!
//!     fn remove<Q>(&self, name: &Q) -> Option<V>
//!     where
//!         K: Borrow<Q>,
//!         Q: Hash + Eq + ?Sized,
//!     {
//!         self.0.lock().unwrap().remove(name).map(|(value, _)| value)
//!     }
//!
//!     fn insert(&self, key: K, value: V, valid_until: Instant) {
//!         self.0.lock().unwrap().insert(key, (value, valid_until));
//!     }
//! }
//!
//! struct Caches {
//!     txt: MapCache<Box<str>, TxtRecord>,
//!     mx: MapCache<Box<str>, RecordSet<Mx>>,
//!     ipv4: MapCache<Box<str>, RecordSet<Ipv4Addr>>,
//!     ipv6: MapCache<Box<str>, RecordSet<Ipv6Addr>>,
//!     ptr: MapCache<IpAddr, RecordSet<Box<str>>>,
//! }
//!
//! impl DnsCache for Caches {
//!     type Txt = MapCache<Box<str>, TxtRecord>;
//!     type Mx = MapCache<Box<str>, RecordSet<Mx>>;
//!     type Ipv4 = MapCache<Box<str>, RecordSet<Ipv4Addr>>;
//!     type Ipv6 = MapCache<Box<str>, RecordSet<Ipv6Addr>>;
//!     type Ptr = MapCache<IpAddr, RecordSet<Box<str>>>;
//!
//!     fn txt(&self) -> Option<&Self::Txt> { Some(&self.txt) }
//!     fn mx(&self) -> Option<&Self::Mx> { Some(&self.mx) }
//!     fn ipv4(&self) -> Option<&Self::Ipv4> { Some(&self.ipv4) }
//!     fn ipv6(&self) -> Option<&Self::Ipv6> { Some(&self.ipv6) }
//!     fn ptr(&self) -> Option<&Self::Ptr> { Some(&self.ptr) }
//! }
//!
//! # async fn run(authenticator: &MessageAuthenticator, caches: &Caches, raw: &[u8]) {
//! let message = AuthenticatedMessage::parse(raw).unwrap();
//! let results = authenticator
//!     .verify_dkim(Parameters::new(&message).with_cache(caches))
//!     .await;
//! # }
//! ```

use super::{Mx, RecordSet, TxtRecord};
use crate::Instant;
use std::{
    borrow::Borrow,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// A cache for one DNS record type, keyed by `K` and holding values of type
/// `V`.
///
/// Methods take `&self`, so implementations that mutate must use interior
/// mutability (a lock or a concurrent map). The lookup helpers call
/// [`get`](Self::get) before querying and [`insert`](Self::insert) after a
/// successful query; they do not check expiry themselves. See the
/// [module documentation](self) for an example.
pub trait ResolverCache<K, V>: Sized {
    /// Returns a copy of the cached value for `name`, or `None` if there is
    /// none. Implementations should return `None` for expired entries.
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    /// Removes the entry for `name` and returns its value. Not called by this
    /// crate; available to applications that invalidate entries.
    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    /// Stores `value` under `key`. `valid_until` is the expiry time derived
    /// from the TTLs of the DNS answer.
    fn insert(&self, key: K, value: V, valid_until: Instant);
}

/// A set of DNS caches, one per record type, passed to verifiers through
/// [`Parameters::with_cache`].
///
/// An accessor that returns `None` disables caching for that record type.
/// See the [module documentation](self) for an example.
pub trait DnsCache {
    /// Cache for parsed TXT records (SPF, DKIM, DMARC, ATPS, MTA-STS,
    /// TLSRPT), keyed by fully qualified domain name.
    type Txt: ResolverCache<Box<str>, TxtRecord>;
    /// Cache for MX records, keyed by fully qualified domain name.
    type Mx: ResolverCache<Box<str>, RecordSet<Mx>>;
    /// Cache for A records, keyed by fully qualified domain name.
    type Ipv4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>>;
    /// Cache for AAAA records, keyed by fully qualified domain name.
    type Ipv6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>>;
    /// Cache for PTR records, keyed by IP address.
    type Ptr: ResolverCache<IpAddr, RecordSet<Box<str>>>;

    /// Returns the TXT record cache, or `None` to disable it.
    fn txt(&self) -> Option<&Self::Txt>;
    /// Returns the MX record cache, or `None` to disable it.
    fn mx(&self) -> Option<&Self::Mx>;
    /// Returns the A record cache, or `None` to disable it.
    fn ipv4(&self) -> Option<&Self::Ipv4>;
    /// Returns the AAAA record cache, or `None` to disable it.
    fn ipv6(&self) -> Option<&Self::Ipv6>;
    /// Returns the PTR record cache, or `None` to disable it.
    fn ptr(&self) -> Option<&Self::Ptr>;
}

/// A cache that stores nothing.
///
/// Implements both [`ResolverCache`] (every lookup misses) and [`DnsCache`]
/// (every accessor returns `None`). It is the default cache type of
/// [`Parameters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCache;

impl<K, V> ResolverCache<K, V> for NoCache {
    fn get<Q>(&self, _: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn remove<Q>(&self, _: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _: K, _: V, _: Instant) {}
}

impl DnsCache for NoCache {
    type Txt = NoCache;
    type Mx = NoCache;
    type Ipv4 = NoCache;
    type Ipv6 = NoCache;
    type Ptr = NoCache;

    fn txt(&self) -> Option<&Self::Txt> {
        None
    }

    fn mx(&self) -> Option<&Self::Mx> {
        None
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        None
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        None
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        None
    }
}

/// The input of a verifier, optionally paired with a DNS cache.
///
/// Every verifier on [`MessageAuthenticator`](crate::MessageAuthenticator)
/// takes `impl Into<Parameters<..>>`, so the bare input (a message, an IP
/// address, SPF or DMARC parameters) can be passed directly when no cache is
/// needed. Wrap it with [`Parameters::new`] and
/// [`with_cache`](Self::with_cache) to use a cache.
pub struct Parameters<'x, P, C: DnsCache = NoCache> {
    /// The verifier input.
    pub input: P,
    /// The DNS cache, or `None` to query without caching.
    pub cache: Option<&'x C>,
}

impl<P> Parameters<'_, P, NoCache> {
    /// Wraps `input` without a cache.
    pub fn new(input: P) -> Self {
        Parameters { input, cache: None }
    }
}

impl<'x, P, C: DnsCache> Parameters<'x, P, C> {
    /// Sets the DNS cache, replacing any cache set before.
    pub fn with_cache<NewC: DnsCache>(self, cache: &'x NewC) -> Parameters<'x, P, NewC> {
        Parameters {
            input: self.input,
            cache: Some(cache),
        }
    }

    /// Returns parameters with a different input and the same cache. Useful
    /// for running several verifiers against one cache.
    pub fn clone_with<NewP>(&self, input: NewP) -> Parameters<'x, NewP, C> {
        Parameters {
            input,
            cache: self.cache,
        }
    }

    #[inline(always)]
    pub(crate) fn txt_cache(&self) -> Option<&'x C::Txt> {
        self.cache.and_then(DnsCache::txt)
    }

    #[inline(always)]
    pub(crate) fn mx_cache(&self) -> Option<&'x C::Mx> {
        self.cache.and_then(DnsCache::mx)
    }

    #[inline(always)]
    pub(crate) fn ipv4_cache(&self) -> Option<&'x C::Ipv4> {
        self.cache.and_then(DnsCache::ipv4)
    }

    #[inline(always)]
    pub(crate) fn ipv6_cache(&self) -> Option<&'x C::Ipv6> {
        self.cache.and_then(DnsCache::ipv6)
    }

    #[inline(always)]
    pub(crate) fn ptr_cache(&self) -> Option<&'x C::Ptr> {
        self.cache.and_then(DnsCache::ptr)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::dns::{
        DnsCache, DnssecStatus, Mx, Parameters, RecordSet, ResolverCache, ToFqdn, TxtRecord,
    };
    use std::{
        borrow::Borrow,
        hash::Hash,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    pub(crate) struct DummyCache<K, V>(std::sync::Mutex<std::collections::HashMap<K, V>>);

    impl<K: Hash + Eq, V: Clone> DummyCache<K, V> {
        pub fn new() -> Self {
            DummyCache(std::sync::Mutex::new(std::collections::HashMap::new()))
        }
    }

    impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for DummyCache<K, V> {
        fn get<Q>(&self, key: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().get(key).cloned()
        }

        fn remove<Q>(&self, key: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().remove(key)
        }

        fn insert(&self, key: K, value: V, _: std::time::Instant) {
            self.0.lock().unwrap().insert(key, value);
        }
    }

    pub(crate) struct DummyCaches {
        pub txt: DummyCache<Box<str>, TxtRecord>,
        pub mx: DummyCache<Box<str>, RecordSet<Mx>>,
        pub ptr: DummyCache<IpAddr, RecordSet<Box<str>>>,
        pub ipv4: DummyCache<Box<str>, RecordSet<Ipv4Addr>>,
        pub ipv6: DummyCache<Box<str>, RecordSet<Ipv6Addr>>,
    }

    impl DummyCaches {
        pub fn new() -> Self {
            Self {
                txt: DummyCache::new(),
                mx: DummyCache::new(),
                ptr: DummyCache::new(),
                ipv4: DummyCache::new(),
                ipv6: DummyCache::new(),
            }
        }

        pub fn with_txt(
            self,
            name: impl ToFqdn,
            value: impl Into<TxtRecord>,
            valid_until: std::time::Instant,
        ) -> Self {
            self.txt.insert(
                name.to_fqdn().into_owned().into_boxed_str(),
                value.into(),
                valid_until,
            );
            self
        }

        pub fn txt_add(
            &self,
            name: impl ToFqdn,
            value: impl Into<TxtRecord>,
            valid_until: std::time::Instant,
        ) {
            self.txt.insert(
                name.to_fqdn().into_owned().into_boxed_str(),
                value.into(),
                valid_until,
            );
        }

        pub fn ipv4_add(
            &self,
            name: impl ToFqdn,
            value: Vec<Ipv4Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv4.insert(
                name.to_fqdn().into_owned().into_boxed_str(),
                RecordSet {
                    records: Arc::from(value.into_boxed_slice()),
                    dnssec_status: DnssecStatus::Indeterminate,
                },
                valid_until,
            );
        }

        pub fn ipv6_add(
            &self,
            name: impl ToFqdn,
            value: Vec<Ipv6Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv6.insert(
                name.to_fqdn().into_owned().into_boxed_str(),
                RecordSet {
                    records: Arc::from(value.into_boxed_slice()),
                    dnssec_status: DnssecStatus::Indeterminate,
                },
                valid_until,
            );
        }

        pub fn ptr_add(&self, name: IpAddr, value: Vec<Box<str>>, valid_until: std::time::Instant) {
            self.ptr.insert(
                name,
                RecordSet {
                    records: Arc::from(value.into_boxed_slice()),
                    dnssec_status: DnssecStatus::Indeterminate,
                },
                valid_until,
            );
        }

        pub fn mx_add(&self, name: impl ToFqdn, value: Vec<Mx>, valid_until: std::time::Instant) {
            self.mx.insert(
                name.to_fqdn().into_owned().into_boxed_str(),
                RecordSet {
                    records: Arc::from(value.into_boxed_slice()),
                    dnssec_status: DnssecStatus::Indeterminate,
                },
                valid_until,
            );
        }

        pub fn parameters<T>(&self, param: T) -> Parameters<'_, T, DummyCaches> {
            Parameters::new(param).with_cache(self)
        }
    }

    impl DnsCache for DummyCaches {
        type Txt = DummyCache<Box<str>, TxtRecord>;
        type Mx = DummyCache<Box<str>, RecordSet<Mx>>;
        type Ipv4 = DummyCache<Box<str>, RecordSet<Ipv4Addr>>;
        type Ipv6 = DummyCache<Box<str>, RecordSet<Ipv6Addr>>;
        type Ptr = DummyCache<IpAddr, RecordSet<Box<str>>>;

        fn txt(&self) -> Option<&Self::Txt> {
            Some(&self.txt)
        }

        fn mx(&self) -> Option<&Self::Mx> {
            Some(&self.mx)
        }

        fn ipv4(&self) -> Option<&Self::Ipv4> {
            Some(&self.ipv4)
        }

        fn ipv6(&self) -> Option<&Self::Ipv6> {
            Some(&self.ipv6)
        }

        fn ptr(&self) -> Option<&Self::Ptr> {
            Some(&self.ptr)
        }
    }
}
