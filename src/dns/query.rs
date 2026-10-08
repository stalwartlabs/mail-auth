/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Backend-independent query layer: negative answers (RFC 2308) and, in test
//! builds, the mock resolver that stands in for the backend.

use super::{DnsEntry, Negative, ResolverCache, ResponseCode};
use crate::{Error, Instant, MessageAuthenticator};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
pub(crate) enum QueryError {
    NotFound {
        code: ResponseCode,
        negative_ttl: Option<u32>,
    },
    Other(Error),
}

pub(crate) type QueryResult<T> = Result<DnsEntry<T>, QueryError>;

impl From<Error> for QueryError {
    fn from(err: Error) -> Self {
        QueryError::Other(err)
    }
}

impl From<QueryError> for Error {
    fn from(err: QueryError) -> Self {
        match err {
            QueryError::NotFound { code, .. } => Negative { code }.into(),
            QueryError::Other(err) => err,
        }
    }
}

#[cfg(not(any(test, feature = "test")))]
impl MessageAuthenticator {
    pub(crate) fn resolve_txt(&self, key: &str) -> impl Future<Output = QueryResult<Vec<Vec<u8>>>> {
        self.query_txt(key)
    }

    pub(crate) fn resolve_mx(
        &self,
        key: &str,
    ) -> impl Future<Output = QueryResult<Vec<(u16, Box<str>)>>> {
        self.query_mx(key)
    }

    pub(crate) fn resolve_ipv4(
        &self,
        key: &str,
    ) -> impl Future<Output = QueryResult<Arc<[Ipv4Addr]>>> {
        self.query_ipv4(key)
    }

    pub(crate) fn resolve_ipv6(
        &self,
        key: &str,
    ) -> impl Future<Output = QueryResult<Arc<[Ipv6Addr]>>> {
        self.query_ipv6(key)
    }

    pub(crate) fn resolve_ptr(
        &self,
        addr: IpAddr,
    ) -> impl Future<Output = QueryResult<Arc<[Box<str>]>>> {
        self.query_ptr(addr)
    }

    pub(crate) fn resolve_exists(&self, key: &str) -> impl Future<Output = crate::Result<bool>> {
        self.query_exists(key)
    }
}

#[cfg(any(test, feature = "test"))]
impl MessageAuthenticator {
    pub(crate) async fn resolve_txt(&self, key: &str) -> QueryResult<Vec<Vec<u8>>> {
        if true {
            return mock_query(key);
        }

        self.query_txt(key).await
    }

    pub(crate) async fn resolve_mx(&self, key: &str) -> QueryResult<Vec<(u16, Box<str>)>> {
        if true {
            return mock_query(key);
        }

        self.query_mx(key).await
    }

    pub(crate) async fn resolve_ipv4(&self, key: &str) -> QueryResult<Arc<[Ipv4Addr]>> {
        if true {
            return mock_query(key);
        }

        self.query_ipv4(key).await
    }

    pub(crate) async fn resolve_ipv6(&self, key: &str) -> QueryResult<Arc<[Ipv6Addr]>> {
        if true {
            return mock_query(key);
        }

        self.query_ipv6(key).await
    }

    pub(crate) async fn resolve_ptr(&self, addr: IpAddr) -> QueryResult<Arc<[Box<str>]>> {
        if true {
            return mock_query(&addr.to_string());
        }

        self.query_ptr(addr).await
    }

    pub(crate) async fn resolve_exists(&self, key: &str) -> crate::Result<bool> {
        if true {
            return match mock_query::<()>(key) {
                Err(QueryError::Other(err)) => Err(err),
                _ => Ok(false),
            };
        }

        self.query_exists(key).await
    }
}

impl MessageAuthenticator {
    pub(crate) fn cache_negative<K, V>(
        &self,
        err: QueryError,
        cache: Option<&impl ResolverCache<K, V>>,
        key: impl FnOnce() -> K,
        value: impl FnOnce(Negative) -> V,
    ) -> Error {
        match err {
            QueryError::NotFound { code, negative_ttl } => {
                let negative = Negative { code };
                if let Some(cache) = cache
                    && let Some(expires) = self.negative_expiry(negative_ttl)
                {
                    cache.insert(key(), value(negative), expires);
                }
                negative.into()
            }
            QueryError::Other(err) => err,
        }
    }

    fn negative_expiry(&self, negative_ttl: Option<u32>) -> Option<Instant> {
        let ttl = Duration::from_secs(u64::from(negative_ttl?)).min(self.max_negative_ttl);
        (!ttl.is_zero()).then(|| Instant::now() + ttl)
    }
}

#[cfg(any(test, feature = "test"))]
const MOCK_NEGATIVE_TTL: u32 = 300;

#[cfg(any(test, feature = "test"))]
fn mock_query<T>(name: &str) -> Result<T, QueryError> {
    use crate::DnsError;

    Err(if name.contains("_parse_error.") {
        QueryError::Other(Error::Parse)
    } else if name.contains("_invalid_record.") {
        QueryError::Other(Error::Dns(DnsError::InvalidRecordType))
    } else if name.contains("_dns_error.") {
        QueryError::Other(Error::Dns(DnsError::Resolver(String::new())))
    } else {
        QueryError::NotFound {
            code: super::DNS_RCODE_NXDOMAIN,
            negative_ttl: (!name.contains("_no_soa.")).then_some(MOCK_NEGATIVE_TTL),
        }
    })
}

#[cfg(any(test, feature = "test"))]
#[doc(hidden)]
pub fn mock_resolve<T>(domain: &str) -> crate::Result<T> {
    mock_query(domain).map_err(Error::from)
}

#[cfg(test)]
mod test {
    use crate::{
        DnsError, DnssecStatus, Error, MessageAuthenticator, Negative, RecordSet, ResolverCache,
        TxtRecord,
        dns::{DNS_RCODE_NXDOMAIN, ResponseCode, cache::test::DummyCaches},
        spf::SpfRecord,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
        time::{Duration, Instant},
    };

    const MISSING: &str = "missing.example.org.";
    const NO_SOA: &str = "missing._no_soa.example.org.";
    const SERVFAIL: &str = "missing._dns_error.example.org.";
    const NXDOMAIN: Negative = Negative {
        code: DNS_RCODE_NXDOMAIN,
    };
    #[cfg(not(feature = "dns-doh"))]
    const NODATA: ResponseCode = ResponseCode::NoError;
    #[cfg(feature = "dns-doh")]
    const NODATA: ResponseCode = 0;

    fn resolver() -> MessageAuthenticator {
        MessageAuthenticator::new_system_conf().expect("resolver")
    }

    fn four(error: Error) -> [Option<Error>; 4] {
        [(); 4].map(|_| Some(error.clone()))
    }

    fn ptr_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    async fn lookup_all(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        name: &str,
    ) -> [Option<Error>; 4] {
        [
            resolver
                .txt_lookup::<SpfRecord>(name, Some(&caches.txt))
                .await
                .err(),
            resolver.mx_lookup(name, Some(&caches.mx)).await.err(),
            resolver.ipv4_lookup(name, Some(&caches.ipv4)).await.err(),
            resolver.ipv6_lookup(name, Some(&caches.ipv6)).await.err(),
        ]
    }

    fn is_cached(caches: &DummyCaches, name: &str) -> [bool; 4] {
        [
            caches.txt.get::<str>(name).is_some(),
            caches.mx.get::<str>(name).is_some(),
            caches.ipv4.get::<str>(name).is_some(),
            caches.ipv6.get::<str>(name).is_some(),
        ]
    }

    // A negative answer with an SOA is stored in the cache of every record type.
    #[tokio::test]
    async fn negative_answers_are_cached() {
        let resolver = resolver();
        let caches = DummyCaches::new();
        for _ in 0..2 {
            assert_eq!(
                lookup_all(&resolver, &caches, MISSING).await,
                four(NXDOMAIN.into())
            );
            assert_eq!(
                resolver
                    .ptr_lookup(ptr_addr(), Some(&caches.ptr))
                    .await
                    .err(),
                Some(NXDOMAIN.into())
            );
        }

        assert!(matches!(
            caches.txt.get::<str>(MISSING),
            Some(TxtRecord::Error(Error::Dns(DnsError::RecordNotFound(code)))) if code == DNS_RCODE_NXDOMAIN
        ));
        assert_eq!(caches.mx.get::<str>(MISSING), Some(Err(NXDOMAIN)));
        assert_eq!(caches.ipv4.get::<str>(MISSING), Some(Err(NXDOMAIN)));
        assert_eq!(caches.ipv6.get::<str>(MISSING), Some(Err(NXDOMAIN)));
        assert_eq!(caches.ptr.get(&ptr_addr()), Some(Err(NXDOMAIN)));
    }

    // A cached NODATA answer is returned with its response code instead of querying.
    #[tokio::test]
    async fn cached_negative_answers_skip_the_query() {
        let resolver = resolver();
        let caches = DummyCaches::new();
        let nodata = Negative { code: NODATA };
        let expires = Instant::now() + Duration::from_secs(60);
        caches
            .txt
            .insert(SERVFAIL.into(), TxtRecord::Error(nodata.into()), expires);
        caches.mx.insert(SERVFAIL.into(), Err(nodata), expires);
        caches.ipv4.insert(SERVFAIL.into(), Err(nodata), expires);
        caches.ipv6.insert(SERVFAIL.into(), Err(nodata), expires);
        caches.ptr.insert(ptr_addr(), Err(nodata), expires);

        assert_eq!(
            lookup_all(&resolver, &caches, SERVFAIL).await,
            four(nodata.into())
        );
        assert_eq!(
            resolver
                .ptr_lookup(ptr_addr(), Some(&caches.ptr))
                .await
                .err(),
            Some(nodata.into())
        );
    }

    // Answers without an SOA, resolver failures and a zero cap are never cached.
    #[tokio::test]
    async fn uncacheable_answers_are_not_cached() {
        let caches = DummyCaches::new();

        let resolver = resolver();
        assert_eq!(
            lookup_all(&resolver, &caches, NO_SOA).await,
            four(NXDOMAIN.into())
        );
        assert_eq!(is_cached(&caches, NO_SOA), [false; 4]);

        assert_eq!(
            lookup_all(&resolver, &caches, SERVFAIL).await,
            four(Error::Dns(DnsError::Resolver(String::new())))
        );
        assert_eq!(is_cached(&caches, SERVFAIL), [false; 4]);

        let resolver = resolver.with_max_negative_ttl(Duration::ZERO);
        assert_eq!(
            lookup_all(&resolver, &caches, MISSING).await,
            four(NXDOMAIN.into())
        );
        assert!(
            resolver
                .ptr_lookup(ptr_addr(), Some(&caches.ptr))
                .await
                .is_err()
        );
        assert_eq!(is_cached(&caches, MISSING), [false; 4]);
        assert_eq!(caches.ptr.get(&ptr_addr()), None);
    }

    // The SOA negative TTL is capped by the configured maximum.
    #[test]
    fn negative_ttl_is_capped() {
        let resolver = resolver().with_max_negative_ttl(Duration::from_secs(60));

        let before = Instant::now();
        let expires = resolver.negative_expiry(Some(300)).expect("cacheable");
        assert!(expires >= before + Duration::from_secs(60));
        assert!(expires <= Instant::now() + Duration::from_secs(60));

        let before = Instant::now();
        let expires = resolver.negative_expiry(Some(30)).expect("cacheable");
        assert!(expires >= before + Duration::from_secs(30));
        assert!(expires <= Instant::now() + Duration::from_secs(30));

        assert_eq!(resolver.negative_expiry(None), None);
        assert_eq!(resolver.negative_expiry(Some(0)), None);
        assert_eq!(
            resolver
                .with_max_negative_ttl(Duration::ZERO)
                .negative_expiry(Some(300)),
            None
        );
    }

    // `exists` answers from cached negatives for both types and queries otherwise.
    #[tokio::test]
    async fn exists_uses_cached_negatives() {
        let resolver = resolver();
        let caches = DummyCaches::new();
        let expires = Instant::now() + Duration::from_secs(60);
        let exists = || resolver.exists(SERVFAIL, Some(&caches.ipv4), Some(&caches.ipv6));
        let servfail = Err(Error::Dns(DnsError::Resolver(String::new())));

        caches.ipv4.insert(SERVFAIL.into(), Err(NXDOMAIN), expires);
        assert_eq!(exists().await, servfail);

        caches.ipv6.insert(SERVFAIL.into(), Err(NXDOMAIN), expires);
        assert_eq!(exists().await, Ok(false));

        caches.ipv4.insert(
            SERVFAIL.into(),
            Ok(RecordSet {
                records: Arc::new([]),
                dnssec_status: DnssecStatus::Secure,
            }),
            expires,
        );
        assert_eq!(exists().await, Ok(false));

        caches.ipv6.insert(
            SERVFAIL.into(),
            Ok(RecordSet {
                records: Arc::new([Ipv6Addr::LOCALHOST]),
                dnssec_status: DnssecStatus::Indeterminate,
            }),
            expires,
        );
        assert_eq!(exists().await, Ok(true));

        assert_eq!(
            resolver
                .exists(MISSING, Some(&caches.ipv4), Some(&caches.ipv6))
                .await,
            Ok(false)
        );
        assert_eq!(is_cached(&caches, MISSING), [false; 4]);
    }
}
