/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Cached DNS lookup helpers on [`MessageAuthenticator`].

use super::{
    DnsEntry, DnssecStatus, IpLookupStrategy, Mx, RecordSet, ResolverCache, ToFqdn, TxtRecord,
    TxtRecordParser, UnwrapTxtRecord,
};
use crate::{Error, MessageAuthenticator};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

impl MessageAuthenticator {
    /// Queries the TXT records of `key` and returns their contents
    /// concatenated into one byte string, without parsing or caching.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn txt_raw_lookup(&self, key: impl ToFqdn) -> crate::Result<Vec<u8>> {
        let key = key.to_fqdn();
        Ok(self
            .query_txt(key.as_ref())
            .await?
            .entry
            .into_iter()
            .flatten()
            .collect())
    }

    /// Queries the TXT records of `key` and returns the first one that parses
    /// as `T` (for example [`SpfRecord`](crate::spf::SpfRecord),
    /// [`DmarcRecord`](crate::dmarc::DmarcRecord) or
    /// [`TlsRptRecord`](crate::mta_sts::TlsRptRecord)).
    ///
    /// When `cache` is set, a cached entry is returned without querying, and
    /// the parse outcome (the record or the parse error) is stored after a
    /// query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    /// When no record parses as `T`, returns the error of the last parse
    /// attempt (usually [`DnsError::InvalidRecordType`](crate::DnsError::InvalidRecordType)),
    /// or `InvalidRecordType` when the answer holds no TXT data.
    pub async fn txt_lookup<T: TxtRecordParser + Into<TxtRecord> + UnwrapTxtRecord>(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
    ) -> crate::Result<Arc<T>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return T::unwrap_txt(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let DnsEntry {
            entry: records,
            expires,
        } = self.query_txt(key.as_ref()).await?;

        let mut result = Err(Error::Dns(crate::DnsError::InvalidRecordType));
        for record in &records {
            result = T::parse(record);
            if result.is_ok() {
                break;
            }
        }

        let result: TxtRecord = result.into();

        if let Some(cache) = cache {
            cache.insert(key.into_owned().into_boxed_str(), result.clone(), expires);
        }

        T::unwrap_txt(result)
    }

    /// Queries the MX records of `key` (RFC 5321 Section 5.1).
    ///
    /// Records are grouped by preference into [`Mx`] values sorted by
    /// ascending preference. When `cache` is set, it is consulted before and
    /// updated after the query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn mx_lookup(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, RecordSet<Mx>>>,
    ) -> crate::Result<RecordSet<Mx>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let DnsEntry {
            entry: mx_records,
            expires,
        } = self.query_mx(key.as_ref()).await?;

        let mut records: Vec<(u16, Vec<Box<str>>)> = Vec::with_capacity(mx_records.len());
        for (preference, exchange) in mx_records {
            if let Some(record) = records.iter_mut().find(|r| r.0 == preference) {
                record.1.push(exchange);
            } else {
                records.push((preference, vec![exchange]));
            }
        }

        records.sort_unstable_by_key(|a| a.0);
        let records: Arc<[Mx]> = records
            .into_iter()
            .map(|(preference, exchanges)| Mx {
                preference,
                exchanges: exchanges.into_boxed_slice(),
            })
            .collect::<Arc<[Mx]>>();
        let records = RecordSet {
            records,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(key.into_owned().into_boxed_str(), records.clone(), expires);
        }

        Ok(records)
    }

    /// Queries the A records of `key`. When `cache` is set, it is consulted
    /// before and updated after the query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn ipv4_lookup(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
    ) -> crate::Result<RecordSet<Ipv4Addr>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return Ok(value);
        }

        let ipv4_lookup = self.ipv4_lookup_raw(key.as_ref()).await?;
        let records = RecordSet {
            records: ipv4_lookup.entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(
                key.into_owned().into_boxed_str(),
                records.clone(),
                ipv4_lookup.expires,
            );
        }

        Ok(records)
    }

    /// Queries the A records of `key` without caching. `key` is queried as
    /// given, without conversion to a fully qualified name. Returns the
    /// addresses with their expiry time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn ipv4_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<[Ipv4Addr]>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        self.query_ipv4(key).await
    }

    /// Queries the AAAA records of `key`. When `cache` is set, it is consulted
    /// before and updated after the query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn ipv6_lookup(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>>>,
    ) -> crate::Result<RecordSet<Ipv6Addr>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return Ok(value);
        }

        let ipv6_lookup = self.ipv6_lookup_raw(key.as_ref()).await?;
        let records = RecordSet {
            records: ipv6_lookup.entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(
                key.into_owned().into_boxed_str(),
                records.clone(),
                ipv6_lookup.expires,
            );
        }

        Ok(records)
    }

    /// Queries the AAAA records of `key` without caching. `key` is queried as
    /// given, without conversion to a fully qualified name. Returns the
    /// addresses with their expiry time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the name has no records of this type, [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name.
    pub async fn ipv6_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<[Ipv6Addr]>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        self.query_ipv6(key).await
    }

    /// Resolves `key` to at most `max_results` IP addresses, querying A and
    /// AAAA records in the order given by `strategy`.
    ///
    /// With a fallback strategy ([`IpLookupStrategy::Ipv4thenIpv6`] or
    /// [`IpLookupStrategy::Ipv6thenIpv4`]), any error from the first query
    /// triggers the second one. The caches are consulted before and updated
    /// after each query.
    ///
    /// # Errors
    ///
    /// Returns the error of the last query performed. See
    /// [`ipv4_lookup`](Self::ipv4_lookup) for the possible errors.
    pub async fn ip_lookup(
        &self,
        key: &str,
        mut strategy: IpLookupStrategy,
        max_results: usize,
        cache_ipv4: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
        cache_ipv6: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>>>,
    ) -> crate::Result<Vec<IpAddr>> {
        loop {
            match strategy {
                IpLookupStrategy::Ipv4Only | IpLookupStrategy::Ipv4thenIpv6 => {
                    match (self.ipv4_lookup(key, cache_ipv4).await, strategy) {
                        (Ok(result), _) => {
                            return Ok(result
                                .records
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect());
                        }
                        (Err(err), IpLookupStrategy::Ipv4Only) => return Err(err),
                        _ => {
                            strategy = IpLookupStrategy::Ipv6Only;
                        }
                    }
                }
                IpLookupStrategy::Ipv6Only | IpLookupStrategy::Ipv6thenIpv4 => {
                    match (self.ipv6_lookup(key, cache_ipv6).await, strategy) {
                        (Ok(result), _) => {
                            return Ok(result
                                .records
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect());
                        }
                        (Err(err), IpLookupStrategy::Ipv6Only) => return Err(err),
                        _ => {
                            strategy = IpLookupStrategy::Ipv4Only;
                        }
                    }
                }
            }
        }
    }

    /// Queries the PTR records of `addr` (reverse DNS). Host names are
    /// returned lowercased. When `cache` is set, it is consulted before and
    /// updated after the query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::RecordNotFound`](crate::DnsError::RecordNotFound)
    /// when the address has no PTR record, or [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when the query fails.
    pub async fn ptr_lookup(
        &self,
        addr: IpAddr,
        cache: Option<&impl ResolverCache<IpAddr, RecordSet<Box<str>>>>,
    ) -> crate::Result<RecordSet<Box<str>>> {
        if let Some(value) = cache.as_ref().and_then(|c| c.get(&addr)) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(&addr.to_string());
        }

        let DnsEntry { entry, expires } = self.query_ptr(addr).await?;
        let ptr = RecordSet {
            records: entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(addr, ptr.clone(), expires);
        }

        Ok(ptr)
    }

    /// Returns `true` if `key` has at least one A or AAAA record, as needed by
    /// the SPF `exists` mechanism (RFC 7208 Section 5.7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when a query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name. A name without records is not an error.
    #[cfg(any(test, feature = "test"))]
    pub async fn exists(
        &self,
        key: impl ToFqdn,
        cache_ipv4: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
        cache_ipv6: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>>>,
    ) -> crate::Result<bool> {
        let key = key.to_fqdn();
        match self.ipv4_lookup(key.as_ref(), cache_ipv4).await {
            Ok(_) => Ok(true),
            Err(Error::Dns(crate::DnsError::RecordNotFound(_))) => {
                match self.ipv6_lookup(key.as_ref(), cache_ipv6).await {
                    Ok(_) => Ok(true),
                    Err(Error::Dns(crate::DnsError::RecordNotFound(_))) => Ok(false),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Returns `true` if `key` has at least one A or AAAA record, as needed by
    /// the SPF `exists` mechanism (RFC 7208 Section 5.7).
    ///
    /// A cached A or AAAA entry for `key` answers `true` without querying.
    /// Query results are not added to the caches.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::Resolver`](crate::DnsError::Resolver)
    /// when a query fails, or [`Error::Parse`] when the name is not a valid
    /// DNS name. A name without records is not an error.
    #[cfg(not(any(test, feature = "test")))]
    pub async fn exists(
        &self,
        key: impl ToFqdn,
        cache_ipv4: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
        cache_ipv6: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>>>,
    ) -> crate::Result<bool> {
        let key = key.to_fqdn();

        if cache_ipv4.is_some_and(|c| c.get::<str>(key.as_ref()).is_some())
            || cache_ipv6.is_some_and(|c| c.get::<str>(key.as_ref()).is_some())
        {
            return Ok(true);
        }

        self.query_exists(key.as_ref()).await
    }
}

#[cfg(any(test, feature = "test"))]
#[doc(hidden)]
pub fn mock_resolve<T>(domain: &str) -> crate::Result<T> {
    Err(if domain.contains("_parse_error.") {
        Error::Parse
    } else if domain.contains("_invalid_record.") {
        Error::Dns(crate::DnsError::InvalidRecordType)
    } else if domain.contains("_dns_error.") {
        Error::Dns(crate::DnsError::Resolver("".to_string()))
    } else {
        Error::Dns(crate::DnsError::RecordNotFound(super::DNS_RCODE_NXDOMAIN))
    })
}
