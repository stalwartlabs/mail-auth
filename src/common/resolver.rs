/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{parse::TxtRecordParser, verify::DomainKey};
use crate::Instant;
use crate::{
    DnssecStatus, Error, IpLookupStrategy, MX, MessageAuthenticator, RecordSet, ResolverCache, Txt,
    dkim::{Atps, DomainKeyReport},
    dmarc::Dmarc,
    mta_sts::{MtaSts, TlsRpt},
    spf::{Macro, Spf},
};
#[cfg(not(feature = "dns-doh"))]
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub struct DnsEntry<T> {
    pub entry: T,
    pub expires: Instant,
}

#[cfg(not(feature = "dns-doh"))]
impl MessageAuthenticator {
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_cloudflare_tls() -> Result<Self, NetError> {
        Self::new(ResolverConfig::tls(&CLOUDFLARE), ResolverOpts::default())
    }

    pub fn new_cloudflare() -> Result<Self, NetError> {
        Self::new(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            ResolverOpts::default(),
        )
    }

    pub fn new_google() -> Result<Self, NetError> {
        Self::new(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            ResolverOpts::default(),
        )
    }

    pub fn new_quad9() -> Result<Self, NetError> {
        Self::new(ResolverConfig::udp_and_tcp(&QUAD9), ResolverOpts::default())
    }

    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_quad9_tls() -> Result<Self, NetError> {
        Self::new(ResolverConfig::tls(&QUAD9), ResolverOpts::default())
    }

    pub fn new_system_conf() -> Result<Self, NetError> {
        let (config, options) = read_system_conf()?;
        Self::new(config, options)
    }

    pub fn new(config: ResolverConfig, options: ResolverOpts) -> Result<Self, NetError> {
        Ok(MessageAuthenticator(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()?,
        ))
    }

    pub fn resolver(&self) -> &TokioResolver {
        &self.0
    }
}

impl MessageAuthenticator {
    pub async fn txt_raw_lookup(&self, key: impl ToFqdn) -> crate::Result<Vec<u8>> {
        let key = key.to_fqdn();

        #[cfg(not(feature = "dns-doh"))]
        let records = {
            let lookup = self
                .0
                .txt_lookup(Name::from_str_relaxed::<&str>(key.as_ref())?)
                .await?;
            let mut records: Vec<Vec<u8>> = Vec::new();
            for record in lookup.answers() {
                if let RData::TXT(txt) = &record.data {
                    let mut entry = Vec::new();
                    for item in &txt.txt_data {
                        entry.extend_from_slice(item);
                    }
                    records.push(entry);
                }
            }
            records
        };

        #[cfg(feature = "dns-doh")]
        let records = self.doh_txt(key.as_ref()).await?.entry;

        Ok(records.into_iter().flatten().collect())
    }

    pub async fn txt_lookup<T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, Txt>>,
    ) -> crate::Result<Arc<T>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return T::unwrap_txt(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        #[cfg(not(feature = "dns-doh"))]
        let (records, expires) = {
            let lookup = self
                .0
                .txt_lookup(Name::from_str_relaxed::<&str>(key.as_ref())?)
                .await?;
            let expires = lookup.valid_until();
            let mut records: Vec<Vec<u8>> = Vec::new();
            for record in lookup.answers() {
                let RData::TXT(txt) = &record.data else {
                    continue;
                };
                match txt.txt_data.len() {
                    0 => {}
                    1 => records.push(txt.txt_data[0].to_vec()),
                    _ => {
                        let mut entry = Vec::with_capacity(255 * txt.txt_data.len());
                        for data in txt.txt_data.iter() {
                            entry.extend_from_slice(data);
                        }
                        records.push(entry);
                    }
                }
            }
            (records, expires)
        };

        #[cfg(feature = "dns-doh")]
        let (records, expires) = {
            let raw = self.doh_txt(key.as_ref()).await?;
            (raw.entry, raw.expires)
        };

        let mut result = Err(Error::Dns(crate::DnsError::InvalidRecordType));
        for record in &records {
            result = T::parse(record);
            if result.is_ok() {
                break;
            }
        }

        let result: Txt = result.into();

        if let Some(cache) = cache {
            cache.insert(key, result.clone(), expires);
        }

        T::unwrap_txt(result)
    }

    pub async fn mx_lookup(
        &self,
        key: impl ToFqdn,
        cache: Option<&impl ResolverCache<Box<str>, RecordSet<MX>>>,
    ) -> crate::Result<RecordSet<MX>> {
        let key = key.to_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get::<str>(key.as_ref())) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        #[cfg(not(feature = "dns-doh"))]
        let (mx_records, expires): (Vec<(u16, Box<str>)>, Instant) = {
            let lookup = self
                .0
                .mx_lookup(Name::from_str_relaxed::<&str>(key.as_ref())?)
                .await?;
            let expires = lookup.valid_until();
            let mx_records = lookup
                .answers()
                .iter()
                .filter_map(|r| {
                    let RData::MX(mx) = &r.data else {
                        return None;
                    };
                    Some((
                        mx.preference,
                        mx.exchange.to_lowercase().to_string().into_boxed_str(),
                    ))
                })
                .collect();
            (mx_records, expires)
        };

        #[cfg(feature = "dns-doh")]
        let (mx_records, expires): (Vec<(u16, Box<str>)>, Instant) = {
            let raw = self.doh_mx(key.as_ref()).await?;
            (raw.entry, raw.expires)
        };

        let mut records: Vec<(u16, Vec<Box<str>>)> = Vec::with_capacity(mx_records.len());
        for (preference, exchange) in mx_records {
            if let Some(record) = records.iter_mut().find(|r| r.0 == preference) {
                record.1.push(exchange);
            } else {
                records.push((preference, vec![exchange]));
            }
        }

        records.sort_unstable_by_key(|a| a.0);
        let records: Arc<[MX]> = records
            .into_iter()
            .map(|(preference, exchanges)| MX {
                preference,
                exchanges: exchanges.into_boxed_slice(),
            })
            .collect::<Arc<[MX]>>();
        let records = RecordSet {
            rrset: records,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(key, records.clone(), expires);
        }

        Ok(records)
    }

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
            rrset: ipv4_lookup.entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(key, records.clone(), ipv4_lookup.expires);
        }

        Ok(records)
    }

    pub async fn ipv4_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<[Ipv4Addr]>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        #[cfg(not(feature = "dns-doh"))]
        {
            let lookup = self
                .0
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

        #[cfg(feature = "dns-doh")]
        self.doh_ipv4(key).await
    }

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
            rrset: ipv6_lookup.entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(key, records.clone(), ipv6_lookup.expires);
        }

        Ok(records)
    }

    pub async fn ipv6_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<[Ipv6Addr]>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        #[cfg(not(feature = "dns-doh"))]
        {
            let lookup = self
                .0
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

        #[cfg(feature = "dns-doh")]
        self.doh_ipv6(key).await
    }

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
                                .rrset
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
                                .rrset
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

        #[cfg(not(feature = "dns-doh"))]
        let (entry, expires): (Arc<[Box<str>]>, Instant) = {
            let lookup = self.0.reverse_lookup(addr).await?;
            let expires = lookup.valid_until();
            let entry = lookup
                .answers()
                .iter()
                .filter_map(|r| {
                    let RData::PTR(ptr) = &r.data else {
                        return None;
                    };
                    if !ptr.is_empty() {
                        Some(ptr.to_lowercase().to_string().into_boxed_str())
                    } else {
                        None
                    }
                })
                .collect::<Arc<[Box<str>]>>();
            (entry, expires)
        };

        #[cfg(feature = "dns-doh")]
        let (entry, expires): (Arc<[Box<str>]>, Instant) = {
            let raw = self.doh_ptr(addr).await?;
            (raw.entry, raw.expires)
        };

        let ptr = RecordSet {
            rrset: entry,
            dnssec_status: DnssecStatus::Indeterminate,
        };

        if let Some(cache) = cache {
            cache.insert(addr, ptr.clone(), expires);
        }

        Ok(ptr)
    }

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

        #[cfg(not(feature = "dns-doh"))]
        {
            match self
                .0
                .lookup_ip(Name::from_str_relaxed::<&str>(key.as_ref())?)
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

        #[cfg(feature = "dns-doh")]
        self.doh_exists(key.as_ref()).await
    }
}

#[cfg(not(feature = "dns-doh"))]
impl From<ProtoError> for Error {
    fn from(err: ProtoError) -> Self {
        Error::Dns(crate::DnsError::Resolver(err.to_string()))
    }
}

#[cfg(not(feature = "dns-doh"))]
impl From<NetError> for Error {
    fn from(err: NetError) -> Self {
        match &err {
            NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                Error::Dns(crate::DnsError::RecordNotFound(no_records.response_code))
            }
            _ => Error::Dns(crate::DnsError::Resolver(err.to_string())),
        }
    }
}

impl From<DomainKey> for Txt {
    fn from(v: DomainKey) -> Self {
        Txt::DomainKey(v.into())
    }
}

impl From<DomainKeyReport> for Txt {
    fn from(v: DomainKeyReport) -> Self {
        Txt::DomainKeyReport(v.into())
    }
}

impl From<Atps> for Txt {
    fn from(v: Atps) -> Self {
        Txt::Atps(v.into())
    }
}

impl From<Spf> for Txt {
    fn from(v: Spf) -> Self {
        Txt::Spf(v.into())
    }
}

impl From<Macro> for Txt {
    fn from(v: Macro) -> Self {
        Txt::SpfMacro(v.into())
    }
}

impl From<Dmarc> for Txt {
    fn from(v: Dmarc) -> Self {
        Txt::Dmarc(v.into())
    }
}

impl From<MtaSts> for Txt {
    fn from(v: MtaSts) -> Self {
        Txt::MtaSts(v.into())
    }
}

impl From<TlsRpt> for Txt {
    fn from(v: TlsRpt) -> Self {
        Txt::TlsRpt(v.into())
    }
}

impl<T: Into<Txt>> From<crate::Result<T>> for Txt {
    fn from(v: crate::Result<T>) -> Self {
        match v {
            Ok(v) => v.into(),
            Err(err) => Txt::Error(err),
        }
    }
}

pub trait UnwrapTxtRecord: Sized {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>>;
}

impl UnwrapTxtRecord for DomainKey {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::DomainKey(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for DomainKeyReport {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::DomainKeyReport(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Atps {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Atps(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Spf {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Spf(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Macro {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::SpfMacro(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Dmarc {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Dmarc(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for MtaSts {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::MtaSts(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for TlsRpt {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::TlsRpt(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

pub trait ToFqdn {
    fn to_fqdn(&self) -> Box<str>;
}

impl<T: AsRef<str>> ToFqdn for T {
    fn to_fqdn(&self) -> Box<str> {
        let value = self.as_ref();
        if value.ends_with('.') {
            value.to_lowercase().into()
        } else {
            format!("{}.", value.to_lowercase()).into()
        }
    }
}

pub trait ToReverseName {
    fn to_reverse_name(&self) -> String;
}

impl ToReverseName for IpAddr {
    fn to_reverse_name(&self) -> String {
        use std::fmt::Write;

        match self {
            IpAddr::V4(ip) => {
                let mut segments = String::with_capacity(15);
                for octet in ip.octets().iter().rev() {
                    if !segments.is_empty() {
                        segments.push('.');
                    }
                    let _ = write!(&mut segments, "{}", octet);
                }
                segments
            }
            IpAddr::V6(ip) => {
                let mut segments = String::with_capacity(63);
                for segment in ip.segments().iter().rev() {
                    for &p in format!("{segment:04x}").as_bytes().iter().rev() {
                        if !segments.is_empty() {
                            segments.push('.');
                        }
                        segments.push(char::from(p));
                    }
                }
                segments
            }
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub fn mock_resolve<T>(domain: &str) -> crate::Result<T> {
    Err(if domain.contains("_parse_error.") {
        Error::ParseError
    } else if domain.contains("_invalid_record.") {
        Error::Dns(crate::DnsError::InvalidRecordType)
    } else if domain.contains("_dns_error.") {
        Error::Dns(crate::DnsError::Resolver("".to_string()))
    } else {
        Error::Dns(crate::DnsError::RecordNotFound(crate::DNS_RCODE_NXDOMAIN))
    })
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::common::resolver::ToReverseName;

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
