use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    proto::rr::RecordType,
    system_conf::read_system_conf,
    AsyncResolver,
};

use crate::{
    dkim::{Atps, DomainKey},
    dmarc::DMARC,
    spf::{Macro, SPF},
    Error, Policy, Resolver, Txt, MX,
};

use super::{
    lru::{DnsCache, LruCache},
    parse::TxtRecordParser,
};

impl Resolver {
    pub fn new_cloudflare_tls() -> Result<Self, ResolveError> {
        Self::new(
            ResolverConfig::cloudflare_tls(),
            ResolverOpts::default(),
            128,
        )
    }

    pub fn new_cloudflare() -> Result<Self, ResolveError> {
        Self::new(ResolverConfig::cloudflare(), ResolverOpts::default(), 128)
    }

    pub fn new_google() -> Result<Self, ResolveError> {
        Self::new(ResolverConfig::google(), ResolverOpts::default(), 128)
    }

    pub fn new_quad9() -> Result<Self, ResolveError> {
        Self::new(ResolverConfig::quad9(), ResolverOpts::default(), 128)
    }

    pub fn new_quad9_tls() -> Result<Self, ResolveError> {
        Self::new(ResolverConfig::quad9_tls(), ResolverOpts::default(), 128)
    }

    pub fn new_system_conf() -> Result<Self, ResolveError> {
        let (config, options) = read_system_conf()?;
        Self::new(config, options, 128)
    }

    pub fn new(
        config: ResolverConfig,
        options: ResolverOpts,
        capacity: usize,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options)?,
            cache_txt: LruCache::with_capacity(capacity),
            cache_mx: LruCache::with_capacity(capacity),
            cache_ipv4: LruCache::with_capacity(capacity),
            cache_ipv6: LruCache::with_capacity(capacity),
            cache_ptr: LruCache::with_capacity(capacity),
            host_domain: String::new(),
            verify_policy: Policy::VeryStrict,
        })
    }

    pub fn with_host_domain(mut self, hostname: &str) -> Self {
        self.host_domain = hostname.to_lowercase();
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.verify_policy = policy;
        self
    }

    pub(crate) async fn txt_lookup<'x, T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<T>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_txt.get(key.as_ref()) {
            return T::unwrap_txt(value);
        }

        #[cfg(test)]
        if true {
            return mock_resolve(key.as_ref());
        }

        let txt_lookup = self.resolver.txt_lookup(key.as_ref()).await?;
        let mut result = Err(Error::InvalidRecordType);
        let records = txt_lookup.as_lookup().record_iter().filter_map(|r| {
            let txt_data = r.data()?.as_txt()?.txt_data();
            match txt_data.len() {
                1 => Cow::from(txt_data[0].as_ref()).into(),
                0 => None,
                _ => {
                    let mut entry = Vec::with_capacity(255 * txt_data.len());
                    for data in txt_data {
                        entry.extend_from_slice(data);
                    }
                    Cow::from(entry).into()
                }
            }
        });

        for record in records {
            result = T::parse(record.as_ref());
            if result.is_ok() {
                break;
            }
        }
        T::unwrap_txt(self.cache_txt.insert(
            key.into_owned(),
            result.into(),
            txt_lookup.valid_until(),
        ))
    }

    pub async fn mx_lookup<'x>(&self, key: impl IntoFqdn<'x>) -> crate::Result<Arc<Vec<MX>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_mx.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(test)]
        if true {
            return mock_resolve(key.as_ref());
        }

        let mx_lookup = self.resolver.mx_lookup(key.as_ref()).await?;
        let mut records = mx_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| {
                let mx = r.data()?.as_mx()?;
                MX {
                    exchange: mx.exchange().to_lowercase().to_string(),
                    preference: mx.preference(),
                }
                .into()
            })
            .collect::<Vec<_>>();
        records.sort_unstable_by(|a, b| a.preference.cmp(&b.preference));

        Ok(self
            .cache_mx
            .insert(key.into_owned(), Arc::new(records), mx_lookup.valid_until()))
    }

    pub async fn ipv4_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<Vec<Ipv4Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_ipv4.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(test)]
        if true {
            return mock_resolve(key.as_ref());
        }

        let ipv4_lookup = self.resolver.ipv4_lookup(key.as_ref()).await?;
        let ips = ipv4_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| (*r.data()?.as_a()?).into())
            .collect::<Vec<_>>();

        Ok(self
            .cache_ipv4
            .insert(key.into_owned(), Arc::new(ips), ipv4_lookup.valid_until()))
    }

    pub async fn ipv6_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<Vec<Ipv6Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_ipv6.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(test)]
        if true {
            return mock_resolve(key.as_ref());
        }

        let ipv6_lookup = self.resolver.ipv6_lookup(key.as_ref()).await?;
        let ips = ipv6_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| (*r.data()?.as_aaaa()?).into())
            .collect::<Vec<_>>();

        Ok(self
            .cache_ipv6
            .insert(key.into_owned(), Arc::new(ips), ipv6_lookup.valid_until()))
    }

    pub async fn ptr_lookup<'x>(&self, addr: IpAddr) -> crate::Result<Arc<Vec<String>>> {
        if let Some(value) = self.cache_ptr.get(&addr) {
            return Ok(value);
        }

        #[cfg(test)]
        if true {
            return mock_resolve(&addr.to_string());
        }

        let ptr_lookup = self.resolver.reverse_lookup(addr).await?;
        let ptr = ptr_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| r.data()?.as_ptr()?.to_lowercase().to_string().into())
            .collect::<Vec<_>>();

        Ok(self
            .cache_ptr
            .insert(addr, Arc::new(ptr), ptr_lookup.valid_until()))
    }

    pub(crate) async fn exists<'x>(&self, key: impl IntoFqdn<'x>) -> crate::Result<bool> {
        #[cfg(test)]
        if true {
            let key = key.into_fqdn().into_owned();
            return match self.ipv4_lookup(key.as_str()).await {
                Ok(_) => Ok(true),
                Err(Error::DNSRecordNotFound(_)) => match self.ipv6_lookup(key.as_str()).await {
                    Ok(_) => Ok(true),
                    Err(Error::DNSRecordNotFound(_)) => Ok(false),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            };
        }

        let key = key.into_fqdn();
        match self.resolver.lookup_ip(key.as_ref()).await {
            Ok(result) => Ok(result.as_lookup().record_iter().any(|r| {
                r.data().map_or(false, |d| {
                    matches!(d.to_record_type(), RecordType::A | RecordType::AAAA)
                })
            })),
            Err(err) => {
                if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    Ok(false)
                } else {
                    Err(Error::DNSError)
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn txt_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: impl Into<Txt>,
        valid_until: std::time::Instant,
    ) {
        self.cache_txt
            .insert(name.into_fqdn().into_owned(), value.into(), valid_until);
    }

    #[cfg(test)]
    pub(crate) fn ipv4_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<Ipv4Addr>,
        valid_until: std::time::Instant,
    ) {
        self.cache_ipv4
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }

    #[cfg(test)]
    pub(crate) fn ipv6_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<Ipv6Addr>,
        valid_until: std::time::Instant,
    ) {
        self.cache_ipv6
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }

    #[cfg(test)]
    pub(crate) fn ptr_add(
        &self,
        name: IpAddr,
        value: Vec<String>,
        valid_until: std::time::Instant,
    ) {
        self.cache_ptr.insert(name, Arc::new(value), valid_until);
    }

    #[cfg(test)]
    pub(crate) fn mx_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<MX>,
        valid_until: std::time::Instant,
    ) {
        self.cache_mx
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }
}

impl From<ResolveError> for Error {
    fn from(err: ResolveError) -> Self {
        match err.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                Error::DNSRecordNotFound(*response_code)
            }
            _ => Error::DNSError,
        }
    }
}

impl From<DomainKey> for Txt {
    fn from(v: DomainKey) -> Self {
        Txt::DomainKey(v.into())
    }
}

impl From<Atps> for Txt {
    fn from(v: Atps) -> Self {
        Txt::Atps(v.into())
    }
}

impl From<SPF> for Txt {
    fn from(v: SPF) -> Self {
        Txt::SPF(v.into())
    }
}

impl From<Macro> for Txt {
    fn from(v: Macro) -> Self {
        Txt::SPFMacro(v.into())
    }
}

impl From<DMARC> for Txt {
    fn from(v: DMARC) -> Self {
        Txt::DMARC(v.into())
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

pub(crate) trait UnwrapTxtRecord: Sized {
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

impl UnwrapTxtRecord for Atps {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Atps(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for SPF {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::SPF(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Macro {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::SPFMacro(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for DMARC {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::DMARC(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
}

impl<'x> IntoFqdn<'x> for String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x str {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
        }
    }
}

#[cfg(test)]
fn mock_resolve<T>(domain: &str) -> crate::Result<T> {
    Err(if domain.contains("_parse_error.") {
        Error::ParseError
    } else if domain.contains("_invalid_record.") {
        Error::InvalidRecordType
    } else if domain.contains("_dns_error.") {
        Error::DNSError
    } else {
        Error::DNSRecordNotFound(trust_dns_resolver::proto::op::ResponseCode::NXDomain)
    })
}
