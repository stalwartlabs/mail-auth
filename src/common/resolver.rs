/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::{ProtoError, ProtoErrorKind},
    system_conf::read_system_conf,
    Name, TokioResolver,
};

use crate::{
    dkim::{Atps, DomainKeyReport},
    dmarc::Dmarc,
    mta_sts::{MtaSts, TlsRpt},
    spf::{Macro, Spf},
    Error, IpLookupStrategy, MessageAuthenticator, ResolverCache, Txt, MX,
};

use super::{parse::TxtRecordParser, verify::DomainKey};

pub struct DnsEntry<T> {
    pub entry: T,
    pub expires: Instant,
}

impl MessageAuthenticator {
    pub fn new_cloudflare_tls() -> Result<Self, ProtoError> {
        Self::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
    }

    pub fn new_cloudflare() -> Result<Self, ProtoError> {
        Self::new(ResolverConfig::cloudflare(), ResolverOpts::default())
    }

    pub fn new_google() -> Result<Self, ProtoError> {
        Self::new(ResolverConfig::google(), ResolverOpts::default())
    }

    pub fn new_quad9() -> Result<Self, ProtoError> {
        Self::new(ResolverConfig::quad9(), ResolverOpts::default())
    }

    pub fn new_quad9_tls() -> Result<Self, ProtoError> {
        Self::new(ResolverConfig::quad9_tls(), ResolverOpts::default())
    }

    pub fn new_system_conf() -> Result<Self, ProtoError> {
        let (config, options) = read_system_conf()?;
        Self::new(config, options)
    }

    pub fn new(config: ResolverConfig, options: ResolverOpts) -> Result<Self, ProtoError> {
        Ok(MessageAuthenticator(
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(options)
                .build(),
        ))
    }

    pub fn resolver(&self) -> &TokioResolver {
        &self.0
    }

    pub async fn txt_raw_lookup(&self, key: impl IntoFqdn<'_>) -> crate::Result<Vec<u8>> {
        let mut result = vec![];
        for record in self
            .0
            .txt_lookup(Name::from_str_relaxed(key.into_fqdn().as_ref())?)
            .await?
            .as_lookup()
            .record_iter()
        {
            if let Some(txt_data) = record.data().as_txt() {
                for item in txt_data.txt_data() {
                    result.extend_from_slice(item);
                }
            }
        }

        Ok(result)
    }

    pub async fn txt_lookup<'x, T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl IntoFqdn<'x>,
        cache: Option<&impl ResolverCache<String, Txt>>,
    ) -> crate::Result<Arc<T>> {
        let key = key.into_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get(key.as_ref())) {
            return T::unwrap_txt(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let txt_lookup = self
            .0
            .txt_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let mut result = Err(Error::InvalidRecordType);
        let records = txt_lookup.as_lookup().record_iter().filter_map(|r| {
            let txt_data = r.data().as_txt()?.txt_data();
            match txt_data.len() {
                1 => Some(Cow::from(txt_data[0].as_ref())),
                0 => None,
                _ => {
                    let mut entry = Vec::with_capacity(255 * txt_data.len());
                    for data in txt_data {
                        entry.extend_from_slice(data);
                    }
                    Some(Cow::from(entry))
                }
            }
        });

        for record in records {
            result = T::parse(record.as_ref());
            if result.is_ok() {
                break;
            }
        }

        let result: Txt = result.into();

        if let Some(cache) = cache {
            cache.insert(key.into_owned(), result.clone(), txt_lookup.valid_until());
        }

        T::unwrap_txt(result)
    }

    pub async fn mx_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        cache: Option<&impl ResolverCache<String, Arc<Vec<MX>>>>,
    ) -> crate::Result<Arc<Vec<MX>>> {
        let key = key.into_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get(key.as_ref())) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let mx_lookup = self
            .0
            .mx_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let mx_records = mx_lookup.as_lookup().records();
        let mut records: Vec<MX> = Vec::with_capacity(mx_records.len());
        for mx_record in mx_records {
            if let Some(mx) = mx_record.data().as_mx() {
                let preference = mx.preference();
                let exchange = mx.exchange().to_lowercase().to_string();

                if let Some(record) = records.iter_mut().find(|r| r.preference == preference) {
                    record.exchanges.push(exchange);
                } else {
                    records.push(MX {
                        exchanges: vec![exchange],
                        preference,
                    });
                }
            }
        }

        records.sort_unstable_by(|a, b| a.preference.cmp(&b.preference));
        let records = Arc::new(records);

        if let Some(cache) = cache {
            cache.insert(key.into_owned(), records.clone(), mx_lookup.valid_until());
        }

        Ok(records)
    }

    pub async fn ipv4_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        cache: Option<&impl ResolverCache<String, Arc<Vec<Ipv4Addr>>>>,
    ) -> crate::Result<Arc<Vec<Ipv4Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get(key.as_ref())) {
            return Ok(value);
        }

        let ipv4_lookup = self.ipv4_lookup_raw(key.as_ref()).await?;

        if let Some(cache) = cache {
            cache.insert(
                key.into_owned(),
                ipv4_lookup.entry.clone(),
                ipv4_lookup.expires,
            );
        }

        Ok(ipv4_lookup.entry)
    }

    pub async fn ipv4_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<Vec<Ipv4Addr>>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        let ipv4_lookup = self.0.ipv4_lookup(Name::from_str_relaxed(key)?).await?;
        let ips: Arc<Vec<Ipv4Addr>> = ipv4_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| r.data().as_a()?.0.into())
            .collect::<Vec<Ipv4Addr>>()
            .into();

        Ok(DnsEntry {
            entry: ips,
            expires: ipv4_lookup.valid_until(),
        })
    }

    pub async fn ipv6_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        cache: Option<&impl ResolverCache<String, Arc<Vec<Ipv6Addr>>>>,
    ) -> crate::Result<Arc<Vec<Ipv6Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = cache.as_ref().and_then(|c| c.get(key.as_ref())) {
            return Ok(value);
        }

        let ipv6_lookup = self.ipv6_lookup_raw(key.as_ref()).await?;

        if let Some(cache) = cache {
            cache.insert(
                key.into_owned(),
                ipv6_lookup.entry.clone(),
                ipv6_lookup.expires,
            );
        }

        Ok(ipv6_lookup.entry)
    }

    pub async fn ipv6_lookup_raw(&self, key: &str) -> crate::Result<DnsEntry<Arc<Vec<Ipv6Addr>>>> {
        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key);
        }

        let ipv6_lookup = self.0.ipv6_lookup(Name::from_str_relaxed(key)?).await?;
        let ips: Arc<Vec<Ipv6Addr>> = ipv6_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| r.data().as_aaaa()?.0.into())
            .collect::<Vec<Ipv6Addr>>()
            .into();

        Ok(DnsEntry {
            entry: ips,
            expires: ipv6_lookup.valid_until(),
        })
    }

    pub async fn ip_lookup(
        &self,
        key: &str,
        mut strategy: IpLookupStrategy,
        max_results: usize,
        cache_ipv4: Option<&impl ResolverCache<String, Arc<Vec<Ipv4Addr>>>>,
        cache_ipv6: Option<&impl ResolverCache<String, Arc<Vec<Ipv6Addr>>>>,
    ) -> crate::Result<Vec<IpAddr>> {
        loop {
            match strategy {
                IpLookupStrategy::Ipv4Only | IpLookupStrategy::Ipv4thenIpv6 => {
                    match (self.ipv4_lookup(key, cache_ipv4).await, strategy) {
                        (Ok(result), _) => {
                            return Ok(result
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect())
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
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect())
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
        cache: Option<&impl ResolverCache<IpAddr, Arc<Vec<String>>>>,
    ) -> crate::Result<Arc<Vec<String>>> {
        if let Some(value) = cache.as_ref().and_then(|c| c.get(&addr)) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(&addr.to_string());
        }

        let ptr_lookup = self.0.reverse_lookup(addr).await?;
        let ptr: Arc<Vec<String>> = ptr_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| {
                let r = r.data().as_ptr()?;
                if !r.is_empty() {
                    r.to_lowercase().to_string().into()
                } else {
                    None
                }
            })
            .collect::<Vec<String>>()
            .into();

        if let Some(cache) = cache {
            cache.insert(addr, ptr.clone(), ptr_lookup.valid_until());
        }

        Ok(ptr)
    }

    #[cfg(any(test, feature = "test"))]
    pub async fn exists<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        cache_ipv4: Option<&impl ResolverCache<String, Arc<Vec<Ipv4Addr>>>>,
        cache_ipv6: Option<&impl ResolverCache<String, Arc<Vec<Ipv6Addr>>>>,
    ) -> crate::Result<bool> {
        let key = key.into_fqdn().into_owned();
        match self.ipv4_lookup(key.as_str(), cache_ipv4).await {
            Ok(_) => Ok(true),
            Err(Error::DnsRecordNotFound(_)) => {
                match self.ipv6_lookup(key.as_str(), cache_ipv6).await {
                    Ok(_) => Ok(true),
                    Err(Error::DnsRecordNotFound(_)) => Ok(false),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(not(any(test, feature = "test")))]
    pub async fn exists<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        cache_ipv4: Option<&impl ResolverCache<String, Arc<Vec<Ipv4Addr>>>>,
        cache_ipv6: Option<&impl ResolverCache<String, Arc<Vec<Ipv6Addr>>>>,
    ) -> crate::Result<bool> {
        let key = key.into_fqdn();

        if cache_ipv4.is_some_and(|c| c.get(key.as_ref()).is_some())
            || cache_ipv6.is_some_and(|c| c.get(key.as_ref()).is_some())
        {
            return Ok(true);
        }

        match self
            .0
            .lookup_ip(Name::from_str_relaxed(key.as_ref())?)
            .await
        {
            Ok(result) => Ok(result.as_lookup().record_iter().any(|r| {
                matches!(
                    r.data().record_type(),
                    hickory_resolver::proto::rr::RecordType::A
                        | hickory_resolver::proto::rr::RecordType::AAAA
                )
            })),
            Err(err) => match err.kind() {
                ProtoErrorKind::NoRecordsFound { .. } => Ok(false),
                _ => Err(err.into()),
            },
        }
    }
}

impl From<ProtoError> for Error {
    fn from(err: ProtoError) -> Self {
        match err.kind() {
            ProtoErrorKind::NoRecordsFound(response_code) => {
                Error::DnsRecordNotFound(response_code.response_code)
            }
            _ => Error::DnsError(err.to_string()),
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

impl<'x> IntoFqdn<'x> for &String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
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
        Error::InvalidRecordType
    } else if domain.contains("_dns_error.") {
        Error::DnsError("".to_string())
    } else {
        Error::DnsRecordNotFound(hickory_resolver::proto::op::ResponseCode::NXDomain)
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
