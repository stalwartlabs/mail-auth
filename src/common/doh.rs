/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::resolver::{DnsEntry, ToReverseName};
use crate::{Error, MessageAuthenticator};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use crate::Instant;
use std::time::Duration;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_PTR: u16 = 12;

const STATUS_NOERROR: u16 = 0;
const STATUS_NXDOMAIN: u16 = 3;

#[derive(Clone)]
pub struct DohResolver {
    client: reqwest::Client,
    endpoint: Box<str>,
}

#[derive(serde::Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(serde::Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

impl MessageAuthenticator {
    pub fn new_doh_cloudflare() -> Self {
        Self::new_doh("https://cloudflare-dns.com/dns-query")
    }

    pub fn new_doh_google() -> Self {
        Self::new_doh("https://dns.google/resolve")
    }

    pub fn new_doh_adguard() -> Self {
        Self::new_doh("https://dns.adguard-dns.com/resolve")
    }

    pub fn new_doh(endpoint: impl Into<Box<str>>) -> Self {
        MessageAuthenticator(DohResolver {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
        })
    }

    #[cfg(any(test, feature = "test"))]
    pub fn new_system_conf() -> Result<Self, std::convert::Infallible> {
        Ok(Self::new_doh_cloudflare())
    }

    pub(crate) async fn doh_txt(&self, name: &str) -> crate::Result<DnsEntry<Vec<Vec<u8>>>> {
        let (answers, expires) = self.doh_query(name, DNS_TYPE_TXT).await?;
        let entry = answers.iter().map(|a| parse_txt_data(&a.data)).collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_mx(
        &self,
        name: &str,
    ) -> crate::Result<DnsEntry<Vec<(u16, Box<str>)>>> {
        let (answers, expires) = self.doh_query(name, DNS_TYPE_MX).await?;
        let entry = answers
            .iter()
            .filter_map(|a| {
                let (preference, exchange) = a.data.split_once(' ')?;
                Some((
                    preference.trim().parse().ok()?,
                    exchange
                        .trim()
                        .trim_end_matches('.')
                        .to_lowercase()
                        .into_boxed_str(),
                ))
            })
            .collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ipv4(
        &self,
        name: &str,
    ) -> crate::Result<DnsEntry<Arc<[Ipv4Addr]>>> {
        let (answers, expires) = self.doh_query(name, DNS_TYPE_A).await?;
        let entry: Arc<[Ipv4Addr]> = answers
            .iter()
            .filter_map(|a| a.data.parse().ok())
            .collect::<Vec<Ipv4Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ipv6(
        &self,
        name: &str,
    ) -> crate::Result<DnsEntry<Arc<[Ipv6Addr]>>> {
        let (answers, expires) = self.doh_query(name, DNS_TYPE_AAAA).await?;
        let entry: Arc<[Ipv6Addr]> = answers
            .iter()
            .filter_map(|a| a.data.parse().ok())
            .collect::<Vec<Ipv6Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ptr(
        &self,
        addr: IpAddr,
    ) -> crate::Result<DnsEntry<Arc<[Box<str>]>>> {
        let name = match addr {
            IpAddr::V4(_) => format!("{}.in-addr.arpa", addr.to_reverse_name()),
            IpAddr::V6(_) => format!("{}.ip6.arpa", addr.to_reverse_name()),
        };
        let (answers, expires) = self.doh_query(&name, DNS_TYPE_PTR).await?;
        let entry: Arc<[Box<str>]> = answers
            .iter()
            .filter_map(|a| {
                let host = a.data.trim_end_matches('.').to_lowercase();
                if host.is_empty() {
                    None
                } else {
                    Some(host.into_boxed_str())
                }
            })
            .collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_exists(&self, name: &str) -> crate::Result<bool> {
        match self.doh_query(name, DNS_TYPE_A).await {
            Ok(_) => Ok(true),
            Err(Error::Dns(crate::DnsError::RecordNotFound(_))) => {
                match self.doh_query(name, DNS_TYPE_AAAA).await {
                    Ok(_) => Ok(true),
                    Err(Error::Dns(crate::DnsError::RecordNotFound(_))) => Ok(false),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn doh_query(
        &self,
        name: &str,
        record_type: u16,
    ) -> crate::Result<(Vec<DohAnswer>, Instant)> {
        let response = self
            .0
            .client
            .get(self.0.endpoint.as_ref())
            .query(&[("name", name), ("type", &record_type.to_string())])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(transport_error)?;

        let body: DohResponse = response.json().await.map_err(transport_error)?;

        match body.status {
            STATUS_NOERROR => {}
            STATUS_NXDOMAIN => return Err(record_not_found()),
            code => {
                return Err(Error::Dns(crate::DnsError::Resolver(format!(
                    "DoH server returned status {code}"
                ))));
            }
        }

        let answers: Vec<DohAnswer> = body
            .answer
            .into_iter()
            .filter(|a| a.record_type == record_type)
            .collect();
        if answers.is_empty() {
            return Err(record_not_found());
        }

        let ttl = answers.iter().map(|a| a.ttl).min().unwrap_or(0);
        Ok((answers, Instant::now() + Duration::from_secs(ttl as u64)))
    }
}

fn record_not_found() -> Error {
    Error::Dns(crate::DnsError::RecordNotFound(STATUS_NXDOMAIN))
}

fn transport_error(err: reqwest::Error) -> Error {
    Error::Dns(crate::DnsError::Resolver(err.to_string()))
}

fn parse_txt_data(data: &str) -> Vec<u8> {
    if !data.contains('"') {
        return data.as_bytes().to_vec();
    }

    let mut out = Vec::with_capacity(data.len());
    let mut in_quotes = false;
    let mut bytes = data.bytes().peekable();
    while let Some(byte) = bytes.next() {
        match byte {
            b'"' => in_quotes = !in_quotes,
            b'\\' if in_quotes => match bytes.next() {
                Some(first) if first.is_ascii_digit() => {
                    let mut code = u16::from(first - b'0');
                    for digit in std::iter::from_fn(|| bytes.next_if(u8::is_ascii_digit)).take(2) {
                        code = code * 10 + u16::from(digit - b'0');
                    }
                    out.push(code as u8);
                }
                Some(literal) => out.push(literal),
                None => {}
            },
            other if in_quotes => out.push(other),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod test {
    use crate::MessageAuthenticator;
    use std::net::{IpAddr, Ipv4Addr};

    fn providers() -> Vec<(&'static str, MessageAuthenticator)> {
        vec![
            ("cloudflare", MessageAuthenticator::new_doh_cloudflare()),
            ("google", MessageAuthenticator::new_doh_google()),
            ("adguard", MessageAuthenticator::new_doh_adguard()),
        ]
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_txt() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        let result = resolver.doh_txt("cloudflare.com").await.unwrap();
        assert!(
            result
                .entry
                .iter()
                .any(|r| r.windows(6).any(|w| w == b"v=spf1")),
            "expected an SPF record, got {:?}",
            result.entry
        );
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_mx() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        let result = resolver.doh_mx("gmail.com").await.unwrap();
        assert!(!result.entry.is_empty(), "expected MX records");
        assert!(result.entry.iter().all(|(pref, host)| *pref > 0 || !host.is_empty()));
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_ipv4() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        let result = resolver.doh_ipv4("one.one.one.one").await.unwrap();
        assert!(result.entry.contains(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_ipv6() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        let result = resolver.doh_ipv6("cloudflare.com").await.unwrap();
        assert!(!result.entry.is_empty(), "expected AAAA records");
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_ptr() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        let result = resolver
            .doh_ptr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await
            .unwrap();
        assert!(
            result.entry.iter().any(|h| h.as_ref() == "one.one.one.one"),
            "got {:?}",
            result.entry
        );
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_exists() {
        let resolver = MessageAuthenticator::new_doh_cloudflare();
        assert!(resolver.doh_exists("cloudflare.com").await.unwrap());
        assert!(
            !resolver
                .doh_exists("nonexistent-label-mailauth-test.cloudflare.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_all_providers() {
        for (name, resolver) in providers() {
            let result = resolver
                .doh_txt("cloudflare.com")
                .await
                .unwrap_or_else(|err| panic!("{name} failed: {err:?}"));
            assert!(!result.entry.is_empty(), "{name} returned no TXT records");
        }
    }
}
