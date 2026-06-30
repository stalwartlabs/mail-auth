/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::resolver::{DnsEntry, ToReverseName};
use crate::Instant;
use crate::{Error, MessageAuthenticator};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_PTR: u16 = 12;

const STATUS_NOERROR: u16 = 0;
const STATUS_NXDOMAIN: u16 = 3;

#[derive(Clone, Copy)]
enum DohFormat {
    Json,
    Wire,
}

#[derive(Clone)]
pub struct DohResolver {
    client: reqwest::Client,
    endpoint: Box<str>,
    format: DohFormat,
}

enum DohRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx(u16, Box<str>),
    Txt(Vec<u8>),
    Ptr(Box<str>),
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

    pub fn new_doh_quad9() -> Self {
        Self::new_doh_wire("https://dns.quad9.net/dns-query")
    }

    pub fn new_doh(endpoint: impl Into<Box<str>>) -> Self {
        Self::new_doh_with_format(endpoint, DohFormat::Json)
    }

    pub fn new_doh_wire(endpoint: impl Into<Box<str>>) -> Self {
        Self::new_doh_with_format(endpoint, DohFormat::Wire)
    }

    fn new_doh_with_format(endpoint: impl Into<Box<str>>, format: DohFormat) -> Self {
        MessageAuthenticator(DohResolver {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            format,
        })
    }

    #[cfg(any(test, feature = "test"))]
    pub fn new_system_conf() -> Result<Self, std::convert::Infallible> {
        Ok(Self::new_doh_cloudflare())
    }

    pub(crate) async fn doh_txt(&self, name: &str) -> crate::Result<DnsEntry<Vec<Vec<u8>>>> {
        let (records, expires) = self.doh_query(name, DNS_TYPE_TXT).await?;
        let entry = records
            .into_iter()
            .filter_map(|record| match record {
                DohRecord::Txt(data) => Some(data),
                _ => None,
            })
            .collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_mx(&self, name: &str) -> crate::Result<DnsEntry<Vec<(u16, Box<str>)>>> {
        let (records, expires) = self.doh_query(name, DNS_TYPE_MX).await?;
        let entry = records
            .into_iter()
            .filter_map(|record| match record {
                DohRecord::Mx(preference, exchange) => Some((preference, exchange)),
                _ => None,
            })
            .collect();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ipv4(&self, name: &str) -> crate::Result<DnsEntry<Arc<[Ipv4Addr]>>> {
        let (records, expires) = self.doh_query(name, DNS_TYPE_A).await?;
        let entry: Arc<[Ipv4Addr]> = records
            .into_iter()
            .filter_map(|record| match record {
                DohRecord::A(addr) => Some(addr),
                _ => None,
            })
            .collect::<Vec<Ipv4Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ipv6(&self, name: &str) -> crate::Result<DnsEntry<Arc<[Ipv6Addr]>>> {
        let (records, expires) = self.doh_query(name, DNS_TYPE_AAAA).await?;
        let entry: Arc<[Ipv6Addr]> = records
            .into_iter()
            .filter_map(|record| match record {
                DohRecord::Aaaa(addr) => Some(addr),
                _ => None,
            })
            .collect::<Vec<Ipv6Addr>>()
            .into();
        Ok(DnsEntry { entry, expires })
    }

    pub(crate) async fn doh_ptr(&self, addr: IpAddr) -> crate::Result<DnsEntry<Arc<[Box<str>]>>> {
        let name = match addr {
            IpAddr::V4(_) => format!("{}.in-addr.arpa", addr.to_reverse_name()),
            IpAddr::V6(_) => format!("{}.ip6.arpa", addr.to_reverse_name()),
        };
        let (records, expires) = self.doh_query(&name, DNS_TYPE_PTR).await?;
        let entry: Arc<[Box<str>]> = records
            .into_iter()
            .filter_map(|record| match record {
                DohRecord::Ptr(host) => Some(host),
                _ => None,
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
    ) -> crate::Result<(Vec<DohRecord>, Instant)> {
        match self.0.format {
            DohFormat::Json => self.doh_query_json(name, record_type).await,
            DohFormat::Wire => self.doh_query_wire(name, record_type).await,
        }
    }

    async fn doh_query_json(
        &self,
        name: &str,
        record_type: u16,
    ) -> crate::Result<(Vec<DohRecord>, Instant)> {
        let response = self
            .0
            .client
            .get(self.0.endpoint.as_ref())
            .query(&[("name", name), ("type", &record_type.to_string())])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(resolver_error)?;

        let body: DohResponse = response.json().await.map_err(resolver_error)?;

        match body.status {
            STATUS_NOERROR => {}
            STATUS_NXDOMAIN => return Err(record_not_found()),
            code => {
                return Err(Error::Dns(crate::DnsError::Resolver(format!(
                    "DoH server returned status {code}"
                ))));
            }
        }

        let mut records = Vec::new();
        let mut min_ttl = u32::MAX;
        for answer in body.answer.iter().filter(|a| a.record_type == record_type) {
            if let Some(record) = parse_json_record(record_type, &answer.data) {
                min_ttl = min_ttl.min(answer.ttl);
                records.push(record);
            }
        }

        finalize(records, min_ttl)
    }

    async fn doh_query_wire(
        &self,
        name: &str,
        record_type: u16,
    ) -> crate::Result<(Vec<DohRecord>, Instant)> {
        let mut message = Message::query();
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_str_relaxed::<&str>(name).map_err(resolver_error)?,
            RecordType::from(record_type),
        ));
        let request = message.to_vec().map_err(resolver_error)?;

        let response = self
            .0
            .client
            .post(self.0.endpoint.as_ref())
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(request)
            .send()
            .await
            .map_err(resolver_error)?;
        let body = response.bytes().await.map_err(resolver_error)?;
        let message = Message::from_vec(&body).map_err(resolver_error)?;

        match message.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err(record_not_found()),
            code => {
                return Err(Error::Dns(crate::DnsError::Resolver(format!(
                    "DoH server returned {code}"
                ))));
            }
        }

        let mut records = Vec::new();
        let mut min_ttl = u32::MAX;
        for answer in &message.answers {
            let record = match (record_type, &answer.data) {
                (DNS_TYPE_A, RData::A(addr)) => DohRecord::A(addr.0),
                (DNS_TYPE_AAAA, RData::AAAA(addr)) => DohRecord::Aaaa(addr.0),
                (DNS_TYPE_MX, RData::MX(mx)) => DohRecord::Mx(
                    mx.preference,
                    mx.exchange.to_lowercase().to_string().into_boxed_str(),
                ),
                (DNS_TYPE_TXT, RData::TXT(txt)) => {
                    let mut data = Vec::new();
                    for chunk in txt.txt_data.iter() {
                        data.extend_from_slice(chunk);
                    }
                    DohRecord::Txt(data)
                }
                (DNS_TYPE_PTR, RData::PTR(ptr)) if !ptr.is_empty() => {
                    DohRecord::Ptr(ptr.to_lowercase().to_string().into_boxed_str())
                }
                _ => continue,
            };
            min_ttl = min_ttl.min(answer.ttl);
            records.push(record);
        }

        finalize(records, min_ttl)
    }
}

fn finalize(records: Vec<DohRecord>, min_ttl: u32) -> crate::Result<(Vec<DohRecord>, Instant)> {
    if records.is_empty() {
        return Err(record_not_found());
    }
    let ttl = if min_ttl == u32::MAX { 0 } else { min_ttl };
    Ok((records, Instant::now() + Duration::from_secs(ttl as u64)))
}

fn parse_json_record(record_type: u16, data: &str) -> Option<DohRecord> {
    match record_type {
        DNS_TYPE_A => data.parse().ok().map(DohRecord::A),
        DNS_TYPE_AAAA => data.parse().ok().map(DohRecord::Aaaa),
        DNS_TYPE_MX => {
            let (preference, exchange) = data.split_once(' ')?;
            Some(DohRecord::Mx(
                preference.trim().parse().ok()?,
                exchange.trim().to_lowercase().into_boxed_str(),
            ))
        }
        DNS_TYPE_TXT => Some(DohRecord::Txt(parse_txt_data(data))),
        DNS_TYPE_PTR => {
            let host = data.trim().to_lowercase();
            (!host.is_empty()).then(|| DohRecord::Ptr(host.into_boxed_str()))
        }
        _ => None,
    }
}

fn record_not_found() -> Error {
    Error::Dns(crate::DnsError::RecordNotFound(STATUS_NXDOMAIN))
}

fn resolver_error(err: impl std::fmt::Display) -> Error {
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
            (
                "cloudflare-json",
                MessageAuthenticator::new_doh_cloudflare(),
            ),
            ("google-json", MessageAuthenticator::new_doh_google()),
            ("adguard-json", MessageAuthenticator::new_doh_adguard()),
            ("quad9-wire", MessageAuthenticator::new_doh_quad9()),
            (
                "cloudflare-wire",
                MessageAuthenticator::new_doh_wire("https://cloudflare-dns.com/dns-query"),
            ),
        ]
    }

    async fn check_all(resolver: &MessageAuthenticator) {
        let txt = resolver.doh_txt("cloudflare.com").await.unwrap();
        assert!(
            txt.entry
                .iter()
                .any(|r| r.windows(6).any(|w| w == b"v=spf1")),
            "expected an SPF record, got {:?}",
            txt.entry
        );

        let mx = resolver.doh_mx("gmail.com").await.unwrap();
        assert!(!mx.entry.is_empty(), "expected MX records");

        let ipv4 = resolver.doh_ipv4("one.one.one.one").await.unwrap();
        assert!(ipv4.entry.contains(&Ipv4Addr::new(1, 1, 1, 1)));

        let ipv6 = resolver.doh_ipv6("cloudflare.com").await.unwrap();
        assert!(!ipv6.entry.is_empty(), "expected AAAA records");

        let ptr = resolver
            .doh_ptr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await
            .unwrap();
        assert!(
            ptr.entry.iter().any(|h| h.contains("one.one.one.one")),
            "got {:?}",
            ptr.entry
        );

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
    async fn doh_json() {
        check_all(&MessageAuthenticator::new_doh_cloudflare()).await;
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_wire() {
        check_all(&MessageAuthenticator::new_doh_wire(
            "https://cloudflare-dns.com/dns-query",
        ))
        .await;
    }

    #[tokio::test]
    #[ignore = "performs live DNS-over-HTTPS queries"]
    async fn doh_wire_quad9() {
        check_all(&MessageAuthenticator::new_doh_quad9()).await;
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
