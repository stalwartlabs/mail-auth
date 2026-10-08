/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DNS-over-HTTPS backend (RFC 8484), enabled by the `dns-doh` feature.
//!
//! Queries are sent with `reqwest`, either as JSON API requests
//! (`application/dns-json`) or as DNS wire format messages
//! (`application/dns-message`, RFC 8484 Section 4.1).

use super::{DnsEntry, QueryError, QueryResult, ToReverseName};
use crate::{Error, Instant, MessageAuthenticator, authenticator::DEFAULT_MAX_NEGATIVE_TTL};
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
const DNS_TYPE_SOA: u16 = 6;

const STATUS_NOERROR: u16 = 0;
const STATUS_NXDOMAIN: u16 = 3;

#[derive(Clone, Copy)]
enum DohFormat {
    Json,
    Wire,
}

/// A DNS-over-HTTPS client (RFC 8484), wrapped by
/// [`MessageAuthenticator`] when the `dns-doh` feature is enabled.
///
/// Built through the `MessageAuthenticator::new_doh*` constructors. Cloning
/// shares the underlying HTTP connection pool. The resolver does not validate
/// DNSSEC.
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
    #[serde(rename = "Authority", default)]
    authority: Vec<DohAnswer>,
}

#[derive(serde::Deserialize)]
#[cfg_attr(test, derive(Debug, Clone))]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

impl MessageAuthenticator {
    /// Creates an authenticator that queries Cloudflare's DNS-over-HTTPS JSON
    /// API (`https://cloudflare-dns.com/dns-query`).
    pub fn new_doh_cloudflare() -> Self {
        Self::new_doh("https://cloudflare-dns.com/dns-query")
    }

    /// Creates an authenticator that queries Google's DNS-over-HTTPS JSON API
    /// (`https://dns.google/resolve`).
    pub fn new_doh_google() -> Self {
        Self::new_doh("https://dns.google/resolve")
    }

    /// Creates an authenticator that queries AdGuard's DNS-over-HTTPS JSON API
    /// (`https://dns.adguard-dns.com/resolve`).
    pub fn new_doh_adguard() -> Self {
        Self::new_doh("https://dns.adguard-dns.com/resolve")
    }

    /// Creates an authenticator that queries Quad9 over DNS-over-HTTPS in wire
    /// format (`https://dns.quad9.net/dns-query`). Quad9 does not offer a JSON
    /// API.
    pub fn new_doh_quad9() -> Self {
        Self::new_doh_wire("https://dns.quad9.net/dns-query")
    }

    /// Creates an authenticator that sends JSON API queries
    /// (`GET <endpoint>?name=<name>&type=<type>` with
    /// `Accept: application/dns-json`) to `endpoint`.
    pub fn new_doh(endpoint: impl Into<Box<str>>) -> Self {
        Self::new_doh_with_format(endpoint, DohFormat::Json)
    }

    /// Creates an authenticator that sends DNS wire format queries (RFC 8484
    /// Section 4.1, `POST` with `Content-Type: application/dns-message`) to
    /// `endpoint`.
    pub fn new_doh_wire(endpoint: impl Into<Box<str>>) -> Self {
        Self::new_doh_with_format(endpoint, DohFormat::Wire)
    }

    fn new_doh_with_format(endpoint: impl Into<Box<str>>, format: DohFormat) -> Self {
        MessageAuthenticator {
            resolver: DohResolver {
                client: reqwest::Client::new(),
                endpoint: endpoint.into(),
                format,
            },
            max_negative_ttl: DEFAULT_MAX_NEGATIVE_TTL,
        }
    }

    /// Test support: returns [`new_doh_cloudflare`](Self::new_doh_cloudflare)
    /// so that test code written for the hickory backend compiles unchanged.
    ///
    /// # Errors
    ///
    /// Never fails.
    #[cfg(any(test, feature = "test"))]
    pub fn new_system_conf() -> Result<Self, std::convert::Infallible> {
        Ok(Self::new_doh_cloudflare())
    }

    pub(crate) async fn query_txt(&self, name: &str) -> QueryResult<Vec<Vec<u8>>> {
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

    pub(crate) async fn query_mx(&self, name: &str) -> QueryResult<Vec<(u16, Box<str>)>> {
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

    pub(crate) async fn query_ipv4(&self, name: &str) -> QueryResult<Arc<[Ipv4Addr]>> {
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

    pub(crate) async fn query_ipv6(&self, name: &str) -> QueryResult<Arc<[Ipv6Addr]>> {
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

    pub(crate) async fn query_ptr(&self, addr: IpAddr) -> QueryResult<Arc<[Box<str>]>> {
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

    pub(crate) async fn query_exists(&self, name: &str) -> crate::Result<bool> {
        match self.doh_query(name, DNS_TYPE_A).await {
            Ok(_) => Ok(true),
            Err(QueryError::NotFound { .. }) => match self.doh_query(name, DNS_TYPE_AAAA).await {
                Ok(_) => Ok(true),
                Err(QueryError::NotFound { .. }) => Ok(false),
                Err(QueryError::Other(err)) => Err(err),
            },
            Err(QueryError::Other(err)) => Err(err),
        }
    }

    async fn doh_query(
        &self,
        name: &str,
        record_type: u16,
    ) -> Result<(Vec<DohRecord>, Instant), QueryError> {
        match self.resolver.format {
            DohFormat::Json => self.doh_query_json(name, record_type).await,
            DohFormat::Wire => self.doh_query_wire(name, record_type).await,
        }
    }

    async fn doh_query_json(
        &self,
        name: &str,
        record_type: u16,
    ) -> Result<(Vec<DohRecord>, Instant), QueryError> {
        let response = self
            .resolver
            .client
            .get(self.resolver.endpoint.as_ref())
            .query(&[("name", name), ("type", &record_type.to_string())])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(resolver_error)?;

        let body: DohResponse = response.json().await.map_err(resolver_error)?;

        match body.status {
            STATUS_NOERROR => {}
            STATUS_NXDOMAIN => {
                return Err(record_not_found(
                    STATUS_NXDOMAIN,
                    json_negative_ttl(&body.authority),
                ));
            }
            code => {
                return Err(QueryError::Other(Error::Dns(crate::DnsError::Resolver(
                    format!("DoH server returned status {code}"),
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

        finalize(records, min_ttl, || json_negative_ttl(&body.authority))
    }

    async fn doh_query_wire(
        &self,
        name: &str,
        record_type: u16,
    ) -> Result<(Vec<DohRecord>, Instant), QueryError> {
        let mut message = Message::query();
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_str_relaxed::<&str>(name).map_err(|_| Error::Parse)?,
            RecordType::from(record_type),
        ));
        let request = message.to_vec().map_err(resolver_error)?;

        let response = self
            .resolver
            .client
            .post(self.resolver.endpoint.as_ref())
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
            ResponseCode::NXDomain => {
                return Err(record_not_found(
                    STATUS_NXDOMAIN,
                    wire_negative_ttl(&message),
                ));
            }
            code => {
                return Err(QueryError::Other(Error::Dns(crate::DnsError::Resolver(
                    format!("DoH server returned {code}"),
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
                    mx.exchange.to_lowercase().to_ascii().into_boxed_str(),
                ),
                (DNS_TYPE_TXT, RData::TXT(txt)) => {
                    let mut data = Vec::new();
                    for chunk in txt.txt_data.iter() {
                        data.extend_from_slice(chunk);
                    }
                    DohRecord::Txt(data)
                }
                (DNS_TYPE_PTR, RData::PTR(ptr)) if !ptr.is_empty() => {
                    DohRecord::Ptr(ptr.to_lowercase().to_ascii().into_boxed_str())
                }
                _ => continue,
            };
            min_ttl = min_ttl.min(answer.ttl);
            records.push(record);
        }

        finalize(records, min_ttl, || wire_negative_ttl(&message))
    }
}

fn finalize(
    records: Vec<DohRecord>,
    min_ttl: u32,
    negative_ttl: impl FnOnce() -> Option<u32>,
) -> Result<(Vec<DohRecord>, Instant), QueryError> {
    if records.is_empty() {
        return Err(record_not_found(STATUS_NOERROR, negative_ttl()));
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

fn record_not_found(code: u16, negative_ttl: Option<u32>) -> QueryError {
    QueryError::NotFound { code, negative_ttl }
}

fn json_negative_ttl(authority: &[DohAnswer]) -> Option<u32> {
    let soa = authority
        .iter()
        .find(|record| record.record_type == DNS_TYPE_SOA)?;
    Some(
        soa.data
            .split_ascii_whitespace()
            .next_back()
            .and_then(|minimum| minimum.parse::<u32>().ok())
            .map_or(soa.ttl, |minimum| soa.ttl.min(minimum)),
    )
}

fn wire_negative_ttl(message: &Message) -> Option<u32> {
    message
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
}

fn resolver_error(err: impl std::fmt::Display) -> QueryError {
    QueryError::Other(Error::Dns(crate::DnsError::Resolver(err.to_string())))
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
    use super::{
        DNS_TYPE_SOA, DohAnswer, DohRecord, QueryError, STATUS_NOERROR, finalize,
        json_negative_ttl, wire_negative_ttl,
    };
    use crate::MessageAuthenticator;
    use hickory_proto::{
        op::Message,
        rr::{Name, RData, Record, rdata::SOA},
    };
    use std::net::{IpAddr, Ipv4Addr};

    const DNS_TYPE_NS: u16 = 2;

    fn json_record(record_type: u16, ttl: u32, data: &str) -> DohAnswer {
        DohAnswer {
            record_type,
            ttl,
            data: data.to_string(),
        }
    }

    fn wire_message(authorities: impl IntoIterator<Item = Record>) -> Message {
        let mut message = Message::query();
        message.authorities.extend(authorities);
        message
    }

    fn soa_record(ttl: u32, minimum: u32) -> Record {
        let name = Name::from_ascii("example.org.").expect("valid name");
        Record::from_rdata(
            name.clone(),
            ttl,
            RData::SOA(SOA::new(
                name.clone(),
                name,
                1,
                7200,
                3600,
                1209600,
                minimum,
            )),
        )
    }

    // The JSON negative TTL is min(SOA TTL, SOA MINIMUM), or the TTL when MINIMUM is unreadable.
    #[test]
    fn json_negative_ttl_from_soa() {
        let soa = "ns.example.org. host.example.org. 1 7200 3600 1209600 300";
        let ns = json_record(DNS_TYPE_NS, 1800, "ns.example.org.");

        for (authority, expected) in [
            (vec![json_record(DNS_TYPE_SOA, 1800, soa)], Some(300)),
            (vec![json_record(DNS_TYPE_SOA, 100, soa)], Some(100)),
            (
                vec![ns.clone(), json_record(DNS_TYPE_SOA, 1800, soa)],
                Some(300),
            ),
            (
                vec![json_record(
                    DNS_TYPE_SOA,
                    1800,
                    "ns.example.org. host.example.org. 1 7200 3600 1209600 x",
                )],
                Some(1800),
            ),
            (vec![json_record(DNS_TYPE_SOA, 1800, "")], Some(1800)),
            (vec![ns], None),
            (vec![], None),
        ] {
            assert_eq!(json_negative_ttl(&authority), expected, "{authority:?}");
        }
    }

    // The wire negative TTL is min(SOA TTL, SOA MINIMUM) from the authority section.
    #[test]
    fn wire_negative_ttl_from_soa() {
        assert_eq!(
            wire_negative_ttl(&wire_message([soa_record(1800, 300)])),
            Some(300)
        );
        assert_eq!(
            wire_negative_ttl(&wire_message([soa_record(100, 300)])),
            Some(100)
        );
        assert_eq!(wire_negative_ttl(&wire_message([])), None);
    }

    // An empty NOERROR answer is NODATA, not NXDOMAIN, and keeps its negative TTL.
    #[test]
    fn empty_answer_is_nodata() {
        assert!(matches!(
            finalize(vec![], u32::MAX, || Some(300)),
            Err(QueryError::NotFound {
                code: STATUS_NOERROR,
                negative_ttl: Some(300)
            })
        ));
        assert!(matches!(
            finalize(vec![DohRecord::A(Ipv4Addr::LOCALHOST)], 60, || None),
            Ok((records, _)) if records.len() == 1
        ));
    }

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
        let txt = resolver.query_txt("cloudflare.com").await.unwrap();
        assert!(
            txt.entry
                .iter()
                .any(|r| r.windows(6).any(|w| w == b"v=spf1")),
            "expected an SPF record, got {:?}",
            txt.entry
        );

        let mx = resolver.query_mx("gmail.com").await.unwrap();
        assert!(!mx.entry.is_empty(), "expected MX records");

        let ipv4 = resolver.query_ipv4("one.one.one.one").await.unwrap();
        assert!(ipv4.entry.contains(&Ipv4Addr::new(1, 1, 1, 1)));

        let ipv6 = resolver.query_ipv6("cloudflare.com").await.unwrap();
        assert!(!ipv6.entry.is_empty(), "expected AAAA records");

        let ptr = resolver
            .query_ptr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await
            .unwrap();
        assert!(
            ptr.entry.iter().any(|h| h.contains("one.one.one.one")),
            "got {:?}",
            ptr.entry
        );

        assert!(resolver.query_exists("cloudflare.com").await.unwrap());
        assert!(
            !resolver
                .query_exists("nonexistent-label-mailauth-test.cloudflare.com")
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
                .query_txt("cloudflare.com")
                .await
                .unwrap_or_else(|err| panic!("{name} failed: {err:?}"));
            assert!(!result.entry.is_empty(), "{name} returned no TXT records");
        }
    }
}
