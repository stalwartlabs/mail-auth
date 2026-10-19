/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

/*
    DISCLAIMER:
    This code has been written by an LLM and is inefficient and unidiomatic.
    It was created to demonstrate mail-auth in the browser and is not intended for production use.
    It may contain errors, security vulnerabilities, or other issues that could cause harm if used
    in a real-world application. Use at your own risk.
*/

use mail_auth::dkim::DomainKey;
use mail_auth::dmarc::DmarcRecord;
use mail_auth::dns::TxtRecordParser;
use mail_auth::spf::SpfRecord;
use mail_auth::{DnsCache, DnssecStatus, Mx, Negative, RecordSet, ResolverCache, TxtRecord};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use web_time::Instant;

type Answer<T> = Result<RecordSet<T>, Negative>;

#[derive(Default)]
pub struct OfflineCache {
    txt: Mutex<HashMap<Box<str>, TxtRecord>>,
    mx: Mutex<HashMap<Box<str>, Answer<Mx>>>,
    ipv4: Mutex<HashMap<Box<str>, Answer<Ipv4Addr>>>,
    ipv6: Mutex<HashMap<Box<str>, Answer<Ipv6Addr>>>,
    ptr: Mutex<HashMap<IpAddr, Answer<Box<str>>>>,
    nxdomain: bool,
}

const NXDOMAIN: Negative = Negative { code: 3 };

fn fqdn(name: &str) -> Box<str> {
    let lower = name.to_lowercase();
    if lower.ends_with('.') {
        lower.into()
    } else {
        format!("{lower}.").into()
    }
}

fn record_set<T>(items: Vec<T>) -> Answer<T> {
    Ok(RecordSet {
        records: items.into(),
        dnssec_status: DnssecStatus::Insecure,
    })
}

impl OfflineCache {
    pub fn offline() -> Self {
        OfflineCache {
            nxdomain: true,
            ..Default::default()
        }
    }

    fn missing<T>(&self) -> Option<Answer<T>> {
        self.nxdomain.then_some(Err(NXDOMAIN))
    }

    pub fn add_records(&self, text: &str) -> Result<(), String> {
        for (line_no, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, char::is_whitespace);
            let name = parts.next().unwrap_or_default().trim();
            let rtype = parts.next().unwrap_or_default().trim().to_ascii_uppercase();
            let value = parts.next().unwrap_or_default().trim();
            if name.is_empty() || rtype.is_empty() || value.is_empty() {
                return Err(format!("Line {}: expected `name TYPE value`", line_no + 1));
            }
            self.add_record(line_no + 1, name, &rtype, value)?;
        }
        Ok(())
    }

    fn add_record(
        &self,
        line_no: usize,
        name: &str,
        rtype: &str,
        value: &str,
    ) -> Result<(), String> {
        match rtype {
            "TXT" => {
                let value = unquote_txt(value);
                let value = value.as_ref();
                let txt: TxtRecord = if name.contains("._domainkey.") {
                    DomainKey::parse(value.as_bytes()).into()
                } else if name.to_ascii_lowercase().starts_with("_dmarc.") {
                    DmarcRecord::parse(value.as_bytes()).into()
                } else {
                    SpfRecord::parse(value.as_bytes()).into()
                };
                self.txt.lock().unwrap().insert(fqdn(name), txt);
            }
            "A" => {
                let ips = parse_list::<Ipv4Addr>(value, line_no, "IPv4")?;
                self.ipv4
                    .lock()
                    .unwrap()
                    .insert(fqdn(name), record_set(ips));
            }
            "AAAA" => {
                let ips = parse_list::<Ipv6Addr>(value, line_no, "IPv6")?;
                self.ipv6
                    .lock()
                    .unwrap()
                    .insert(fqdn(name), record_set(ips));
            }
            "MX" => {
                let mut fields = value.split_whitespace();
                let preference = fields
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .ok_or_else(|| format!("Line {line_no}: MX needs `<preference> <host>`"))?;
                let host = fields
                    .next()
                    .ok_or_else(|| format!("Line {line_no}: MX needs an exchange host"))?;
                let mx = Mx {
                    exchanges: Box::new([fqdn(host)]),
                    preference,
                };
                let mut map = self.mx.lock().unwrap();
                let key = fqdn(name);
                let mut existing: Vec<Mx> = map
                    .get(&key)
                    .and_then(|r| r.as_ref().ok())
                    .map(|r| r.records.to_vec())
                    .unwrap_or_default();
                existing.push(mx);
                map.insert(key, record_set(existing));
            }
            "PTR" => {
                let ip = name
                    .parse::<IpAddr>()
                    .map_err(|_| format!("Line {line_no}: PTR name must be an IP address"))?;
                self.ptr
                    .lock()
                    .unwrap()
                    .insert(ip, record_set(vec![fqdn(value)]));
            }
            other => return Err(format!("Line {line_no}: unsupported record type `{other}`")),
        }
        Ok(())
    }
}

fn unquote_txt(value: &str) -> Cow<'_, str> {
    let value = value.trim();
    let grouped = value
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .map_or(value, str::trim);
    if !grouped.starts_with('"') {
        return Cow::Borrowed(value);
    }
    let value = grouped;
    let mut joined = String::with_capacity(value.len());
    let mut in_quotes = false;
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(next) = chars.next() {
                    joined.push(next);
                }
            }
            _ if in_quotes => joined.push(ch),
            _ => {}
        }
    }
    Cow::Owned(joined)
}

fn parse_list<T: std::str::FromStr>(
    value: &str,
    line_no: usize,
    label: &str,
) -> Result<Vec<T>, String> {
    value
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<T>()
                .map_err(|_| format!("Line {line_no}: invalid {label} address `{s}`"))
        })
        .collect()
}

impl ResolverCache<Box<str>, TxtRecord> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.txt
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .or_else(|| self.nxdomain.then(|| TxtRecord::Error(NXDOMAIN.into())))
    }
    fn remove<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.txt.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: TxtRecord, _valid_until: Instant) {
        self.txt.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, Answer<Mx>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<Answer<Mx>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.mx
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .or_else(|| self.missing())
    }
    fn remove<Q>(&self, name: &Q) -> Option<Answer<Mx>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.mx.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: Answer<Mx>, _valid_until: Instant) {
        self.mx.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, Answer<Ipv4Addr>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<Answer<Ipv4Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv4
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .or_else(|| self.missing())
    }
    fn remove<Q>(&self, name: &Q) -> Option<Answer<Ipv4Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv4.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: Answer<Ipv4Addr>, _valid_until: Instant) {
        self.ipv4.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, Answer<Ipv6Addr>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<Answer<Ipv6Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv6
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .or_else(|| self.missing())
    }
    fn remove<Q>(&self, name: &Q) -> Option<Answer<Ipv6Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv6.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: Answer<Ipv6Addr>, _valid_until: Instant) {
        self.ipv6.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<IpAddr, Answer<Box<str>>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<Answer<Box<str>>>
    where
        IpAddr: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ptr
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .or_else(|| self.missing())
    }
    fn remove<Q>(&self, name: &Q) -> Option<Answer<Box<str>>>
    where
        IpAddr: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ptr.lock().unwrap().remove(name)
    }
    fn insert(&self, key: IpAddr, value: Answer<Box<str>>, _valid_until: Instant) {
        self.ptr.lock().unwrap().insert(key, value);
    }
}

impl DnsCache for OfflineCache {
    type Txt = OfflineCache;
    type Mx = OfflineCache;
    type Ipv4 = OfflineCache;
    type Ipv6 = OfflineCache;
    type Ptr = OfflineCache;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(self)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        Some(self)
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(self)
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(self)
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(self)
    }
}
