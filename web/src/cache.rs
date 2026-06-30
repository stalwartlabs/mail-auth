/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::common::parse::TxtRecordParser;
use mail_auth::common::verify::DomainKey;
use mail_auth::dmarc::Dmarc;
use mail_auth::spf::Spf;
use mail_auth::{DnssecStatus, MX, RecordSet, ResolverCache, Txt};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use web_time::Instant;

#[derive(Default)]
pub struct OfflineCache {
    txt: Mutex<HashMap<Box<str>, Txt>>,
    mx: Mutex<HashMap<Box<str>, RecordSet<MX>>>,
    ipv4: Mutex<HashMap<Box<str>, RecordSet<Ipv4Addr>>>,
    ipv6: Mutex<HashMap<Box<str>, RecordSet<Ipv6Addr>>>,
    ptr: Mutex<HashMap<IpAddr, RecordSet<Box<str>>>>,
}

fn fqdn(name: &str) -> Box<str> {
    let lower = name.to_lowercase();
    if lower.ends_with('.') {
        lower.into()
    } else {
        format!("{lower}.").into()
    }
}

fn record_set<T>(items: Vec<T>) -> RecordSet<T> {
    RecordSet {
        rrset: items.into(),
        dnssec_status: DnssecStatus::Insecure,
    }
}

impl OfflineCache {
    pub fn from_records(text: &str) -> Result<Self, String> {
        let cache = OfflineCache::default();
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
            cache.add_record(line_no + 1, name, &rtype, value)?;
        }
        Ok(cache)
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
                let value = value.trim().trim_matches('"');
                let txt: Txt = if name.contains("._domainkey.") {
                    DomainKey::parse(value.as_bytes()).into()
                } else if name.to_ascii_lowercase().starts_with("_dmarc.") {
                    Dmarc::parse(value.as_bytes()).into()
                } else {
                    Spf::parse(value.as_bytes()).into()
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
                let mx = MX {
                    exchanges: Box::new([fqdn(host)]),
                    preference,
                };
                let mut map = self.mx.lock().unwrap();
                let key = fqdn(name);
                let mut existing: Vec<MX> =
                    map.get(&key).map(|r| r.rrset.to_vec()).unwrap_or_default();
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

impl ResolverCache<Box<str>, Txt> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.txt.lock().unwrap().get(name).cloned()
    }
    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.txt.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: Txt, _valid_until: Instant) {
        self.txt.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, RecordSet<MX>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<RecordSet<MX>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.mx.lock().unwrap().get(name).cloned()
    }
    fn remove<Q>(&self, name: &Q) -> Option<RecordSet<MX>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.mx.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: RecordSet<MX>, _valid_until: Instant) {
        self.mx.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<RecordSet<Ipv4Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv4.lock().unwrap().get(name).cloned()
    }
    fn remove<Q>(&self, name: &Q) -> Option<RecordSet<Ipv4Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv4.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: RecordSet<Ipv4Addr>, _valid_until: Instant) {
        self.ipv4.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<RecordSet<Ipv6Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv6.lock().unwrap().get(name).cloned()
    }
    fn remove<Q>(&self, name: &Q) -> Option<RecordSet<Ipv6Addr>>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ipv6.lock().unwrap().remove(name)
    }
    fn insert(&self, key: Box<str>, value: RecordSet<Ipv6Addr>, _valid_until: Instant) {
        self.ipv6.lock().unwrap().insert(key, value);
    }
}

impl ResolverCache<IpAddr, RecordSet<Box<str>>> for OfflineCache {
    fn get<Q>(&self, name: &Q) -> Option<RecordSet<Box<str>>>
    where
        IpAddr: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ptr.lock().unwrap().get(name).cloned()
    }
    fn remove<Q>(&self, name: &Q) -> Option<RecordSet<Box<str>>>
    where
        IpAddr: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.ptr.lock().unwrap().remove(name)
    }
    fn insert(&self, key: IpAddr, value: RecordSet<Box<str>>, _valid_until: Instant) {
        self.ptr.lock().unwrap().insert(key, value);
    }
}
