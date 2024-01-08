/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use crate::{Error, Resolver, SpfOutput, SpfResult};

use super::{Macro, Mechanism, Qualifier, Spf, Variables};

impl Resolver {
    /// Verifies the SPF EHLO identity
    pub async fn verify_spf_helo(
        &self,
        ip: IpAddr,
        helo_domain: &str,
        host_domain: &str,
    ) -> SpfOutput {
        if helo_domain.has_labels() {
            self.check_host(
                ip,
                helo_domain,
                helo_domain,
                host_domain,
                &format!("postmaster@{helo_domain}"),
            )
            .await
        } else {
            SpfOutput::new(helo_domain.to_string()).with_result(SpfResult::None)
        }
    }

    /// Verifies the SPF MAIL FROM identity
    pub async fn verify_spf_sender(
        &self,
        ip: IpAddr,
        helo_domain: &str,
        host_domain: &str,
        sender: &str,
    ) -> SpfOutput {
        self.check_host(
            ip,
            sender.rsplit_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            host_domain,
            sender,
        )
        .await
    }

    /// Verifies both the SPF EHLO and MAIL FROM identities
    pub async fn verify_spf(
        &self,
        ip: IpAddr,
        helo_domain: &str,
        host_domain: &str,
        mail_from: &str,
    ) -> SpfOutput {
        // Verify HELO identity
        let output = self.verify_spf_helo(ip, helo_domain, host_domain).await;
        if matches!(output.result(), SpfResult::Pass) {
            // Verify MAIL FROM identity
            self.verify_spf_sender(ip, helo_domain, host_domain, mail_from)
                .await
        } else {
            output
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    #[allow(clippy::iter_skip_zero)]
    pub async fn check_host(
        &self,
        ip: IpAddr,
        domain: &str,
        helo_domain: &str,
        host_domain: &str,
        sender: &str,
    ) -> SpfOutput {
        let output = SpfOutput::new(domain.to_string());
        if domain.is_empty() || domain.len() > 63 || !domain.has_labels() {
            return output.with_result(SpfResult::None);
        }
        let mut vars = Variables::new();
        let mut has_p_var = false;
        vars.set_ip(&ip);
        if !sender.is_empty() {
            vars.set_sender(sender.as_bytes());
        } else {
            vars.set_sender(format!("postmaster@{domain}").into_bytes());
        }
        vars.set_domain(domain.as_bytes());
        vars.set_host_domain(host_domain.as_bytes());
        vars.set_helo_domain(helo_domain.as_bytes());

        let mut lookup_limit = LookupLimit::new();
        let mut spf_record = match self.txt_lookup::<Spf>(domain).await {
            Ok(spf_record) => spf_record,
            Err(err) => return output.with_result(err.into()),
        };

        let mut domain = domain.to_string();
        let mut include_stack = Vec::new();

        let mut result = None;
        let mut directives = spf_record.directives.iter().enumerate().skip(0);

        loop {
            while let Some((pos, directive)) = directives.next() {
                if !has_p_var && directive.mechanism.needs_ptr() {
                    if !lookup_limit.can_lookup() {
                        return output
                            .with_result(SpfResult::PermError)
                            .with_report(&spf_record);
                    }
                    if let Some(ptr) = self
                        .ptr_lookup(ip)
                        .await
                        .ok()
                        .and_then(|ptrs| ptrs.first().map(|ptr| ptr.as_bytes().to_vec()))
                    {
                        vars.set_validated_domain(ptr);
                    }
                    has_p_var = true;
                }

                let matches = match &directive.mechanism {
                    Mechanism::All => true,
                    Mechanism::Ip4 { addr, mask } => ip.matches_ipv4_mask(addr, *mask),
                    Mechanism::Ip6 { addr, mask } => ip.matches_ipv6_mask(addr, *mask),
                    Mechanism::A {
                        macro_string,
                        ip4_mask,
                        ip6_mask,
                    } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }
                        match self
                            .ip_matches(
                                macro_string.eval(&vars, &domain, true).as_ref(),
                                ip,
                                *ip4_mask,
                                *ip6_mask,
                            )
                            .await
                        {
                            Ok(true) => true,
                            Ok(false) | Err(Error::DnsRecordNotFound(_)) => false,
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                    }
                    Mechanism::Mx {
                        macro_string,
                        ip4_mask,
                        ip6_mask,
                    } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let mut matches = false;
                        match self
                            .mx_lookup(macro_string.eval(&vars, &domain, true).as_ref())
                            .await
                        {
                            Ok(records) => {
                                for exchange in records.iter().flat_map(|mx| mx.exchanges.iter()) {
                                    if !lookup_limit.can_lookup() {
                                        return output
                                            .with_result(SpfResult::PermError)
                                            .with_report(&spf_record);
                                    }

                                    match self.ip_matches(exchange, ip, *ip4_mask, *ip6_mask).await
                                    {
                                        Ok(true) => {
                                            matches = true;
                                            break;
                                        }
                                        Ok(false) | Err(Error::DnsRecordNotFound(_)) => (),
                                        Err(_) => {
                                            return output
                                                .with_result(SpfResult::TempError)
                                                .with_report(&spf_record);
                                        }
                                    }
                                }
                            }
                            Err(Error::DnsRecordNotFound(_)) => (),
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                        matches
                    }
                    Mechanism::Include { macro_string } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_name = macro_string.eval(&vars, &domain, true);
                        match self.txt_lookup::<Spf>(target_name.as_ref()).await {
                            Ok(included_spf) => {
                                let new_domain = target_name.to_string();
                                include_stack.push((
                                    std::mem::replace(&mut spf_record, included_spf),
                                    pos,
                                    domain,
                                ));
                                directives = spf_record.directives.iter().enumerate().skip(0);
                                domain = new_domain;
                                vars.set_domain(domain.as_bytes().to_vec());
                                continue;
                            }
                            Err(
                                Error::DnsRecordNotFound(_)
                                | Error::InvalidRecordType
                                | Error::ParseError,
                            ) => {
                                return output
                                    .with_result(SpfResult::PermError)
                                    .with_report(&spf_record)
                            }
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record)
                            }
                        }
                    }
                    Mechanism::Ptr { macro_string } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_addr = macro_string.eval(&vars, &domain, true).to_lowercase();
                        let target_sub_addr = format!(".{target_addr}");
                        let mut matches = false;

                        if let Ok(records) = self.ptr_lookup(ip).await {
                            for record in records.iter() {
                                if lookup_limit.can_lookup() {
                                    if let Ok(true) =
                                        self.ip_matches(record, ip, u32::MAX, u128::MAX).await
                                    {
                                        matches = record == &target_addr
                                            || record.ends_with(&target_sub_addr);
                                        if matches {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        matches
                    }
                    Mechanism::Exists { macro_string } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        if let Ok(result) = self
                            .exists(macro_string.eval(&vars, &domain, true).as_ref())
                            .await
                        {
                            result
                        } else {
                            return output
                                .with_result(SpfResult::TempError)
                                .with_report(&spf_record);
                        }
                    }
                };

                if matches {
                    result = Some((&directive.qualifier).into());
                    break;
                }
            }

            if let Some((prev_record, prev_pos, prev_domain)) = include_stack.pop() {
                spf_record = prev_record;
                directives = spf_record.directives.iter().enumerate().skip(prev_pos);
                let (_, directive) = directives.next().unwrap();

                if matches!(result, Some(SpfResult::Pass)) {
                    result = Some((&directive.qualifier).into());
                    break;
                } else {
                    vars.set_domain(prev_domain.as_bytes().to_vec());
                    domain = prev_domain;
                    result = None;
                }
            } else {
                // Follow redirect
                if let (Some(macro_string), None) = (&spf_record.redirect, &result) {
                    if !lookup_limit.can_lookup() {
                        return output
                            .with_result(SpfResult::PermError)
                            .with_report(&spf_record);
                    }

                    let target_name = macro_string.eval(&vars, &domain, true);
                    match self.txt_lookup::<Spf>(target_name.as_ref()).await {
                        Ok(redirect_spf) => {
                            let new_domain = target_name.to_string();
                            spf_record = redirect_spf;
                            directives = spf_record.directives.iter().enumerate().skip(0);
                            domain = new_domain;
                            vars.set_domain(domain.as_bytes().to_vec());
                            continue;
                        }
                        Err(
                            Error::DnsRecordNotFound(_)
                            | Error::InvalidRecordType
                            | Error::ParseError,
                        ) => {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record)
                        }
                        Err(_) => {
                            return output
                                .with_result(SpfResult::TempError)
                                .with_report(&spf_record)
                        }
                    }
                }

                break;
            }
        }

        // Evaluate explain
        if let (Some(macro_string), Some(SpfResult::Fail { .. })) = (&spf_record.exp, &result) {
            if let Ok(macro_string) = self
                .txt_lookup::<Macro>(macro_string.eval(&vars, &domain, true).to_string())
                .await
            {
                return output
                    .with_result(SpfResult::Fail)
                    .with_explanation(macro_string.eval(&vars, &domain, false).to_string())
                    .with_report(&spf_record);
            }
        }

        output
            .with_result(result.unwrap_or(SpfResult::Neutral))
            .with_report(&spf_record)
    }

    async fn ip_matches(
        &self,
        target_name: &str,
        ip: IpAddr,
        ip4_mask: u32,
        ip6_mask: u128,
    ) -> crate::Result<bool> {
        Ok(match ip {
            IpAddr::V4(ip) => self
                .ipv4_lookup(target_name)
                .await?
                .iter()
                .any(|addr| ip.matches_ipv4_mask(addr, ip4_mask)),
            IpAddr::V6(ip) => self
                .ipv6_lookup(target_name)
                .await?
                .iter()
                .any(|addr| ip.matches_ipv6_mask(addr, ip6_mask)),
        })
    }
}

trait IpMask {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool;
    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool;
}

impl IpMask for IpAddr {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool {
        u32::from_be_bytes(match &self {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    ip.octets()
                } else {
                    return false;
                }
            }
        }) & mask
            == u32::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(match &self {
            IpAddr::V6(ip) => ip.octets(),
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        }) & mask
            == u128::from_be_bytes(addr.octets()) & mask
    }
}

impl IpMask for Ipv6Addr {
    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(self.octets()) & mask == u128::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv4_mask(&self, _addr: &Ipv4Addr, _mask: u32) -> bool {
        unimplemented!()
    }
}

impl IpMask for Ipv4Addr {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool {
        u32::from_be_bytes(self.octets()) & mask == u32::from_be_bytes(addr.octets()) & mask
    }

    fn matches_ipv6_mask(&self, _addr: &Ipv6Addr, _mask: u128) -> bool {
        unimplemented!()
    }
}

impl From<&Qualifier> for SpfResult {
    fn from(q: &Qualifier) -> Self {
        match q {
            Qualifier::Pass => SpfResult::Pass,
            Qualifier::Fail => SpfResult::Fail,
            Qualifier::SoftFail => SpfResult::SoftFail,
            Qualifier::Neutral => SpfResult::Neutral,
        }
    }
}

impl From<Error> for SpfResult {
    fn from(err: Error) -> Self {
        match err {
            Error::DnsRecordNotFound(_) | Error::InvalidRecordType => SpfResult::None,
            Error::ParseError => SpfResult::PermError,
            _ => SpfResult::TempError,
        }
    }
}

struct LookupLimit {
    num_lookups: u32,
    timer: Instant,
}

impl LookupLimit {
    pub fn new() -> Self {
        LookupLimit {
            num_lookups: 1,
            timer: Instant::now(),
        }
    }

    #[inline(always)]
    fn can_lookup(&mut self) -> bool {
        if self.num_lookups < 10 && self.timer.elapsed().as_secs() < 20 {
            self.num_lookups += 1;
            true
        } else {
            false
        }
    }
}

pub trait HasLabels {
    fn has_labels(&self) -> bool;
}

impl HasLabels for &str {
    fn has_labels(&self) -> bool {
        let mut has_dots = false;
        let mut has_chars = false;
        for ch in self.chars() {
            if ch.is_alphanumeric() {
                has_chars = true;
            } else if ch == '.' {
                has_dots = true;
            }
            if has_chars && has_dots {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {

    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crate::{
        common::parse::TxtRecordParser,
        spf::{Macro, Spf},
        Resolver, SpfResult, MX,
    };

    #[tokio::test]
    async fn spf_verify() {
        let valid_until = Instant::now() + Duration::from_secs(30);
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("spf");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            println!("===== {} =====", file_name.display());
            let test_suite = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();

            for test in test_suite.split("---\n") {
                let resolver = Resolver::new_system_conf().unwrap();
                let mut test_name = "";
                let mut last_test_name = "";
                let mut helo = "";
                let mut mail_from = "";
                let mut client_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
                let mut test_num = 1;

                for line in test.split('\n') {
                    let line = line.trim();
                    let line = if let Some(line) = line.strip_prefix('-') {
                        line.trim()
                    } else {
                        line
                    };

                    #[cfg(any(test, feature = "test"))]
                    {
                        if let Some(name) = line.strip_prefix("name:") {
                            test_name = name.trim();
                        } else if let Some(record) = line.strip_prefix("spf:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            resolver.txt_add(
                                name.trim().to_string(),
                                Spf::parse(record.as_bytes()),
                                valid_until,
                            );
                        } else if let Some(record) = line.strip_prefix("exp:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            resolver.txt_add(
                                name.trim().to_string(),
                                Macro::parse(record.as_bytes()),
                                valid_until,
                            );
                        } else if let Some(record) = line.strip_prefix("a:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            resolver.ipv4_add(
                                name.trim().to_string(),
                                record
                                    .split(',')
                                    .map(|item| item.trim().parse::<Ipv4Addr>().unwrap())
                                    .collect(),
                                valid_until,
                            );
                        } else if let Some(record) = line.strip_prefix("aaaa:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            resolver.ipv6_add(
                                name.trim().to_string(),
                                record
                                    .split(',')
                                    .map(|item| item.trim().parse::<Ipv6Addr>().unwrap())
                                    .collect(),
                                valid_until,
                            );
                        } else if let Some(record) = line.strip_prefix("ptr:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            resolver.ptr_add(
                                name.trim().parse::<IpAddr>().unwrap(),
                                record
                                    .split(',')
                                    .map(|item| item.trim().to_string())
                                    .collect(),
                                valid_until,
                            );
                        } else if let Some(record) = line.strip_prefix("mx:") {
                            let (name, record) = record.trim().split_once(' ').unwrap();
                            let mut mxs = Vec::new();
                            for (pos, item) in record.split(',').enumerate() {
                                let ip = item.trim().parse::<IpAddr>().unwrap();
                                let mx_name = format!("mx.{ip}.{pos}");
                                match ip {
                                    IpAddr::V4(ip) => {
                                        resolver.ipv4_add(mx_name.clone(), vec![ip], valid_until)
                                    }
                                    IpAddr::V6(ip) => {
                                        resolver.ipv6_add(mx_name.clone(), vec![ip], valid_until)
                                    }
                                }
                                mxs.push(MX {
                                    exchanges: vec![mx_name],
                                    preference: (pos + 1) as u16,
                                });
                            }
                            resolver.mx_add(name.trim().to_string(), mxs, valid_until);
                        } else if let Some(value) = line.strip_prefix("domain:") {
                            helo = value.trim();
                        } else if let Some(value) = line.strip_prefix("sender:") {
                            mail_from = value.trim();
                        } else if let Some(value) = line.strip_prefix("ip:") {
                            client_ip = value.trim().parse().unwrap();
                        } else if let Some(value) = line.strip_prefix("expect:") {
                            let value = value.trim();
                            let (result, exp): (SpfResult, &str) =
                                if let Some((result, exp)) = value.split_once(' ') {
                                    (result.trim().try_into().unwrap(), exp.trim())
                                } else {
                                    (value.try_into().unwrap(), "")
                                };
                            let output = resolver
                                .verify_spf(client_ip, helo, "localdomain.org", mail_from)
                                .await;
                            assert_eq!(
                                output.result(),
                                result,
                                "Failed for {test_name:?}, test {test_num}.",
                            );

                            if !exp.is_empty() {
                                assert_eq!(Some(exp.to_string()).as_deref(), output.explanation());
                            }
                            test_num += 1;
                            if test_name != last_test_name {
                                println!("Passed test {test_name:?}");
                                last_test_name = test_name;
                            }
                        }
                    }
                }
            }
        }
    }
}
