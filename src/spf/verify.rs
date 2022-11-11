use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Error, Resolver, SPFResult};

use super::{Macro, Mechanism, Qualifier, Variables, SPF};

impl Resolver {
    pub async fn verify_spf(&self, ip: IpAddr, mail_from: &str, helo_domain: &str) -> SPFResult {
        // Verify HELO domain
        if self.verify_helo {
            let mut has_dots = false;
            let mut has_chars = false;
            for ch in helo_domain.chars() {
                if ch.is_alphanumeric() {
                    has_chars = true;
                } else if ch == '.' {
                    has_dots = true;
                }
                if has_chars && has_dots {
                    break;
                }
            }
            if has_chars && has_dots {
                match self
                    .check_host(
                        ip,
                        helo_domain,
                        helo_domain,
                        &format!("postmaster@{}", helo_domain),
                    )
                    .await
                {
                    SPFResult::TempError | SPFResult::PermError | SPFResult::None => (),
                    result => return result,
                }
            }
        }

        self.check_host(
            ip,
            mail_from.split_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            mail_from,
        )
        .await
    }

    #[allow(clippy::while_let_on_iterator)]
    pub(crate) async fn check_host(
        &self,
        ip: IpAddr,
        domain: &str,
        helo_domain: &str,
        sender: &str,
    ) -> SPFResult {
        if domain.is_empty() || domain.len() > 63 {
            return SPFResult::None;
        }
        let mut vars = Variables::new();
        let mut has_p_var = false;
        vars.set_ip(&ip);
        if !sender.is_empty() {
            vars.set_sender(sender.as_bytes());
        } else {
            vars.set_sender(format!("postmaster@{}", domain).into_bytes());
        }
        vars.set_domain(domain.as_bytes());
        vars.set_host_domain(&self.host_domain);
        vars.set_helo_domain(helo_domain.as_bytes());

        let mut spf_record = match self.txt_lookup::<SPF>(format!("{}.", domain)).await {
            Ok(spf_record) => spf_record,
            Err(err) => return err.into(),
        };
        let mut lookup_count: u32 = 1;

        let mut domain = domain.to_string();
        let mut include_stack = Vec::new();

        let mut result = SPFResult::Neutral;
        let mut directives = spf_record.directives.iter().enumerate().skip(0);

        loop {
            while let Some((pos, directive)) = directives.next() {
                if !has_p_var && directive.mechanism.needs_ptr() {
                    if !lookup_count.can_lookup() {
                        return SPFResult::PermError;
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
                        if !lookup_count.can_lookup() {
                            return SPFResult::PermError;
                        }
                        match self
                            .ip_matches(
                                macro_string.eval(&vars, &domain).as_ref(),
                                ip,
                                *ip4_mask,
                                *ip6_mask,
                            )
                            .await
                        {
                            Ok(true) => true,
                            Ok(false) | Err(Error::DNSRecordNotFound(_)) => false,
                            Err(_) => {
                                return SPFResult::TempError;
                            }
                        }
                    }
                    Mechanism::Mx {
                        macro_string,
                        ip4_mask,
                        ip6_mask,
                    } => {
                        if !lookup_count.can_lookup() {
                            return SPFResult::PermError;
                        }

                        let mut matches = false;
                        match self
                            .mx_lookup(macro_string.eval(&vars, &domain).as_ref())
                            .await
                        {
                            Ok(records) => {
                                if !lookup_count.can_lookup() {
                                    return SPFResult::PermError;
                                }

                                for record in records.iter() {
                                    match self
                                        .ip_matches(&record.exchange, ip, *ip4_mask, *ip6_mask)
                                        .await
                                    {
                                        Ok(true) => {
                                            matches = true;
                                            break;
                                        }
                                        Ok(false) | Err(Error::DNSRecordNotFound(_)) => (),
                                        Err(_) => {
                                            return SPFResult::TempError;
                                        }
                                    }
                                }
                            }
                            Err(Error::DNSRecordNotFound(_)) => (),
                            Err(_) => {
                                return SPFResult::TempError;
                            }
                        }
                        matches
                    }
                    Mechanism::Include { macro_string } => {
                        if !lookup_count.can_lookup() {
                            return SPFResult::PermError;
                        }

                        let target_name = macro_string.eval(&vars, &domain);
                        match self.txt_lookup::<SPF>(target_name.to_string()).await {
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
                                Error::DNSRecordNotFound(_)
                                | Error::InvalidRecordType
                                | Error::ParseError,
                            ) => return SPFResult::PermError,
                            Err(_) => return SPFResult::TempError,
                        }
                    }
                    Mechanism::Ptr { macro_string } => {
                        if !lookup_count.can_lookup() {
                            return SPFResult::PermError;
                        }

                        let target_addr = macro_string.eval(&vars, &domain).to_lowercase();
                        let target_sub_addr = format!(".{}", target_addr);
                        let mut matches = false;
                        if let Ok(records) = self.ptr_lookup(ip).await {
                            for record in records.iter() {
                                if !lookup_count.can_lookup() {
                                    return SPFResult::PermError;
                                }

                                if let Ok(true) =
                                    self.ip_matches(record, ip, u32::MAX, u128::MAX).await
                                {
                                    if record == &target_addr || record.ends_with(&target_sub_addr)
                                    {
                                        matches = true;
                                        break;
                                    }
                                }
                            }
                        }
                        matches
                    }
                    Mechanism::Exists { macro_string } => {
                        if !lookup_count.can_lookup() {
                            return SPFResult::PermError;
                        }

                        if let Ok(result) = self
                            .exists(macro_string.eval(&vars, &domain).as_ref())
                            .await
                        {
                            result
                        } else {
                            return SPFResult::TempError;
                        }
                    }
                };

                if matches {
                    result = (&directive.qualifier).into();
                    break;
                }
            }

            if let Some((prev_record, prev_pos, prev_domain)) = include_stack.pop() {
                spf_record = prev_record;
                directives = spf_record.directives.iter().enumerate().skip(prev_pos);
                let (_, directive) = directives.next().unwrap();

                if matches!(result, SPFResult::Pass) {
                    result = (&directive.qualifier).into();
                    break;
                } else {
                    vars.set_domain(prev_domain.as_bytes().to_vec());
                    domain = prev_domain;
                    result = SPFResult::Neutral;
                }
            } else {
                // Follow redirect
                if let (Some(macro_string), SPFResult::Neutral) = (&spf_record.redirect, &result) {
                    if !lookup_count.can_lookup() {
                        return SPFResult::PermError;
                    }

                    let target_name = macro_string.eval(&vars, &domain);
                    match self.txt_lookup::<SPF>(target_name.to_string()).await {
                        Ok(redirect_spf) => {
                            let new_domain = target_name.to_string();
                            spf_record = redirect_spf;
                            directives = spf_record.directives.iter().enumerate().skip(0);
                            domain = new_domain;
                            vars.set_domain(domain.as_bytes().to_vec());
                            continue;
                        }
                        Err(
                            Error::DNSRecordNotFound(_)
                            | Error::InvalidRecordType
                            | Error::ParseError,
                        ) => return SPFResult::PermError,
                        Err(_) => return SPFResult::TempError,
                    }
                }

                break;
            }
        }

        // Evaluate explain
        if let (Some(macro_string), SPFResult::Fail(_)) = (&spf_record.exp, &result) {
            if let Ok(macro_string) = self
                .txt_lookup::<Macro>(macro_string.eval(&vars, &domain).to_string())
                .await
            {
                result = SPFResult::Fail(macro_string.eval(&vars, &domain).to_string());
            }
        }

        result
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
                .ipv4_lookup(target_name.as_ref())
                .await?
                .iter()
                .any(|addr| ip.matches_ipv4_mask(addr, ip4_mask)),
            IpAddr::V6(ip) => self
                .ipv6_lookup(target_name.as_ref())
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
                if let Some(ip) = ip.to_ipv4() {
                    ip.octets()
                } else {
                    return false;
                }
            }
        }) & mask
            == u32::from_be_bytes(addr.octets())
    }

    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(match &self {
            IpAddr::V6(ip) => ip.octets(),
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        }) & mask
            == u128::from_be_bytes(addr.octets())
    }
}

impl IpMask for Ipv6Addr {
    fn matches_ipv6_mask(&self, addr: &Ipv6Addr, mask: u128) -> bool {
        u128::from_be_bytes(self.octets()) & mask == u128::from_be_bytes(addr.octets())
    }

    fn matches_ipv4_mask(&self, _addr: &Ipv4Addr, _mask: u32) -> bool {
        unimplemented!()
    }
}

impl IpMask for Ipv4Addr {
    fn matches_ipv4_mask(&self, addr: &Ipv4Addr, mask: u32) -> bool {
        u32::from_be_bytes(self.octets()) & mask == u32::from_be_bytes(addr.octets())
    }

    fn matches_ipv6_mask(&self, _addr: &Ipv6Addr, _mask: u128) -> bool {
        unimplemented!()
    }
}

impl From<&Qualifier> for SPFResult {
    fn from(q: &Qualifier) -> Self {
        match q {
            Qualifier::Pass => SPFResult::Pass,
            Qualifier::Fail => SPFResult::Fail(String::new()),
            Qualifier::SoftFail => SPFResult::SoftFail,
            Qualifier::Neutral => SPFResult::Neutral,
        }
    }
}

impl From<Error> for SPFResult {
    fn from(err: Error) -> Self {
        match err {
            Error::DNSRecordNotFound(_) | Error::InvalidRecordType => SPFResult::None,
            Error::ParseError => SPFResult::PermError,
            _ => SPFResult::TempError,
        }
    }
}

trait LookupLimit {
    fn can_lookup(&mut self) -> bool;
}

impl LookupLimit for u32 {
    #[inline(always)]
    fn can_lookup(&mut self) -> bool {
        if *self < 10 {
            *self += 1;
            true
        } else {
            false
        }
    }
}
