/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Macro, Mechanism, Qualifier, SpfIdentity, SpfRecord, Variables};
use crate::DnsError;
use crate::Instant;
use crate::dns::{DnsCache, has_valid_labels};
use crate::{
    Error, MessageAuthenticator, Parameters, RecordSet, ResolverCache, SpfOutput, SpfResult,
    dns::cache::NoCache,
};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Input of an SPF check: the client IP, the identity to check and the
/// values used for macro expansion.
///
/// Built with [`SpfParameters::helo`], [`SpfParameters::mail_from`],
/// [`SpfParameters::helo_and_mail_from`] or [`SpfParameters::new`], and
/// passed to [`MessageAuthenticator::verify_spf`] or
/// [`MessageAuthenticator::check_host`], optionally wrapped in [`Parameters`]
/// to supply a DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpfParameters<'x> {
    ip: IpAddr,
    domain: &'x str,
    helo_domain: &'x str,
    host_domain: &'x str,
    sender: Sender<'x>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sender<'x> {
    Helo,
    MailFrom(&'x str),
    Full(&'x str),
}

#[allow(clippy::iter_skip_zero)]
impl MessageAuthenticator {
    /// Verifies the SPF identities of an SMTP session (RFC 7208).
    ///
    /// With parameters built by [`SpfParameters::helo_and_mail_from`] (or
    /// [`SpfParameters::new`]), the HELO identity is checked first. Its output
    /// is returned when the result is `fail` or the sender is empty;
    /// otherwise the MAIL FROM identity is checked and its output returned.
    /// With parameters built by [`SpfParameters::helo`] or
    /// [`SpfParameters::mail_from`], a single [`check_host`] is run for that
    /// identity.
    ///
    /// The DNS lookups performed are those of [`check_host`], once per
    /// identity checked. See [`SpfResult`] for the meaning of each result.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{MessageAuthenticator, SpfResult, spf::verify::SpfParameters};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator) {
    /// let output = authenticator
    ///     .verify_spf(SpfParameters::helo_and_mail_from(
    ///         "192.0.2.1".parse().unwrap(),
    ///         "mx.example.org",
    ///         "mx.my-host.org",
    ///         "sender@example.org",
    ///     ))
    ///     .await;
    ///
    /// if output.result() == SpfResult::Fail {
    ///     println!("rejected: {:?}", output.explanation());
    /// }
    /// # }
    /// ```
    ///
    /// [`check_host`]: MessageAuthenticator::check_host
    pub async fn verify_spf<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        match &params.input.sender {
            Sender::Full(sender) => {
                let helo_output = self
                    .check_host(params.clone_with(SpfParameters::helo(
                        params.input.ip,
                        params.input.helo_domain,
                        params.input.host_domain,
                    )))
                    .await;
                if sender.is_empty() || helo_output.result() == SpfResult::Fail {
                    helo_output
                } else {
                    self.check_host(params.clone_with(SpfParameters::mail_from(
                        params.input.ip,
                        params.input.helo_domain,
                        params.input.host_domain,
                        sender,
                    )))
                    .await
                }
            }
            _ => self.check_host(params).await,
        }
    }

    /// Runs the `check_host()` function (RFC 7208, Section 4) for a single
    /// identity.
    ///
    /// Evaluates the SPF record of the parameters' domain against the client
    /// IP. The DNS lookups performed are:
    ///
    /// - TXT for the `v=spf1` record of the domain, and of every `include:`
    ///   and `redirect=` target.
    /// - A or AAAA (depending on the client IP family) for the `a`, `mx`,
    ///   `ptr` and `exists` mechanisms.
    /// - MX for the `mx` mechanism.
    /// - PTR for the `ptr` mechanism and the `p` macro.
    /// - TXT for the `exp=` explanation, only on a `fail` result.
    ///
    /// The number of DNS-querying mechanisms and modifiers is limited to 10
    /// and the whole evaluation to 20 seconds; an `mx` mechanism may resolve
    /// at most 10 exchanges. Exceeding a limit yields `permerror`.
    ///
    /// The returned [`SpfOutput`] holds one of:
    ///
    /// - [`SpfResult::None`]: the domain is not a valid name or publishes no
    ///   SPF record.
    /// - [`SpfResult::Pass`], [`SpfResult::Fail`], [`SpfResult::SoftFail`] or
    ///   [`SpfResult::Neutral`]: the qualifier of the first matching
    ///   directive, or `neutral` when none matches.
    /// - [`SpfResult::TempError`]: a DNS lookup failed transiently.
    /// - [`SpfResult::PermError`]: a record could not be parsed, an
    ///   `include:` or `redirect=` target has no record, or a limit was
    ///   exceeded.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{MessageAuthenticator, spf::verify::SpfParameters};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator) {
    /// let output = authenticator
    ///     .check_host(SpfParameters::new(
    ///         "192.0.2.1".parse().unwrap(),
    ///         "example.org",
    ///         "mx.example.org",
    ///         "mx.my-host.org",
    ///         "sender@example.org",
    ///     ))
    ///     .await;
    /// println!("spf={} domain={}", output.result(), output.domain());
    /// # }
    /// ```
    #[allow(clippy::while_let_on_iterator)]
    #[allow(clippy::iter_skip_zero)]
    pub async fn check_host<'x, C>(
        &self,
        params: impl Into<Parameters<'x, SpfParameters<'x>, C>>,
    ) -> SpfOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        let domain = params.input.domain;
        let ip = params.input.ip;
        let helo_domain = params.input.helo_domain;
        let host_domain = params.input.host_domain;
        let (sender, identity) = match &params.input.sender {
            Sender::Helo => ("", SpfIdentity::Helo),
            Sender::MailFrom(sender) | Sender::Full(sender) => (*sender, SpfIdentity::MailFrom),
        };

        let output = SpfOutput::new(domain.to_string()).with_identity(identity);
        if domain.is_empty() || domain.len() > 255 || !has_valid_labels(domain) {
            return output.with_result(SpfResult::None);
        }
        let postmaster;
        let sender = if sender.is_empty() {
            postmaster = postmaster_at(domain);
            postmaster.as_str()
        } else {
            sender
        };
        let mut vars = Variables::new();
        let mut has_p_var = false;
        vars.set_ip(&ip);
        vars.set_sender(sender.as_bytes());
        vars.set_domain(domain.as_bytes());
        vars.set_host_domain(host_domain.as_bytes());
        vars.set_helo_domain(helo_domain.as_bytes());

        let mut lookup_limit = LookupLimit::new();
        let mut spf_record = match self
            .txt_lookup::<SpfRecord>(domain, params.txt_cache())
            .await
        {
            Ok(spf_record) => spf_record,
            Err(err) => return output.with_result(err.into()),
        };

        let mut domain = Cow::Borrowed(domain);
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
                        .ptr_lookup(ip, params.ptr_cache())
                        .await
                        .ok()
                        .and_then(|ptrs| ptrs.records.first().map(|ptr| ptr.as_bytes().to_vec()))
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
                                params.ipv4_cache(),
                                params.ipv6_cache(),
                            )
                            .await
                        {
                            Ok(true) => true,
                            Ok(false) | Err(Error::Dns(DnsError::RecordNotFound(_))) => false,
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
                            .mx_lookup(&*macro_string.eval(&vars, &domain, true), params.mx_cache())
                            .await
                        {
                            Ok(records) => {
                                for (mx_num, exchange) in records
                                    .records
                                    .iter()
                                    .flat_map(|mx| mx.exchanges.iter())
                                    .enumerate()
                                {
                                    if mx_num > 9 {
                                        return output
                                            .with_result(SpfResult::PermError)
                                            .with_report(&spf_record);
                                    }

                                    match self
                                        .ip_matches(
                                            exchange,
                                            ip,
                                            *ip4_mask,
                                            *ip6_mask,
                                            params.ipv4_cache(),
                                            params.ipv6_cache(),
                                        )
                                        .await
                                    {
                                        Ok(true) => {
                                            matches = true;
                                            break;
                                        }
                                        Ok(false)
                                        | Err(Error::Dns(DnsError::RecordNotFound(_))) => (),
                                        Err(_) => {
                                            return output
                                                .with_result(SpfResult::TempError)
                                                .with_report(&spf_record);
                                        }
                                    }
                                }
                            }
                            Err(Error::Dns(DnsError::RecordNotFound(_))) => (),
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
                        let included = self
                            .txt_lookup::<SpfRecord>(&*target_name, params.txt_cache())
                            .await;
                        match included {
                            Ok(included_spf) => {
                                let new_domain = target_name.into_owned();
                                include_stack.push((
                                    std::mem::replace(&mut spf_record, included_spf),
                                    pos,
                                    domain,
                                ));
                                directives = spf_record.directives.iter().enumerate().skip(0);
                                vars.set_domain(new_domain.as_bytes().to_vec());
                                domain = Cow::Owned(new_domain);
                                continue;
                            }
                            Err(
                                Error::Dns(DnsError::RecordNotFound(_))
                                | Error::Dns(DnsError::InvalidRecordType)
                                | Error::Parse,
                            ) => {
                                return output
                                    .with_result(SpfResult::PermError)
                                    .with_report(&spf_record);
                            }
                            Err(_) => {
                                return output
                                    .with_result(SpfResult::TempError)
                                    .with_report(&spf_record);
                            }
                        }
                    }
                    Mechanism::Ptr { macro_string } => {
                        if !lookup_limit.can_lookup() {
                            return output
                                .with_result(SpfResult::PermError)
                                .with_report(&spf_record);
                        }

                        let target_name = macro_string.eval(&vars, &domain, true);
                        let target_addr = to_lowercase(target_name.as_ref());
                        let target_addr = target_addr.as_ref();
                        let mut matches = false;

                        if let Ok(records) = self.ptr_lookup(ip, params.ptr_cache()).await {
                            for record in records.records.iter() {
                                if lookup_limit.can_lookup()
                                    && let Ok(true) = self
                                        .ip_matches(
                                            record,
                                            ip,
                                            u32::MAX,
                                            u128::MAX,
                                            params.ipv4_cache(),
                                            params.ipv6_cache(),
                                        )
                                        .await
                                {
                                    matches = record.as_ref() == target_addr
                                        || record
                                            .strip_suffix('.')
                                            .unwrap_or(record.as_ref())
                                            .strip_suffix(target_addr)
                                            .is_some_and(|prefix| prefix.ends_with('.'));
                                    if matches {
                                        break;
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
                            .exists(
                                &*macro_string.eval(&vars, &domain, true),
                                params.ipv4_cache(),
                                params.ipv6_cache(),
                            )
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

            if let (Some(macro_string), None) = (&spf_record.redirect, &result) {
                if !lookup_limit.can_lookup() {
                    return output
                        .with_result(SpfResult::PermError)
                        .with_report(&spf_record);
                }

                let target_name = macro_string.eval(&vars, &domain, true);
                let redirect = self
                    .txt_lookup::<SpfRecord>(&*target_name, params.txt_cache())
                    .await;
                match redirect {
                    Ok(redirect_spf) => {
                        let new_domain = target_name.into_owned();
                        spf_record = redirect_spf;
                        directives = spf_record.directives.iter().enumerate().skip(0);
                        vars.set_domain(new_domain.as_bytes().to_vec());
                        domain = Cow::Owned(new_domain);
                        continue;
                    }
                    Err(
                        Error::Dns(DnsError::RecordNotFound(_))
                        | Error::Dns(DnsError::InvalidRecordType)
                        | Error::Parse,
                    ) => {
                        return output
                            .with_result(SpfResult::PermError)
                            .with_report(&spf_record);
                    }
                    Err(_) => {
                        return output
                            .with_result(SpfResult::TempError)
                            .with_report(&spf_record);
                    }
                }
            }

            if let Some((prev_record, prev_pos, prev_domain)) = include_stack.pop() {
                spf_record = prev_record;
                directives = spf_record.directives.iter().enumerate().skip(prev_pos);
                let qualifier = directives.next().map(|(_, directive)| &directive.qualifier);

                if matches!(result, Some(SpfResult::Pass)) {
                    if let Some(qualifier) = qualifier {
                        result = Some(qualifier.into());
                    }
                    break;
                } else {
                    vars.set_domain(prev_domain.as_bytes().to_vec());
                    domain = prev_domain;
                    result = None;
                }
            } else {
                break;
            }
        }

        if let (Some(macro_string), Some(SpfResult::Fail)) = (&spf_record.exp, &result)
            && let Ok(macro_string) = self
                .txt_lookup::<Macro>(macro_string.eval(&vars, &domain, true), params.txt_cache())
                .await
        {
            return output
                .with_result(SpfResult::Fail)
                .with_explanation(macro_string.eval(&vars, &domain, false).into_owned())
                .with_report(&spf_record);
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
        cache_ipv4: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
        cache_ipv6: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv6Addr>>>,
    ) -> crate::Result<bool> {
        Ok(match ip {
            IpAddr::V4(ip) => self
                .ipv4_lookup(target_name, cache_ipv4)
                .await?
                .records
                .iter()
                .any(|addr| ip.matches_ipv4_mask(addr, ip4_mask)),
            IpAddr::V6(ip) => self
                .ipv6_lookup(target_name, cache_ipv6)
                .await?
                .records
                .iter()
                .any(|addr| ip.matches_ipv6_mask(addr, ip6_mask)),
        })
    }
}

fn postmaster_at(domain: &str) -> String {
    const POSTMASTER: &str = "postmaster@";
    let mut sender = String::with_capacity(POSTMASTER.len() + domain.len());
    sender.push_str(POSTMASTER);
    sender.push_str(domain);
    sender
}

fn to_lowercase(value: &str) -> Cow<'_, str> {
    if value.is_ascii() {
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(value.to_ascii_lowercase())
        } else {
            Cow::Borrowed(value)
        }
    } else {
        Cow::Owned(value.to_lowercase())
    }
}

impl<'x> SpfParameters<'x> {
    /// Checks the HELO identity (RFC 7208, Section 2.3).
    ///
    /// The SPF record of `helo_domain` is evaluated with `<sender>` set to
    /// `postmaster@<helo_domain>`. `host_domain` is the name of the host
    /// performing the check (the `r` macro).
    pub fn helo(ip: IpAddr, helo_domain: &'x str, host_domain: &'x str) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: helo_domain,
            helo_domain,
            host_domain,
            sender: Sender::Helo,
        }
    }

    /// Checks the MAIL FROM identity (RFC 7208, Section 2.4).
    ///
    /// The SPF record of the domain of `sender` is evaluated; when `sender`
    /// has no `@`, `helo_domain` is used instead. An empty `sender` (null
    /// reverse-path) is replaced by `postmaster@<domain>`. `host_domain` is
    /// the name of the host performing the check (the `r` macro).
    pub fn mail_from(
        ip: IpAddr,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: sender.rsplit_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            host_domain,
            sender: Sender::MailFrom(sender),
        }
    }

    /// Checks the HELO identity and then, unless it fails, the MAIL FROM
    /// identity.
    ///
    /// Only [`MessageAuthenticator::verify_spf`] runs both checks; given to
    /// [`MessageAuthenticator::check_host`], these parameters check the MAIL
    /// FROM identity alone. Arguments are those of [`SpfParameters::mail_from`].
    pub fn helo_and_mail_from(
        ip: IpAddr,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> SpfParameters<'x> {
        SpfParameters {
            ip,
            domain: sender.rsplit_once('@').map_or(helo_domain, |(_, d)| d),
            helo_domain,
            host_domain,
            sender: Sender::Full(sender),
        }
    }

    /// Parameters for [`MessageAuthenticator::check_host`].
    ///
    /// - `ip`: the SMTP client IP address (`<ip>`).
    /// - `domain`: the domain whose SPF record is evaluated (`<domain>`).
    /// - `helo_domain`: the domain given in the HELO or EHLO command.
    /// - `host_domain`: the name of the host performing the check (the `r` macro).
    /// - `sender`: the MAIL FROM address (`<sender>`); an empty string is
    ///   replaced by `postmaster@<domain>`.
    ///
    /// Given to [`MessageAuthenticator::verify_spf`], these parameters behave
    /// like [`SpfParameters::helo_and_mail_from`] and `domain` is ignored.
    pub fn new(
        ip: IpAddr,
        domain: &'x str,
        helo_domain: &'x str,
        host_domain: &'x str,
        sender: &'x str,
    ) -> Self {
        SpfParameters {
            ip,
            domain,
            helo_domain,
            host_domain,
            sender: Sender::Full(sender),
        }
    }

    pub(crate) fn ip(&self) -> IpAddr {
        self.ip
    }

    pub(crate) fn helo_domain(&self) -> &'x str {
        self.helo_domain
    }

    pub(crate) fn host_domain(&self) -> &'x str {
        self.host_domain
    }

    pub(crate) fn mail_from_address(&self) -> Option<&'x str> {
        match self.sender {
            Sender::Helo => None,
            Sender::MailFrom(sender) | Sender::Full(sender) => Some(sender),
        }
    }
}

impl<'x> From<SpfParameters<'x>> for Parameters<'x, SpfParameters<'x>, NoCache> {
    fn from(params: SpfParameters<'x>) -> Self {
        Parameters::new(params)
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
            Error::Dns(DnsError::RecordNotFound(_)) | Error::Dns(DnsError::InvalidRecordType) => {
                SpfResult::None
            }
            Error::Parse => SpfResult::PermError,
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
        if self.num_lookups <= 10 && self.timer.elapsed().as_secs() < 20 {
            self.num_lookups += 1;
            true
        } else {
            false
        }
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
        MessageAuthenticator, Mx, SpfResult,
        dns::cache::test::DummyCaches,
        parse::TxtRecordParser,
        spf::{Macro, SpfRecord},
    };

    use super::SpfParameters;

    #[tokio::test]
    async fn spf_verify() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let valid_until = Instant::now() + Duration::from_secs(30);
        let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("resources");
        test_dir.push("spf");

        for file_name in fs::read_dir(&test_dir).unwrap() {
            let file_name = file_name.unwrap().path();
            println!("===== {} =====", file_name.display());
            let test_suite = String::from_utf8(fs::read(&file_name).unwrap()).unwrap();
            let caches = DummyCaches::new();

            for test in test_suite.split("---\n") {
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

                    if let Some(name) = line.strip_prefix("name:") {
                        test_name = name.trim();
                    } else if let Some(record) = line.strip_prefix("spf:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.txt_add(
                            name.trim().to_string(),
                            SpfRecord::parse(record.as_bytes()),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("exp:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.txt_add(
                            name.trim().to_string(),
                            Macro::parse(record.as_bytes()),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("a:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ipv4_add(
                            name.trim().to_string(),
                            record
                                .split(',')
                                .map(|item| item.trim().parse::<Ipv4Addr>().unwrap())
                                .collect(),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("aaaa:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ipv6_add(
                            name.trim().to_string(),
                            record
                                .split(',')
                                .map(|item| item.trim().parse::<Ipv6Addr>().unwrap())
                                .collect(),
                            valid_until,
                        );
                    } else if let Some(record) = line.strip_prefix("ptr:") {
                        let (name, record) = record.trim().split_once(' ').unwrap();
                        caches.ptr_add(
                            name.trim().parse::<IpAddr>().unwrap(),
                            record
                                .split(',')
                                .map(|item| Box::from(item.trim()))
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
                                    caches.ipv4_add(mx_name.clone(), vec![ip], valid_until)
                                }
                                IpAddr::V6(ip) => {
                                    caches.ipv6_add(mx_name.clone(), vec![ip], valid_until)
                                }
                            }
                            mxs.push(Mx {
                                exchanges: Box::new([mx_name.into_boxed_str()]),
                                preference: (pos + 1) as u16,
                            });
                        }
                        caches.mx_add(name.trim().to_string(), mxs, valid_until);
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
                                (result.trim().parse::<SpfResult>().unwrap(), exp.trim())
                            } else {
                                (value.parse::<SpfResult>().unwrap(), "")
                            };
                        let output = resolver
                            .verify_spf(caches.parameters(SpfParameters::helo_and_mail_from(
                                client_ip,
                                helo,
                                "localdomain.org",
                                mail_from,
                            )))
                            .await;
                        assert_eq!(
                            output.result(),
                            result,
                            "Failed for {test_name:?}, test {test_num}, ehlo: {helo}, mail-from: {mail_from}.",
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
