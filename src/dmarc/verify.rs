/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Alignment, DmarcRecord, Policy, Psd};
use crate::DnsError;
use crate::dns::DnsCache;
use crate::{
    AuthenticatedMessage, Dkim2Result, DkimOutput, DkimResult, DmarcOutput, DmarcResult, Error,
    MessageAuthenticator, Parameters, RecordSet, ResolverCache, SpfOutput, SpfResult, TxtRecord,
    dkim2::Dkim2Output, dns::cache::NoCache, dns::to_a_label,
};
use std::{borrow::Cow, net::Ipv4Addr, sync::Arc};

const DMARC_PREFIX: &str = "_dmarc.";
const REPORT_PREFIX: &str = "._report._dmarc.";

/// Input of [`MessageAuthenticator::verify_dmarc`]: the message and the
/// results of the underlying authentication checks.
///
/// Built with [`DmarcParameters::new`], optionally extended with
/// [`DmarcParameters::with_dkim2_output`], and optionally wrapped in
/// [`Parameters`] to supply a DNS cache.
pub struct DmarcParameters<'x> {
    /// The message; its RFC5322.From header gives the Author Domain.
    pub message: &'x AuthenticatedMessage<'x>,
    /// Output of [`MessageAuthenticator::verify_dkim`] for the message.
    pub dkim_output: &'x [DkimOutput<'x>],
    /// Output of DKIM2 verification, if performed; only instance 1 is used
    /// for alignment.
    pub dkim2_output: Option<&'x Dkim2Output<'x>>,
    /// The RFC5321.MailFrom domain (or the HELO domain for a null
    /// reverse-path) that SPF was evaluated for.
    pub mail_from_domain: &'x str,
    /// Output of SPF verification for `mail_from_domain`.
    pub spf_output: &'x SpfOutput,
}

impl MessageAuthenticator {
    /// Evaluates the DMARC policy of a message (RFC 9989, Section 4.10).
    ///
    /// The Author Domain is taken from the RFC5322.From header. Messages
    /// without a From domain, or whose From header lists several different
    /// domains, are exempt and yield an empty output (result `None`).
    ///
    /// DNS lookups performed:
    ///
    /// - A DNS Tree Walk of TXT queries for `_dmarc.<name>`, from the Author
    ///   Domain up to the top-level domain, capped at eight queries. A record
    ///   with `psd=y` or `psd=n` stops the walk. The Author Domain's own
    ///   record applies if present, otherwise the Organizational Domain's,
    ///   otherwise the shortest one found.
    /// - An A query for the Author Domain when a record found above it has
    ///   `np` different from `sp`, to tell a non-existent subdomain (NXDOMAIN,
    ///   RFC 8020) from an existing one.
    /// - Further Tree Walks to find the Organizational Domain of SPF and DKIM
    ///   identifiers under relaxed alignment.
    ///
    /// A record without a valid `p` tag is treated as `p=none` when it has a
    /// valid `rua` tag; otherwise DMARC does not apply.
    ///
    /// The returned [`DmarcOutput`] carries per-mechanism results
    /// ([`DmarcOutput::spf_result`], [`DmarcOutput::dkim_result`]) and the
    /// overall [`DmarcOutput::result`]:
    ///
    /// - [`DmarcResult::Pass`]: SPF or DKIM produced an aligned pass.
    /// - [`DmarcResult::Fail`]: a record applies and no mechanism produced
    ///   an aligned pass.
    /// - [`DmarcResult::TempError`]: a transient DNS error prevented the
    ///   evaluation.
    /// - [`DmarcResult::PermError`]: the DMARC record could not be
    ///   retrieved.
    /// - [`DmarcResult::None`]: DMARC does not apply to the message.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{
    ///     AuthenticatedMessage, DmarcResult, MessageAuthenticator, dmarc::Policy,
    ///     dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
    /// };
    ///
    /// # async fn run(authenticator: &MessageAuthenticator, raw_message: &[u8]) {
    /// let message = AuthenticatedMessage::parse(raw_message).unwrap();
    /// let dkim_output = authenticator.verify_dkim(&message).await;
    /// let spf_output = authenticator
    ///     .verify_spf(SpfParameters::mail_from(
    ///         "192.0.2.1".parse().unwrap(),
    ///         "mx.example.org",
    ///         "mx.my-host.org",
    ///         "sender@example.org",
    ///     ))
    ///     .await;
    /// let dmarc_output = authenticator
    ///     .verify_dmarc(DmarcParameters::new(
    ///         &message,
    ///         &dkim_output,
    ///         "example.org",
    ///         &spf_output,
    ///     ))
    ///     .await;
    ///
    /// if matches!(dmarc_output.result(), DmarcResult::Fail(_))
    ///     && dmarc_output.policy() == Policy::Reject
    /// {
    ///     println!("reject message from {}", dmarc_output.domain());
    /// }
    /// # }
    /// ```
    pub async fn verify_dmarc<'x, C>(
        &self,
        params: impl Into<Parameters<'x, DmarcParameters<'x>, C>>,
    ) -> DmarcOutput
    where
        C: DnsCache + 'x,
    {
        let params = params.into();
        let message = params.input.message;
        let dkim_output = params.input.dkim_output;
        let dkim2_output = params.input.dkim2_output;
        let mail_from_domain = to_a_label(params.input.mail_from_domain);
        let mail_from_domain = mail_from_domain.as_ref();
        let spf_output = params.input.spf_output;
        let cache_txt = params.txt_cache();
        let cache_ipv4 = params.ipv4_cache();
        let mut rfc5322_from_domain = Cow::Borrowed("");
        for from in &message.from {
            if let Some((_, domain)) = from.rsplit_once('@') {
                let domain = to_a_label(domain);
                if rfc5322_from_domain.is_empty() {
                    rfc5322_from_domain = domain;
                } else if rfc5322_from_domain != domain {
                    return DmarcOutput::default();
                }
            }
        }
        if rfc5322_from_domain.is_empty() {
            return DmarcOutput::default();
        }
        let rfc5322_from_domain = rfc5322_from_domain.as_ref();

        let walk = match self.dmarc_tree_walk(rfc5322_from_domain, cache_txt).await {
            Ok(walk) => walk,
            Err(err) => {
                let err = DmarcResult::from(err);
                return DmarcOutput::default()
                    .with_domain(rfc5322_from_domain)
                    .with_dkim_result(err.clone())
                    .with_spf_result(err);
            }
        };
        if walk.is_empty() {
            return DmarcOutput::default().with_domain(rfc5322_from_domain);
        }

        let author_org =
            organizational_domain(&walk, rfc5322_from_domain).unwrap_or(rfc5322_from_domain);

        let (record, is_author_record) =
            if let Some((_, record)) = walk.iter().find(|(name, _)| *name == rfc5322_from_domain) {
                (record, true)
            } else if let Some((_, record)) = walk
                .iter()
                .find(|(name, _)| *name == author_org)
                .or_else(|| walk.last())
            {
                (record, false)
            } else {
                return DmarcOutput::default().with_domain(rfc5322_from_domain);
            };

        let mut policy = if record.p == Policy::Unspecified {
            if record.rua.is_empty() {
                return DmarcOutput::default().with_domain(rfc5322_from_domain);
            }
            Policy::None
        } else if is_author_record {
            record.p
        } else if record.np != record.sp
            && self.domain_exists(rfc5322_from_domain, cache_ipv4).await == Some(false)
        {
            record.np
        } else {
            record.sp
        };

        if record.t {
            policy = match policy {
                Policy::Reject => Policy::Quarantine,
                Policy::Quarantine => Policy::None,
                other => other,
            };
        }
        let aspf = record.aspf;
        let adkim = record.adkim;

        let mut output = DmarcOutput {
            spf_result: DmarcResult::None,
            dkim_result: DmarcResult::None,
            domain: rfc5322_from_domain.to_string(),
            policy,
            record: None,
        };

        let dkim_signatures = dkim_output
            .iter()
            .filter_map(|o| match (&o.result, &o.signature) {
                (DkimResult::Pass, Some(signature)) => Some((signature.d.as_str(), None)),
                (DkimResult::TempError(err), Some(signature)) => {
                    Some((signature.d.as_str(), Some(err)))
                }
                _ => None,
            })
            .chain(dkim2_output.and_then(|o| {
                o.chain
                    .iter()
                    .find(|link| link.signature.i == 1)
                    .and_then(|link| match (&o.result, &link.result) {
                        (Dkim2Result::Pass, Dkim2Result::Pass) => {
                            Some((link.signature.d.as_str(), None))
                        }
                        (Dkim2Result::TempError(_), Dkim2Result::TempError(err)) => {
                            Some((link.signature.d.as_str(), Some(err)))
                        }
                        _ => None,
                    })
            }))
            .map(|(d, temp_error)| (to_a_label(d), temp_error))
            .collect::<Vec<_>>();

        let mut org_memo: Vec<(&str, &str)> = vec![(rfc5322_from_domain, author_org)];

        if matches!(spf_output.result, SpfResult::Pass | SpfResult::TempError) {
            let spf_pass = spf_output.result == SpfResult::Pass;
            output.spf_result = match self
                .is_aligned(
                    mail_from_domain,
                    rfc5322_from_domain,
                    author_org,
                    aspf,
                    cache_txt,
                    &mut org_memo,
                )
                .await
            {
                Ok(true) if spf_pass => DmarcResult::Pass,
                Ok(true) => DmarcResult::TempError(Error::Dns(DnsError::Resolver(String::new()))),
                Ok(false) if spf_pass => DmarcResult::Fail(Error::NotAligned),
                Ok(false) => DmarcResult::None,
                Err(err) => DmarcResult::TempError(err),
            };
        }

        let mut has_dkim_pass = false;
        let mut dkim_temp_error = None;
        for (d, temp_error) in &dkim_signatures {
            if temp_error.is_some() && dkim_temp_error.is_some() {
                continue;
            }
            has_dkim_pass |= temp_error.is_none();
            match self
                .is_aligned(
                    d.as_ref(),
                    rfc5322_from_domain,
                    author_org,
                    adkim,
                    cache_txt,
                    &mut org_memo,
                )
                .await
            {
                Ok(true) => match temp_error {
                    None => {
                        output.dkim_result = DmarcResult::Pass;
                        return output.with_record(Arc::clone(record));
                    }
                    Some(err) => dkim_temp_error = Some((*err).clone()),
                },
                Ok(false) => (),
                Err(err) => {
                    dkim_temp_error.get_or_insert(err);
                }
            }
        }

        output.dkim_result = if let Some(err) = dkim_temp_error {
            DmarcResult::TempError(err)
        } else if has_dkim_pass {
            DmarcResult::Fail(Error::NotAligned)
        } else {
            DmarcResult::None
        };

        output.with_record(Arc::clone(record))
    }

    /// Returns the reporting addresses that are authorized to receive DMARC
    /// reports for a policy domain (RFC 9989).
    ///
    /// Takes a `(policy_domain, addresses)` pair, optionally wrapped in
    /// [`Parameters`] to supply a DNS cache. `addresses` is usually
    /// [`DmarcRecord::rua`] or [`DmarcRecord::ruf`], but any `AsRef<str>`
    /// holding an email address works. An address is authorized when its
    /// domain is the policy domain or a subdomain of it (internal), or, for
    /// an external destination, when a `v=DMARC1` TXT record exists at
    /// `<policy_domain>._report._dmarc.<destination_domain>`. One TXT lookup
    /// is performed per external address. Addresses are returned in input
    /// order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::Resolver`] when a lookup fails
    /// with a transient resolver error. A missing or invalid authorization
    /// record is not an error: the address is left out.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{DmarcOutput, MessageAuthenticator};
    ///
    /// # async fn run(authenticator: &MessageAuthenticator, output: &DmarcOutput) -> mail_auth::Result<()> {
    /// if let Some(record) = output.record() {
    ///     let authorized = authenticator
    ///         .authorized_report_addresses((output.domain(), record.rua()))
    ///         .await?;
    ///     for uri in authorized {
    ///         println!("send aggregate report to {}", uri.uri());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authorized_report_addresses<'x, 'y, T, C>(
        &self,
        params: impl Into<Parameters<'y, (&'y str, &'x [T]), C>>,
    ) -> crate::Result<Vec<&'x T>>
    where
        T: AsRef<str> + 'x,
        C: DnsCache + 'y,
    {
        let params = params.into();
        let (domain, addresses) = params.input;
        let txt_cache = params.txt_cache();
        let domain = to_a_label(domain);
        let domain = domain.as_ref();
        let mut result = Vec::with_capacity(addresses.len());
        let mut key = String::new();
        for address in addresses {
            let address_ref = address.as_ref();
            let address_domain = to_a_label(
                address_ref
                    .rsplit_once('@')
                    .map(|(_, d)| d)
                    .unwrap_or_default(),
            );
            let address_domain = address_domain.as_ref();
            let is_internal = address_domain == domain
                || address_domain
                    .strip_suffix(domain)
                    .is_some_and(|prefix| prefix.ends_with('.'));
            let is_authorized = is_internal || {
                key.clear();
                key.reserve(domain.len() + REPORT_PREFIX.len() + address_domain.len() + 1);
                key.push_str(domain);
                key.push_str(REPORT_PREFIX);
                key.push_str(address_domain);
                key.push('.');
                match self.txt_lookup::<DmarcRecord>(&key, txt_cache).await {
                    Ok(_) => true,
                    Err(err @ Error::Dns(DnsError::Resolver(_))) => return Err(err),
                    _ => false,
                }
            };
            if is_authorized {
                result.push(address);
            }
        }

        Ok(result)
    }

    /// Performs a DNS Tree Walk (RFC 9989 Section 4.10) starting at `domain`
    /// and returns every valid DMARC Policy Record found from the starting
    /// point (longest name) up to the top-level domain (shortest name).
    async fn dmarc_tree_walk<'x>(
        &self,
        domain: &'x str,
        txt_cache: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
    ) -> crate::Result<Vec<(&'x str, Arc<DmarcRecord>)>> {
        let total = domain.split('.').filter(|l| !l.is_empty()).count();
        let mut found = Vec::new();
        if total < 2 {
            return Ok(found);
        }

        let mut count = total;
        let mut key = String::with_capacity(domain.len() + DMARC_PREFIX.len() + 1);
        loop {
            let name = drop_leftmost_labels(domain, total - count);
            key.clear();
            key.push_str(DMARC_PREFIX);
            key.push_str(name);
            key.push('.');
            match self.txt_lookup::<DmarcRecord>(&key, txt_cache).await {
                Ok(dmarc) => {
                    let stop = matches!(dmarc.psd, Psd::Yes | Psd::No);
                    found.push((name, dmarc));
                    if stop {
                        break;
                    }
                }
                Err(Error::Dns(DnsError::RecordNotFound(_)))
                | Err(Error::Dns(DnsError::InvalidRecordType)) => (),
                Err(err) => return Err(err),
            }

            if count == 1 {
                break;
            }
            count = if count >= 8 { 7 } else { count - 1 };
        }

        Ok(found)
    }

    /// Determines whether `domain` exists in the DNS per RFC 8020.
    async fn domain_exists(
        &self,
        domain: &str,
        cache_ipv4: Option<&impl ResolverCache<Box<str>, RecordSet<Ipv4Addr>>>,
    ) -> Option<bool> {
        match self.ipv4_lookup(domain, cache_ipv4).await {
            Ok(_) => Some(true),
            Err(Error::Dns(DnsError::RecordNotFound(code))) => {
                Some(code != crate::dns::DNS_RCODE_NXDOMAIN)
            }
            Err(_) => None,
        }
    }

    async fn is_aligned<'x>(
        &self,
        domain: &'x str,
        author_domain: &'x str,
        author_org: &'x str,
        alignment: Alignment,
        txt_cache: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
        memo: &mut Vec<(&'x str, &'x str)>,
    ) -> crate::Result<bool> {
        Ok(domain == author_domain
            || (alignment == Alignment::Relaxed
                && domain
                    .strip_suffix(author_org)
                    .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('.'))
                && self
                    .organizational_domain_of(domain, txt_cache, memo)
                    .await?
                    == author_org))
    }

    /// Determines the Organizational Domain of `domain` via a DNS Tree Walk (RFC 9989 Section 4.10.2).
    async fn organizational_domain_of<'x>(
        &self,
        domain: &'x str,
        txt_cache: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
        memo: &mut Vec<(&'x str, &'x str)>,
    ) -> crate::Result<&'x str> {
        if let Some(&(_, org)) = memo.iter().find(|(d, _)| *d == domain) {
            return Ok(org);
        }
        let org = match self.dmarc_tree_walk(domain, txt_cache).await {
            Ok(walk) => organizational_domain(&walk, domain).unwrap_or(domain),
            Err(err @ Error::Dns(DnsError::Resolver(_))) => return Err(err),
            Err(_) => domain,
        };
        memo.push((domain, org));
        Ok(org)
    }
}

/// Selects the Organizational Domain from the set of DMARC Policy Records
/// retrieved by a Tree Walk (RFC 9989 Section 4.10.2). The `walk` is ordered
/// from the longest name (the starting domain) to the shortest.
fn organizational_domain<'x>(
    walk: &[(&'x str, Arc<DmarcRecord>)],
    start: &'x str,
) -> Option<&'x str> {
    for (name, record) in walk {
        match record.psd {
            Psd::No => return Some(name),
            Psd::Yes if *name != start => return Some(one_label_below(name, start)),
            _ => {}
        }
    }
    walk.last().map(|(name, _)| *name)
}

/// Returns the domain one label below `psd_name` on the path toward `start`.
fn one_label_below<'x>(psd_name: &str, start: &'x str) -> &'x str {
    let depth = psd_name.split('.').filter(|l| !l.is_empty()).count() + 1;
    let start_labels = start.split('.').filter(|l| !l.is_empty()).count();
    drop_leftmost_labels(start, start_labels.saturating_sub(depth))
}

/// Returns the suffix of `domain` after removing its `n` leftmost labels.
fn drop_leftmost_labels(domain: &str, n: usize) -> &str {
    let mut suffix = domain;
    for _ in 0..n {
        match suffix.split_once('.') {
            Some((_, rest)) => suffix = rest,
            None => return "",
        }
    }
    suffix
}

impl<'x> DmarcParameters<'x> {
    /// Creates the parameters from the message, the DKIM verification
    /// output, the domain SPF was evaluated for (RFC5321.MailFrom domain, or
    /// the HELO domain for a null reverse-path) and the SPF output.
    pub fn new(
        message: &'x AuthenticatedMessage<'x>,
        dkim_output: &'x [DkimOutput<'x>],
        mail_from_domain: &'x str,
        spf_output: &'x SpfOutput,
    ) -> Self {
        Self {
            message,
            dkim_output,
            dkim2_output: None,
            mail_from_domain,
            spf_output,
        }
    }

    /// Adds the DKIM2 verification output; a passing instance 1 signature
    /// takes part in DKIM alignment.
    pub fn with_dkim2_output(mut self, dkim2_output: &'x Dkim2Output<'x>) -> Self {
        self.dkim2_output = Some(dkim2_output);
        self
    }
}

impl<'x> From<DmarcParameters<'x>> for Parameters<'x, DmarcParameters<'x>, NoCache> {
    fn from(params: DmarcParameters<'x>) -> Self {
        Parameters::new(params)
    }
}

impl<'x, 'y, T> From<(&'y str, &'x [T])> for Parameters<'y, (&'y str, &'x [T]), NoCache> {
    fn from(params: (&'y str, &'x [T])) -> Self {
        Parameters::new(params)
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests;
