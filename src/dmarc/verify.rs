/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Alignment, Dmarc, Policy, Psd};
use crate::DnsError;
use crate::{
    AuthenticatedMessage, Dkim2Result, DkimOutput, DkimResult, DmarcOutput, DmarcResult, Error, MX,
    MessageAuthenticator, Parameters, RecordSet, ResolverCache, SpfOutput, SpfResult, Txt,
    common::cache::NoCache, dkim2::Dkim2Output,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub struct DmarcParameters<'x> {
    pub message: &'x AuthenticatedMessage<'x>,
    pub dkim_output: &'x [DkimOutput<'x>],
    pub dkim2_output: Option<&'x Dkim2Output<'x>>,
    pub rfc5321_mail_from_domain: &'x str,
    pub spf_output: &'x SpfOutput,
}

impl MessageAuthenticator {
    /// Verifies the DMARC policy of an RFC5321.MailFrom domain
    pub async fn verify_dmarc<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, DmarcParameters<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> DmarcOutput
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
    {
        // Extract RFC5322.From domain
        let params = params.into();
        let message = params.params.message;
        let dkim_output = params.params.dkim_output;
        let dkim2_output = params.params.dkim2_output;
        let rfc5321_mail_from_domain = params.params.rfc5321_mail_from_domain;
        let spf_output = params.params.spf_output;
        let cache_txt = params.cache_txt;
        let cache_ipv4 = params.cache_ipv4;
        let mut rfc5322_from_domain = "";
        for from in &message.from {
            if let Some((_, domain)) = from.rsplit_once('@') {
                if rfc5322_from_domain.is_empty() {
                    rfc5322_from_domain = domain;
                } else if rfc5322_from_domain != domain {
                    // Multi-valued RFC5322.From header fields with multiple
                    // domains MUST be exempt from DMARC checking.
                    return DmarcOutput::default();
                }
            }
        }
        if rfc5322_from_domain.is_empty() {
            return DmarcOutput::default();
        }

        // Perform a DNS Tree Walk to discover the DMARC Policy Record for the
        // Author Domain (RFC 9989 Section 4.10.1)
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

        // Determine the Organizational Domain of the Author Domain
        let author_org =
            organizational_domain(&walk, rfc5322_from_domain).unwrap_or(rfc5322_from_domain);

        // Select the DMARC Policy Record to apply: the Author Domain's own
        // record, otherwise the Organizational Domain's, otherwise the PSD's
        // (RFC 9989 Section 4.10.1).
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

        // Determine the Domain Owner Assessment Policy
        let mut policy = if is_author_record {
            // A record published at the Author Domain uses the "p" tag
            record.p
        } else if record.np != record.sp
            && self.domain_exists(rfc5322_from_domain, cache_ipv4).await == Some(false)
        {
            // The Author Domain returns NXDOMAIN, i.e. is a non-existent
            // subdomain (RFC 8020), so "np" applies
            record.np
        } else {
            // The Author Domain is an existing subdomain, so "sp" applies
            record.sp
        };

        // A record without a valid "p" tag is treated as "p=none" when a valid
        // "rua" tag is present, otherwise DMARC does not apply (Section 4.10.1)
        if policy == Policy::Unspecified {
            if record.rua.is_empty() {
                return DmarcOutput::default().with_domain(rfc5322_from_domain);
            }
            policy = Policy::None;
        }

        // In test mode ("t=y") the stated policy is not applied; enforcement is
        // dropped by one level (RFC 9989 Section 4.7)
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

        // Cache Organizational Domains resolved during alignment
        let mut org_memo: Vec<(&str, &str)> = vec![(rfc5322_from_domain, author_org)];

        if spf_output.result == SpfResult::Pass {
            // Check SPF alignment (Section 4.10.2)
            let aligned = rfc5321_mail_from_domain == rfc5322_from_domain
                || (aspf == Alignment::Relaxed
                    && self
                        .organizational_domain_of(
                            rfc5321_mail_from_domain,
                            cache_txt,
                            &mut org_memo,
                        )
                        .await
                        == author_org);
            output.spf_result = if aligned {
                DmarcResult::Pass
            } else {
                DmarcResult::Fail(Error::NotAligned)
            };
        }

        // Check DKIM alignment (Section 4.10.2)
        let mut has_dkim = false;
        let mut aligned = false;
        for d in dkim_output
            .iter()
            .filter(|o| o.result == DkimResult::Pass)
            .filter_map(|o| o.signature.as_ref())
            .map(|s| s.d.as_str())
            .chain(
                dkim2_output
                    .filter(|o| o.result == Dkim2Result::Pass)
                    .and_then(|o| {
                        o.chain
                            .iter()
                            .find(|link| link.signature.i == 1 && link.result == Dkim2Result::Pass)
                            .map(|link| link.signature.d.as_str())
                    }),
            )
        {
            has_dkim = true;
            if d == rfc5322_from_domain
                || (adkim == Alignment::Relaxed
                    && self
                        .organizational_domain_of(d, cache_txt, &mut org_memo)
                        .await
                        == author_org)
            {
                aligned = true;
                break;
            }
        }

        if has_dkim {
            output.dkim_result = if aligned {
                DmarcResult::Pass
            } else {
                DmarcResult::Fail(Error::NotAligned)
            };
        }

        output.with_record(Arc::clone(record))
    }

    /// Validates the external report e-mail addresses of a DMARC record
    pub async fn verify_dmarc_report_address<'x, T: AsRef<str>>(
        &self,
        domain: &str,
        addresses: &'x [T],
        txt_cache: Option<&impl ResolverCache<Box<str>, Txt>>,
    ) -> Option<Vec<&'x T>> {
        let mut result = Vec::with_capacity(addresses.len());
        for address in addresses {
            let address_ref = address.as_ref();
            let address_domain = address_ref
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or_default();
            // No external authorization is required when the destination is the
            // policy domain itself or a subdomain of it.
            let is_internal = address_domain == domain
                || address_domain
                    .strip_suffix(domain)
                    .is_some_and(|prefix| prefix.ends_with('.'));
            if is_internal
                || match self
                    .txt_lookup::<Dmarc>(
                        format!("{domain}._report._dmarc.{address_domain}."),
                        txt_cache,
                    )
                    .await
                {
                    Ok(_) => true,
                    Err(Error::Dns(DnsError::Resolver(_))) => return None,
                    _ => false,
                }
            {
                result.push(address);
            }
        }

        result.into()
    }

    /// Performs a DNS Tree Walk (RFC 9989 Section 4.10) starting at `domain`
    /// and returns every valid DMARC Policy Record found from the starting
    /// point (longest name) up to the top-level domain (shortest name).
    async fn dmarc_tree_walk<'x>(
        &self,
        domain: &'x str,
        txt_cache: Option<&impl ResolverCache<Box<str>, Txt>>,
    ) -> crate::Result<Vec<(&'x str, Arc<Dmarc>)>> {
        let total = domain.split('.').filter(|l| !l.is_empty()).count();
        let mut found = Vec::new();
        if total < 2 {
            return Ok(found);
        }

        // The first query targets the starting point; subsequent queries drop
        // to 7 labels when the name has 8 or more (the eight-query cap) and then
        // one label at a time down to the top-level domain.
        let mut count = total;
        loop {
            let name = drop_leftmost_labels(domain, total - count);
            match self
                .txt_lookup::<Dmarc>(format!("_dmarc.{name}."), txt_cache)
                .await
            {
                Ok(dmarc) => {
                    // A record carrying "psd=y" or "psd=n" stops the walk
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
            // The name resolves to an address: it exists.
            Ok(_) => Some(true),
            // NODATA (any RCODE other than NXDOMAIN) means the name exists but
            // has no A record; only NXDOMAIN means the name does not exist.
            Err(Error::Dns(DnsError::RecordNotFound(code))) => {
                Some(code != crate::DNS_RCODE_NXDOMAIN)
            }
            Err(_) => None,
        }
    }

    /// Determines the Organizational Domain of `domain` via a DNS Tree Walk (RFC 9989 Section 4.10.2).
    async fn organizational_domain_of<'x>(
        &self,
        domain: &'x str,
        txt_cache: Option<&impl ResolverCache<Box<str>, Txt>>,
        memo: &mut Vec<(&'x str, &'x str)>,
    ) -> &'x str {
        if let Some(&(_, org)) = memo.iter().find(|(d, _)| *d == domain) {
            return org;
        }
        let org = match self.dmarc_tree_walk(domain, txt_cache).await {
            Ok(walk) => organizational_domain(&walk, domain).unwrap_or(domain),
            Err(_) => domain,
        };
        memo.push((domain, org));
        org
    }
}

/// Selects the Organizational Domain from the set of DMARC Policy Records
/// retrieved by a Tree Walk (RFC 9989 Section 4.10.2). The `walk` is ordered
/// from the longest name (the starting domain) to the shortest.
fn organizational_domain<'x>(walk: &[(&'x str, Arc<Dmarc>)], start: &'x str) -> Option<&'x str> {
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
    pub fn new(
        message: &'x AuthenticatedMessage<'x>,
        dkim_output: &'x [DkimOutput<'x>],
        rfc5321_mail_from_domain: &'x str,
        spf_output: &'x SpfOutput,
    ) -> Self {
        Self {
            message,
            dkim_output,
            dkim2_output: None,
            rfc5321_mail_from_domain,
            spf_output,
        }
    }

    pub fn with_dkim2_output(mut self, dkim2_output: &'x Dkim2Output<'x>) -> Self {
        self.dkim2_output = Some(dkim2_output);
        self
    }
}

impl<'x> From<DmarcParameters<'x>>
    for Parameters<
        'x,
        DmarcParameters<'x>,
        NoCache<Box<str>, Txt>,
        NoCache<Box<str>, RecordSet<MX>>,
        NoCache<Box<str>, RecordSet<Ipv4Addr>>,
        NoCache<Box<str>, RecordSet<Ipv6Addr>>,
        NoCache<IpAddr, RecordSet<Box<str>>>,
    >
{
    fn from(params: DmarcParameters<'x>) -> Self {
        Parameters::new(params)
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use super::DmarcParameters;
    use crate::{
        AuthenticatedMessage, DkimOutput, DkimResult, DmarcResult, Error, MessageAuthenticator,
        SpfOutput, SpfResult,
        common::{cache::test::DummyCaches, parse::TxtRecordParser},
        dkim::{DkimError, Signature},
        dmarc::{Dmarc, Policy, URI},
    };
    use mail_parser::MessageParser;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn dmarc_verify_alignment() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();

        for (
            dmarc_dns,
            dmarc,
            message,
            rfc5321_mail_from_domain,
            signature_domain,
            dkim,
            spf,
            expect_dkim,
            expect_spf,
            policy,
        ) in [
            // Strict - Pass
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "example.org",
                "example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Relaxed - Pass on the Organizational Domain
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=r; adkim=r; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                "subdomain.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Strict - Fail (subdomain identifiers do not match exactly)
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                "subdomain.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Fail(Error::NotAligned),
                DmarcResult::Fail(Error::NotAligned),
                Policy::Reject,
            ),
            // Failed mechanisms produce no aligned result
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "example.org",
                "example.org",
                DkimResult::Fail(Error::Dkim(DkimError::SignatureExpired)),
                SpfResult::Fail,
                DmarcResult::None,
                DmarcResult::None,
                Policy::Reject,
            ),
        ] {
            caches.txt_add(
                dmarc_dns,
                Dmarc::parse(dmarc.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3200, 0),
            );

            let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
            let signature = Signature {
                d: signature_domain.into(),
                ..Default::default()
            };
            let dkim = DkimOutput {
                result: dkim,
                signature: (&signature).into(),
                report: None,
                is_atps: false,
            };
            let spf = SpfOutput {
                result: spf,
                domain: rfc5321_mail_from_domain.to_string(),
                report: None,
                explanation: None,
            };
            let result = resolver
                .verify_dmarc(caches.parameters(DmarcParameters::new(
                    &auth_message,
                    &[dkim],
                    rfc5321_mail_from_domain,
                    &spf,
                )))
                .await;
            assert_eq!(result.dkim_result, expect_dkim, "dkim {message}");
            assert_eq!(result.spf_result, expect_spf, "spf {message}");
            assert_eq!(result.policy, policy, "policy {message}");
        }
    }

    #[tokio::test]
    async fn dmarc_policy_discovery() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let expires = Instant::now() + Duration::new(3200, 0);

        // Author Domain has its own record -> "p" applies
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.example.org.",
            Dmarc::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
            expires,
        );
        assert_eq!(
            policy_of(&resolver, &caches, "hello@example.org").await,
            Policy::Reject,
        );

        // Existing subdomain, only the Organizational Domain publishes a
        // record -> "sp" applies
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.example.org.",
            Dmarc::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
            expires,
        );
        caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
        assert_eq!(
            policy_of(&resolver, &caches, "hello@sub.example.org").await,
            Policy::Quarantine,
        );

        // Non-existent subdomain -> "np" applies
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.example.org.",
            Dmarc::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
            expires,
        );
        assert_eq!(
            policy_of(&resolver, &caches, "hello@ghost.example.org").await,
            Policy::None,
        );

        // Missing "p" with a valid "rua" -> treated as "p=none"
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.example.org.",
            Dmarc::parse(b"v=DMARC1; rua=mailto:d@example.org").unwrap(),
            expires,
        );
        assert_eq!(
            policy_of(&resolver, &caches, "hello@example.org").await,
            Policy::None,
        );

        // No record at all -> DMARC does not apply
        let caches = DummyCaches::new();
        let result = verify(&resolver, &caches, "hello@nothing.example").await;
        assert_eq!(result.dmarc_record(), None);
    }

    #[tokio::test]
    async fn dmarc_tree_walk_psd() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let expires = Instant::now() + Duration::new(3200, 0);

        // "psd=n" marks the Organizational Domain: relaxed alignment between
        // "a.mail.example.com" and an identifier under "mail.example.com" holds
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.mail.example.com.",
            Dmarc::parse(b"v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com").unwrap(),
            expires,
        );
        caches.ipv4_add("a.mail.example.com.", vec![[127, 0, 0, 1].into()], expires);
        let result = verify_aligned(
            &resolver,
            &caches,
            "hello@a.mail.example.com",
            "b.mail.example.com",
        )
        .await;
        assert_eq!(result.spf_result(), &DmarcResult::Pass);

        // "psd=y" pushes the Organizational Domain one label below, so
        // "giant.bank.example" and "mega.bank.example" are different
        // Organizational Domains and do not align
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.bank.example.",
            Dmarc::parse(b"v=DMARC1; p=reject; psd=y; rua=mailto:d@bank.example").unwrap(),
            expires,
        );
        caches.txt_add(
            "_dmarc.giant.bank.example.",
            Dmarc::parse(b"v=DMARC1; p=reject; rua=mailto:d@giant.bank.example").unwrap(),
            expires,
        );
        let result = verify_aligned(
            &resolver,
            &caches,
            "hello@giant.bank.example",
            "mega.bank.example",
        )
        .await;
        assert_eq!(result.spf_result(), &DmarcResult::Fail(Error::NotAligned));
    }

    #[tokio::test]
    async fn dmarc_tree_walk_query_cap() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let expires = Instant::now() + Duration::new(3200, 0);

        // A record published between the Author Domain and the 7-labels-remaining
        // shortcut is never discovered, but "example.com" is reached within the
        // eight-query budget.
        let caches = DummyCaches::new();
        caches.txt_add(
            "_dmarc.example.com.",
            Dmarc::parse(b"v=DMARC1; p=reject; np=none; rua=mailto:d@example.com").unwrap(),
            expires,
        );
        assert_eq!(
            policy_of(
                &resolver,
                &caches,
                "hello@a.b.c.d.e.f.g.h.i.j.mail.example.com",
            )
            .await,
            Policy::None,
        );
    }

    async fn verify(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        from: &str,
    ) -> DmarcOutputHelper {
        verify_aligned(resolver, caches, from, "").await
    }

    async fn verify_aligned(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        from: &str,
        mail_from_domain: &str,
    ) -> DmarcOutputHelper {
        let message = format!("From: {from}\r\n\r\n");
        let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
        let spf = SpfOutput {
            result: SpfResult::Pass,
            domain: mail_from_domain.to_string(),
            report: None,
            explanation: None,
        };
        resolver
            .verify_dmarc(caches.parameters(DmarcParameters::new(
                &auth_message,
                &[],
                mail_from_domain,
                &spf,
            )))
            .await
    }

    async fn policy_of(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        from: &str,
    ) -> Policy {
        verify(resolver, caches, from).await.policy()
    }

    type DmarcOutputHelper = crate::DmarcOutput;

    #[tokio::test]
    async fn dmarc_verify_dkim2() {
        use crate::Dkim2Result;
        use crate::dkim2::{ChainLink, Dkim2Output, Signature as Dkim2Signature};

        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();

        for (dmarc_dns, dmarc, message, signature_domain, dkim2_result, expect_dkim, policy) in [
            // Strict - Pass
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "example.org",
                Dkim2Result::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Relaxed - Pass on the Organizational Domain
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=r; adkim=r; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                Dkim2Result::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Strict - Fail (subdomain does not match exactly)
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                Dkim2Result::Pass,
                DmarcResult::Fail(Error::NotAligned),
                Policy::Reject,
            ),
            // Chain did not verify - no DKIM alignment
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
                "From: hello@example.org\r\n\r\n",
                "example.org",
                Dkim2Result::Fail(Error::NotAligned),
                DmarcResult::None,
                Policy::Reject,
            ),
        ] {
            caches.txt_add(
                dmarc_dns,
                Dmarc::parse(dmarc.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3200, 0),
            );

            let auth_message = AuthenticatedMessage::parse(message.as_bytes()).unwrap();
            let signature = Dkim2Signature {
                i: 1,
                d: signature_domain.into(),
                ..Default::default()
            };
            let dkim2 = Dkim2Output {
                result: dkim2_result.clone(),
                chain: vec![ChainLink {
                    signature: &signature,
                    instance: None,
                    result: dkim2_result,
                    custody_ok: true,
                }],
            };
            let spf = SpfOutput {
                result: SpfResult::None,
                domain: "example.org".to_string(),
                report: None,
                explanation: None,
            };
            let result = resolver
                .verify_dmarc(
                    caches.parameters(
                        DmarcParameters::new(&auth_message, &[], "example.org", &spf)
                            .with_dkim2_output(&dkim2),
                    ),
                )
                .await;
            assert_eq!(result.dkim_result, expect_dkim);
            assert_eq!(result.policy, policy);
        }
    }

    #[tokio::test]
    async fn dmarc_verify_report_address() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new().with_txt(
            "example.org._report._dmarc.external.org.",
            Dmarc::parse(b"v=DMARC1").unwrap(),
            Instant::now() + Duration::new(3200, 0),
        );
        let uris = vec![
            URI::new("dmarc@example.org", 0),
            URI::new("dmarc@external.org", 0),
            URI::new("domain@other.org", 0),
        ];

        assert_eq!(
            resolver
                .verify_dmarc_report_address("example.org", &uris, Some(&caches.txt))
                .await
                .unwrap(),
            vec![
                &URI::new("dmarc@example.org", 0),
                &URI::new("dmarc@external.org", 0),
            ]
        );
    }
}
