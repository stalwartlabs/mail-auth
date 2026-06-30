/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Alignment, Dmarc};
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

pub struct DmarcParameters<'x, F>
where
    F: for<'y> Fn(&'y str) -> &'y str,
{
    pub message: &'x AuthenticatedMessage<'x>,
    pub dkim_output: &'x [DkimOutput<'x>],
    pub dkim2_output: Option<&'x Dkim2Output<'x>>,
    pub rfc5321_mail_from_domain: &'x str,
    pub spf_output: &'x SpfOutput,
    pub domain_suffix_fn: F,
}

impl MessageAuthenticator {
    /// Verifies the DMARC policy of an RFC5321.MailFrom domain
    pub async fn verify_dmarc<'x, TXT, MXX, IPV4, IPV6, PTR, F>(
        &self,
        params: impl Into<Parameters<'x, DmarcParameters<'x, F>, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> DmarcOutput
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
        F: for<'y> Fn(&'y str) -> &'y str,
    {
        // Extract RFC5322.From domain
        let params = params.into();
        let message = params.params.message;
        let dkim_output = params.params.dkim_output;
        let dkim2_output = params.params.dkim2_output;
        let domain_suffix_fn = params.params.domain_suffix_fn;
        let rfc5321_mail_from_domain = params.params.rfc5321_mail_from_domain;
        let spf_output = params.params.spf_output;
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

        // Obtain DMARC policy
        let dmarc = match self
            .dmarc_tree_walk(rfc5322_from_domain, params.cache_txt)
            .await
        {
            Ok(Some(dmarc)) => dmarc,
            Ok(None) => return DmarcOutput::default().with_domain(rfc5322_from_domain),
            Err(err) => {
                let err = DmarcResult::from(err);
                return DmarcOutput::default()
                    .with_domain(rfc5322_from_domain)
                    .with_dkim_result(err.clone())
                    .with_spf_result(err);
            }
        };

        let mut output = DmarcOutput {
            spf_result: DmarcResult::None,
            dkim_result: DmarcResult::None,
            domain: rfc5322_from_domain.to_string(),
            policy: dmarc.p,
            record: None,
        };

        let dkim_pass_domains = dkim_output
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
            .collect::<Vec<_>>();

        let has_dkim_pass = !dkim_pass_domains.is_empty();
        if spf_output.result == SpfResult::Pass || has_dkim_pass {
            // Check SPF alignment
            let rfc5322_from_subdomain = domain_suffix_fn(rfc5322_from_domain);
            if spf_output.result == SpfResult::Pass {
                output.spf_result = if rfc5321_mail_from_domain == rfc5322_from_domain {
                    DmarcResult::Pass
                } else if dmarc.aspf == Alignment::Relaxed
                    && domain_suffix_fn(rfc5321_mail_from_domain) == rfc5322_from_subdomain
                {
                    output.policy = dmarc.sp;
                    DmarcResult::Pass
                } else {
                    DmarcResult::Fail(Error::NotAligned)
                };
            }

            // Check DKIM alignment
            if has_dkim_pass {
                output.dkim_result = if dkim_pass_domains.iter().any(|d| d.eq(&rfc5322_from_domain))
                {
                    DmarcResult::Pass
                } else if dmarc.adkim == Alignment::Relaxed
                    && dkim_pass_domains
                        .iter()
                        .any(|&d| domain_suffix_fn(d) == rfc5322_from_subdomain)
                {
                    output.policy = dmarc.sp;
                    DmarcResult::Pass
                } else {
                    if dkim_pass_domains
                        .iter()
                        .any(|&d| domain_suffix_fn(d) == rfc5322_from_subdomain)
                    {
                        output.policy = dmarc.sp;
                    }
                    DmarcResult::Fail(Error::NotAligned)
                };
            }
        }

        output.with_record(dmarc)
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
            if address_ref.ends_with(domain)
                || match self
                    .txt_lookup::<Dmarc>(
                        format!(
                            "{}._report._dmarc.{}.",
                            domain,
                            address_ref
                                .rsplit_once('@')
                                .map(|(_, d)| d)
                                .unwrap_or_default()
                        ),
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

    async fn dmarc_tree_walk(
        &self,
        domain: &str,
        txt_cache: Option<&impl ResolverCache<Box<str>, Txt>>,
    ) -> crate::Result<Option<Arc<Dmarc>>> {
        let labels = domain.split('.').collect::<Vec<_>>();
        let mut x = labels.len();
        if x == 1 {
            return Ok(None);
        }
        while x != 0 {
            // Build query domain
            let mut domain = String::with_capacity(domain.len() + 8);
            domain.push_str("_dmarc");
            for label in labels.iter().skip(labels.len() - x) {
                domain.push('.');
                domain.push_str(label);
            }
            domain.push('.');

            // Query DMARC
            match self.txt_lookup::<Dmarc>(domain, txt_cache).await {
                Ok(dmarc) => {
                    return Ok(Some(dmarc));
                }
                Err(Error::Dns(DnsError::RecordNotFound(_)))
                | Err(Error::Dns(DnsError::InvalidRecordType)) => (),
                Err(err) => return Err(err),
            }

            // If x < 5, remove the left-most (highest-numbered) label from the subject domain.
            // If x >= 5, remove the left-most (highest-numbered) labels from the subject
            // domain until 4 labels remain.
            if x < 5 {
                x -= 1;
            } else {
                x = 4;
            }
        }

        Ok(None)
    }
}

impl<'x> DmarcParameters<'x, fn(&str) -> &str> {
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
            domain_suffix_fn: |d| d,
        }
    }
}

impl<'x, F> DmarcParameters<'x, F>
where
    F: for<'y> Fn(&'y str) -> &'y str,
{
    pub fn with_dkim2_output(mut self, dkim2_output: &'x Dkim2Output<'x>) -> Self {
        self.dkim2_output = Some(dkim2_output);
        self
    }

    pub fn with_domain_suffix_fn<NewF>(self, f: NewF) -> DmarcParameters<'x, NewF>
    where
        NewF: for<'y> Fn(&'y str) -> &'y str,
    {
        DmarcParameters {
            message: self.message,
            dkim_output: self.dkim_output,
            dkim2_output: self.dkim2_output,
            rfc5321_mail_from_domain: self.rfc5321_mail_from_domain,
            spf_output: self.spf_output,
            domain_suffix_fn: f,
        }
    }
}

impl<'x, F> From<DmarcParameters<'x, F>>
    for Parameters<
        'x,
        DmarcParameters<'x, F>,
        NoCache<Box<str>, Txt>,
        NoCache<Box<str>, RecordSet<MX>>,
        NoCache<Box<str>, RecordSet<Ipv4Addr>>,
        NoCache<Box<str>, RecordSet<Ipv6Addr>>,
        NoCache<IpAddr, RecordSet<Box<str>>>,
    >
where
    F: for<'y> Fn(&'y str) -> &'y str,
{
    fn from(params: DmarcParameters<'x, F>) -> Self {
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
    async fn dmarc_verify() {
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
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@example.org\r\n\r\n",
                "example.org",
                "example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Relaxed - Pass
            (
                "_dmarc.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=r; adkim=r; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                "subdomain.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Quarantine,
            ),
            // Strict - Fail
            (
                "_dmarc.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                "subdomain.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Fail(Error::NotAligned),
                DmarcResult::Fail(Error::NotAligned),
                Policy::Quarantine,
            ),
            // Strict - Pass with tree walk
            (
                "_dmarc.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@a.b.c.example.org\r\n\r\n",
                "a.b.c.example.org",
                "a.b.c.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Relaxed - Pass with tree walk
            (
                "_dmarc.c.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=r; adkim=r; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@a.b.c.example.org\r\n\r\n",
                "example.org",
                "example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Quarantine,
            ),
            // Relaxed - Pass with tree walk and different subdomains
            (
                "_dmarc.c.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=r; adkim=r; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
                "From: hello@a.b.c.example.org\r\n\r\n",
                "z.example.org",
                "z.example.org",
                DkimResult::Pass,
                SpfResult::Pass,
                DmarcResult::Pass,
                DmarcResult::Pass,
                Policy::Quarantine,
            ),
            // Failed mechanisms
            (
                "_dmarc.example.org.",
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                    "rua=mailto:dmarc-feedback@example.org"
                ),
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
            assert_eq!(
                auth_message,
                AuthenticatedMessage::from_parsed(
                    &MessageParser::new().parse(message).unwrap(),
                    true
                )
            );
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
                .verify_dmarc(
                    caches.parameters(
                        DmarcParameters::new(
                            &auth_message,
                            &[dkim],
                            rfc5321_mail_from_domain,
                            &spf,
                        )
                        .with_domain_suffix_fn(|d| psl::domain_str(d).unwrap_or(d)),
                    ),
                )
                .await;
            assert_eq!(result.dkim_result, expect_dkim);
            assert_eq!(result.spf_result, expect_spf);
            assert_eq!(result.policy, policy);
        }
    }

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
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                "From: hello@example.org\r\n\r\n",
                "example.org",
                Dkim2Result::Pass,
                DmarcResult::Pass,
                Policy::Reject,
            ),
            // Relaxed - Pass on organizational domain
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=r; adkim=r; fo=1;",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                Dkim2Result::Pass,
                DmarcResult::Pass,
                Policy::Quarantine,
            ),
            // Strict - Fail (subdomain does not match exactly)
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                "From: hello@example.org\r\n\r\n",
                "subdomain.example.org",
                Dkim2Result::Pass,
                DmarcResult::Fail(Error::NotAligned),
                Policy::Quarantine,
            ),
            // Chain did not verify - no DKIM alignment
            (
                "_dmarc.example.org.",
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
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
                            .with_dkim2_output(&dkim2)
                            .with_domain_suffix_fn(|d| psl::domain_str(d).unwrap_or(d)),
                    ),
                )
                .await;
            assert_eq!(result.dkim_result, expect_dkim);
            assert_eq!(result.policy, policy);
        }

        caches.txt_add(
            "_dmarc.example.org.",
            Dmarc::parse(b"v=DMARC1; p=reject; aspf=s; adkim=s; fo=1;").unwrap(),
            Instant::now() + Duration::new(3200, 0),
        );
        let auth_message = AuthenticatedMessage::parse(b"From: hello@example.org\r\n\r\n").unwrap();
        let originator = Dkim2Signature {
            i: 1,
            d: "other.org".into(),
            ..Default::default()
        };
        let forwarder = Dkim2Signature {
            i: 2,
            d: "example.org".into(),
            ..Default::default()
        };
        let link = |signature| ChainLink {
            signature,
            instance: None,
            result: Dkim2Result::Pass,
            custody_ok: true,
        };
        let dkim2 = Dkim2Output {
            result: Dkim2Result::Pass,
            chain: vec![link(&originator), link(&forwarder)],
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
                        .with_dkim2_output(&dkim2)
                        .with_domain_suffix_fn(|d| psl::domain_str(d).unwrap_or(d)),
                ),
            )
            .await;
        assert_eq!(result.dkim_result, DmarcResult::Fail(Error::NotAligned));
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
