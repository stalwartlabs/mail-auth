/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::DmarcParameters;
use crate::{
    AuthenticatedMessage, DkimOutput, DkimResult, DmarcResult, DnsError, Error,
    MessageAuthenticator, SpfOutput, SpfResult,
    dkim::{DkimError, Signature},
    dmarc::{DmarcRecord, Policy, Uri},
    dns::cache::test::DummyCaches,
    parse::TxtRecordParser,
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
        mail_from_domain,
        signature_domain,
        dkim,
        spf,
        expect_dkim,
        expect_spf,
        policy,
    ) in [
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
        (
            "_dmarc.xn--eebajf.xn--9dbq2a.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@xn--eebajf.xn--9dbq2a",
            "From: hello@\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\r\n\r\n",
            "xn--eebajf.xn--9dbq2a",
            "xn--eebajf.xn--9dbq2a",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.xn--eebajf.xn--9dbq2a.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@xn--eebajf.xn--9dbq2a",
            "From: hello@xn--eebajf.xn--9dbq2a\r\n\r\n",
            "\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            "\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            DkimResult::Pass,
            SpfResult::Pass,
            DmarcResult::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
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
            DmarcRecord::parse(dmarc.as_bytes()).unwrap(),
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
            domain: mail_from_domain.to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        let result = resolver
            .verify_dmarc(caches.parameters(DmarcParameters::new(
                &auth_message,
                &[dkim],
                mail_from_domain,
                &spf,
            )))
            .await;
        assert_eq!(result.dkim_result, expect_dkim, "dkim {message}");
        assert_eq!(result.spf_result, expect_spf, "spf {message}");
        assert_eq!(result.policy, policy, "policy {message}");
        let expect_result = if expect_dkim == DmarcResult::Pass || expect_spf == DmarcResult::Pass {
            DmarcResult::Pass
        } else {
            DmarcResult::Fail(Error::NotAligned)
        };
        assert_eq!(result.result(), expect_result, "result {message}");
    }
}

#[tokio::test]
async fn dmarc_policy_discovery() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let expires = Instant::now() + Duration::new(3200, 0);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@example.org").await,
        Policy::Reject,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    assert_eq!(
        policy_of(&resolver, &caches, "hello@sub.example.org").await,
        Policy::Quarantine,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; sp=quarantine; np=none").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@ghost.example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; rua=mailto:d@example.org").unwrap(),
        expires,
    );
    assert_eq!(
        policy_of(&resolver, &caches, "hello@example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; sp=reject; rua=mailto:d@example.org").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    assert_eq!(
        policy_of(&resolver, &caches, "hello@sub.example.org").await,
        Policy::None,
    );

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; sp=reject; np=reject").unwrap(),
        expires,
    );
    caches.ipv4_add("sub.example.org.", vec![[127, 0, 0, 1].into()], expires);
    let result = verify(&resolver, &caches, "hello@sub.example.org").await;
    assert_eq!(result.record(), None);
    assert_eq!(result.result(), DmarcResult::None);

    let caches = DummyCaches::new();
    let result = verify(&resolver, &caches, "hello@nothing.example").await;
    assert_eq!(result.record(), None);
    assert_eq!(result.result(), DmarcResult::None);
}

#[tokio::test]
async fn dmarc_verify_temp_errors() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(
            b"v=DMARC1; p=reject; rua=mailto:d@example.org; ruf=mailto:f@example.org",
        )
        .unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );
    let dns_error = Error::Dns(DnsError::Resolver("timeout".to_string()));
    let empty_dns_error = Error::Dns(DnsError::Resolver(String::new()));
    let auth_message = AuthenticatedMessage::parse(b"From: hello@example.org\r\n\r\n").unwrap();

    for (mail_from_domain, spf, signature_domain, dkim, expect_spf, expect_dkim, expect) in [
        (
            "example.org",
            SpfResult::TempError,
            "example.org",
            DkimResult::Fail(Error::Dkim(DkimError::BodyHashMismatch)),
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
        ),
        (
            "other.net",
            SpfResult::TempError,
            "other.net",
            DkimResult::TempError(dns_error.clone()),
            DmarcResult::None,
            DmarcResult::None,
            DmarcResult::Fail(Error::NotAligned),
        ),
        (
            "other.net",
            SpfResult::Fail,
            "example.org",
            DkimResult::TempError(dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(dns_error.clone()),
            DmarcResult::TempError(dns_error.clone()),
        ),
        (
            "example.org",
            SpfResult::TempError,
            "example.org",
            DkimResult::Pass,
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::Pass,
            DmarcResult::Pass,
        ),
        (
            "attacker._dns_error.net",
            SpfResult::Pass,
            "attacker._dns_error.net",
            DkimResult::Pass,
            DmarcResult::Fail(Error::NotAligned),
            DmarcResult::Fail(Error::NotAligned),
            DmarcResult::Fail(Error::NotAligned),
        ),
        (
            "sub._dns_error.example.org",
            SpfResult::Pass,
            "other.net",
            DkimResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
            DmarcResult::None,
            DmarcResult::TempError(empty_dns_error.clone()),
        ),
    ] {
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
            domain: mail_from_domain.to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        let result = resolver
            .verify_dmarc(caches.parameters(DmarcParameters::new(
                &auth_message,
                &[dkim],
                mail_from_domain,
                &spf,
            )))
            .await;
        let case = format!("{mail_from_domain} {signature_domain}");
        assert_eq!(result.spf_result, expect_spf, "spf {case}");
        assert_eq!(result.dkim_result, expect_dkim, "dkim {case}");
        assert_eq!(result.result(), expect, "result {case}");
        assert_eq!(
            result.failure_report().is_none(),
            matches!(expect, DmarcResult::TempError(_) | DmarcResult::Pass),
            "failure report {case}"
        );
    }
}

#[tokio::test]
async fn dmarc_tree_walk_psd() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let expires = Instant::now() + Duration::new(3200, 0);

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.mail.example.com.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com").unwrap(),
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

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.bank.example.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; psd=y; rua=mailto:d@bank.example").unwrap(),
        expires,
    );
    caches.txt_add(
        "_dmarc.giant.bank.example.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; rua=mailto:d@giant.bank.example").unwrap(),
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

    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.com.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; np=none; rua=mailto:d@example.com").unwrap(),
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
        identity: None,
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

async fn policy_of(resolver: &MessageAuthenticator, caches: &DummyCaches, from: &str) -> Policy {
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
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "example.org",
            Dkim2Result::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=r; adkim=r; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            Dkim2Result::Pass,
            DmarcResult::Pass,
            Policy::Reject,
        ),
        (
            "_dmarc.example.org.",
            "v=DMARC1; p=reject; aspf=s; adkim=s; fo=1; rua=mailto:d@example.org",
            "From: hello@example.org\r\n\r\n",
            "subdomain.example.org",
            Dkim2Result::Pass,
            DmarcResult::Fail(Error::NotAligned),
            Policy::Reject,
        ),
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
            DmarcRecord::parse(dmarc.as_bytes()).unwrap(),
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
            identity: None,
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
        DmarcRecord::parse(b"v=DMARC1").unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );
    let uris = vec![
        Uri::new("dmarc@example.org", 0),
        Uri::new("dmarc@external.org", 0),
        Uri::new("domain@other.org", 0),
    ];

    assert_eq!(
        resolver
            .authorized_report_addresses(caches.parameters(("example.org", uris.as_slice())))
            .await
            .unwrap(),
        vec![
            &Uri::new("dmarc@example.org", 0),
            &Uri::new("dmarc@external.org", 0),
        ]
    );
}

#[tokio::test]
async fn dmarc_verify_report_address_idn() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    let uris = vec![
        Uri::new(
            "dmarc@\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
            0,
        ),
        Uri::new("dmarc@sub.xn--eebajf.xn--9dbq2a", 0),
    ];

    assert_eq!(
        resolver
            .authorized_report_addresses(
                caches.parameters(("xn--eebajf.xn--9dbq2a", uris.as_slice()))
            )
            .await
            .unwrap(),
        uris.iter().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn dmarc_alignment_is_case_insensitive() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = DummyCaches::new();
    caches.txt_add(
        "_dmarc.example.org.",
        DmarcRecord::parse(b"v=DMARC1; p=reject; aspf=s; rua=mailto:d@example.org").unwrap(),
        Instant::now() + Duration::new(3200, 0),
    );

    let result = verify_aligned(&resolver, &caches, "hello@example.org", "EXAMPLE.ORG").await;
    assert_eq!(result.spf_result(), &DmarcResult::Pass);
}
