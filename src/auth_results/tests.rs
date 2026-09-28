/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#[cfg(feature = "arc")]
use crate::{ArcOutput, arc::ArcError};
use crate::{
    AuthenticationResults, DkimOutput, DkimResult, DmarcOutput, DmarcResult, DnsError, Error,
    IprevOutput, IprevResult, ReceivedSpf, SpfOutput, SpfResult,
    crypto::CryptoError,
    dkim::Signature,
    dmarc::{DmarcRecord, Policy},
    parse::TxtRecordParser,
    spf::verify::SpfParameters,
};
use std::sync::Arc;

#[test]
fn authentication_results() {
    let mut auth_results = AuthenticationResults::new("mydomain.org");

    for (expected_auth_results, dkim) in [
        (
            "dkim=pass header.d=example.org header.s=myselector",
            DkimOutput {
                result: DkimResult::Pass,
                signature: (&Signature {
                    d: "example.org".into(),
                    s: "myselector".into(),
                    ..Default::default()
                })
                    .into(),
                report: None,
                is_atps: false,
            },
        ),
        (
            concat!(
                "dkim=fail (verification failed) header.d=example.org ",
                "header.s=myselector header.b=MTIzNDU2"
            ),
            DkimOutput {
                result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
                signature: (&Signature {
                    d: "example.org".into(),
                    s: "myselector".into(),
                    b: b"123456".to_vec(),
                    ..Default::default()
                })
                    .into(),
                report: None,
                is_atps: false,
            },
        ),
        (
            concat!(
                "dkim-atps=temperror (dns error) header.d=atps.example.org ",
                "header.s=otherselctor header.b=YWJjZGVm header.from=jdoe@example.org"
            ),
            DkimOutput {
                result: DkimResult::TempError(Error::Dns(DnsError::Resolver("".to_string()))),
                signature: (&Signature {
                    d: "atps.example.org".into(),
                    s: "otherselctor".into(),
                    b: b"abcdef".to_vec(),
                    ..Default::default()
                })
                    .into(),
                report: None,
                is_atps: true,
            },
        ),
    ] {
        auth_results = auth_results.with_dkim_results(&[dkim], "jdoe@example.org");
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected_auth_results
        );
    }

    for (
        expected_auth_results,
        expected_received_spf,
        result,
        ip_addr,
        receiver,
        helo,
        mail_from,
    ) in [
        (
            concat!(
                "spf=pass (localhost: domain of jdoe@example.org designates 192.168.1.1 ",
                "as permitted sender) smtp.mailfrom=jdoe@example.org"
            ),
            concat!(
                "pass (localhost: domain of jdoe@example.org designates 192.168.1.1 as ",
                "permitted sender)\r\n\treceiver=localhost; client-ip=192.168.1.1; ",
                "envelope-from=\"jdoe@example.org\"; helo=example.org;"
            ),
            SpfResult::Pass,
            "192.168.1.1".parse().unwrap(),
            "localhost",
            "example.org",
            "jdoe@example.org",
        ),
        (
            concat!(
                "spf=fail (mx.domain.org: domain of sender@otherdomain.org does not ",
                "designate a:b:c::f as permitted sender) smtp.mailfrom=sender@otherdomain.org"
            ),
            concat!(
                "fail (mx.domain.org: domain of sender@otherdomain.org does not designate ",
                "a:b:c::f as permitted sender)\r\n\treceiver=mx.domain.org; ",
                "client-ip=a:b:c::f; envelope-from=\"sender@otherdomain.org\"; ",
                "helo=otherdomain.org;"
            ),
            SpfResult::Fail,
            "a:b:c::f".parse().unwrap(),
            "mx.domain.org",
            "otherdomain.org",
            "sender@otherdomain.org",
        ),
        (
            concat!(
                "spf=neutral (mx.domain.org: domain of postmaster@example.org reports neutral ",
                "for a:b:c::f) smtp.mailfrom=<>"
            ),
            concat!(
                "neutral (mx.domain.org: domain of postmaster@example.org reports neutral for ",
                "a:b:c::f)\r\n\treceiver=mx.domain.org; client-ip=a:b:c::f; ",
                "envelope-from=\"postmaster@example.org\"; helo=example.org;"
            ),
            SpfResult::Neutral,
            "a:b:c::f".parse().unwrap(),
            "mx.domain.org",
            "example.org",
            "",
        ),
    ] {
        auth_results.hostname = receiver;
        let params = SpfParameters::mail_from(ip_addr, helo, receiver, mail_from);
        let output = SpfOutput {
            result,
            domain: "".to_string(),
            report: None,
            explanation: None,
            identity: None,
        };
        auth_results = auth_results.with_spf_result(&output, &params);
        let received_spf = ReceivedSpf::new(&output, &params);
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected_auth_results
        );
        assert_eq!(received_spf.received_spf, expected_received_spf);
    }

    for (expected_auth_results, dmarc) in [
        (
            "dmarc=pass header.from=example.org policy.dmarc=none",
            DmarcOutput {
                spf_result: DmarcResult::Pass,
                dkim_result: DmarcResult::None,
                domain: "example.org".to_string(),
                policy: Policy::None,
                record: None,
            },
        ),
        (
            "dmarc=fail (policy not aligned) header.from=example.com policy.dmarc=quarantine",
            DmarcOutput {
                dkim_result: DmarcResult::Fail(Error::NotAligned),
                spf_result: DmarcResult::None,
                domain: "example.com".to_string(),
                policy: Policy::Quarantine,
                record: None,
            },
        ),
        (
            "dmarc=fail (policy not aligned) header.from=example.net policy.dmarc=reject",
            DmarcOutput {
                dkim_result: DmarcResult::None,
                spf_result: DmarcResult::None,
                domain: "example.net".to_string(),
                policy: Policy::Reject,
                record: Some(Arc::new(DmarcRecord::parse(b"v=DMARC1; p=reject").unwrap())),
            },
        ),
        (
            "dmarc=none header.from=example.net policy.dmarc=none",
            DmarcOutput {
                dkim_result: DmarcResult::None,
                spf_result: DmarcResult::None,
                domain: "example.net".to_string(),
                policy: Policy::None,
                record: None,
            },
        ),
    ] {
        auth_results = auth_results.with_dmarc_result(&dmarc);
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected_auth_results
        );
    }

    #[cfg(feature = "arc")]
    for (expected_auth_results, arc, remote_ip) in [
        (
            "arc=pass smtp.remote-ip=192.127.9.2",
            DkimResult::Pass,
            "192.127.9.2".parse().unwrap(),
        ),
        (
            "arc=neutral (body hash did not verify) smtp.remote-ip=\"1:2:3::a\"",
            DkimResult::Neutral(Error::Arc(ArcError::BodyHashMismatch)),
            "1:2:3::a".parse().unwrap(),
        ),
    ] {
        auth_results = auth_results.with_arc_result(
            &ArcOutput {
                result: arc,
                set: vec![],
            },
            remote_ip,
        );
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected_auth_results
        );
    }

    for (expected_auth_results, iprev, remote_ip) in [
        (
            "iprev=pass policy.iprev=192.127.9.2",
            IprevOutput {
                result: IprevResult::Pass,
                ptr: None,
            },
            "192.127.9.2".parse().unwrap(),
        ),
        (
            "iprev=fail (policy not aligned) policy.iprev=\"1:2:3::a\"",
            IprevOutput {
                result: IprevResult::Fail(Error::NotAligned),
                ptr: None,
            },
            "1:2:3::a".parse().unwrap(),
        ),
    ] {
        auth_results = auth_results.with_iprev_result(&iprev, remote_ip);
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected_auth_results
        );
    }
}

#[test]
fn dkim2_authentication_results() {
    use crate::{
        Dkim2Result,
        dkim2::{ChainLink, Dkim2Error, Dkim2Output, Signature as Dkim2Signature},
    };

    let originator = Dkim2Signature {
        i: 1,
        d: "example.org".into(),
        ..Default::default()
    };
    let relay = Dkim2Signature {
        i: 2,
        d: "relay.example.com".into(),
        ..Default::default()
    };

    let pass = Dkim2Output {
        result: Dkim2Result::Pass,
        chain: vec![
            ChainLink {
                signature: &originator,
                instance: None,
                result: Dkim2Result::Pass,
                custody_ok: true,
            },
            ChainLink {
                signature: &relay,
                instance: None,
                result: Dkim2Result::Pass,
                custody_ok: true,
            },
        ],
    };

    let fail = Dkim2Output {
        result: Dkim2Result::Fail(Error::Dkim2(Dkim2Error::BodyHashMismatch(2))),
        chain: vec![
            ChainLink {
                signature: &originator,
                instance: None,
                result: Dkim2Result::Pass,
                custody_ok: true,
            },
            ChainLink {
                signature: &relay,
                instance: None,
                result: Dkim2Result::Fail(Error::Dkim2(Dkim2Error::BodyHashMismatch(2))),
                custody_ok: true,
            },
        ],
    };

    let permerror: Dkim2Output =
        Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureMissing(1))).into();

    let none: Dkim2Output = Dkim2Result::None.into();

    for (expected, output) in [
        ("dkim2=pass header.d=example.org header.i=1", &pass),
        (
            concat!(
                "dkim2=fail (Message-Instance m=2 body hash mismatch) ",
                "header.d=relay.example.com header.i=2"
            ),
            &fail,
        ),
        ("dkim2=permerror (DKIM2-Signature i=1 missing)", &permerror),
        ("dkim2=none", &none),
    ] {
        let auth_results = AuthenticationResults::new("mydomain.org").with_dkim2_result(output);
        assert_eq!(
            auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
            expected
        );
    }
}

#[test]
fn dkim_result_header_injection() {
    let signature = Signature {
        i: "u@evil.test\r\nReply-To: attacker@evil.test\r\nX-Injected: yes".into(),
        d: "evil.test\r\nX-Injected-D: yes".into(),
        s: "sel\r\nX-Injected-S: yes".into(),
        b: b"123456".to_vec(),
        ..Default::default()
    };
    let output = DkimOutput {
        result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
        signature: Some(&signature),
        report: None,
        is_atps: false,
    };
    let auth_results =
        AuthenticationResults::new("mx.example.org").with_dkim_result(&output, "from@example.org");

    assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
    let value = auth_results.auth_results.split_once("header.i=").unwrap().1;
    assert!(!value.contains('\r') && !value.contains('\n'));
    assert!(value.starts_with("\"u@evil.test"));
    assert!(value.contains("Reply-To: attacker@evil.test"));
}

#[test]
fn dkim_result_header_i_quoted_local_part() {
    let signature = Signature {
        i: "a;b=c (note)\"x@example.org".into(),
        d: "example.org".into(),
        s: "sel".into(),
        ..Default::default()
    };
    let output = DkimOutput {
        result: DkimResult::Pass,
        signature: Some(&signature),
        report: None,
        is_atps: false,
    };
    let auth_results =
        AuthenticationResults::new("mx.example.org").with_dkim_result(&output, "from@example.org");
    let value = auth_results.auth_results.split_once("header.i=").unwrap().1;

    assert!(value.starts_with("\"a;b=c (note)\\\"x@example.org\""));
    assert_eq!(value.matches('"').count(), 3);
}

#[test]
fn dkim_result_header_d_injection() {
    let signature = Signature {
        d: "evil.test\r\nX-Injected: yes".into(),
        s: "sel\"; smtp.bogus=1".into(),
        ..Default::default()
    };
    let output = DkimOutput {
        result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
        signature: Some(&signature),
        report: None,
        is_atps: false,
    };
    let auth_results =
        AuthenticationResults::new("mx.example.org").with_dkim_result(&output, "from@example.org");

    assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
    let value = auth_results.auth_results.split_once("header.d=").unwrap().1;
    assert!(!value.contains('\r') && !value.contains('\n'));
    assert!(!value.contains('"') && !value.contains(';'));
}

#[test]
fn spf_result_header_injection() {
    let spf = SpfOutput {
        result: SpfResult::Pass,
        domain: String::new(),
        report: None,
        explanation: None,
        identity: None,
    };
    let auth_results = AuthenticationResults::new("mx.example.org").with_spf_result(
        &spf,
        &SpfParameters::mail_from(
            "192.168.1.1".parse().unwrap(),
            "helo.test\r\nX-Injected-Helo: yes",
            "mx.example.org",
            "a@evil.test\r\nX-Injected: yes",
        ),
    );
    assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);

    let auth_results = AuthenticationResults::new("mx.example.org").with_spf_result(
        &spf,
        &SpfParameters::helo(
            "192.168.1.1".parse().unwrap(),
            "helo.test\r\nX-Injected: yes",
            "mx.example.org",
        ),
    );
    assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
}

#[test]
fn dmarc_result_header_injection() {
    let auth_results =
        AuthenticationResults::new("mx.example.org").with_dmarc_result(&DmarcOutput {
            spf_result: DmarcResult::Pass,
            dkim_result: DmarcResult::None,
            domain: "evil.test\r\nX-Injected: yes".to_string(),
            policy: Policy::None,
            record: None,
        });
    assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
    let value = auth_results
        .auth_results
        .split_once("header.from=")
        .unwrap()
        .1;
    assert!(!value.contains('\r') && !value.contains('\n'));
}

#[test]
fn received_spf_header_injection() {
    let spf = SpfOutput {
        result: SpfResult::Pass,
        domain: String::new(),
        report: None,
        explanation: None,
        identity: None,
    };
    let received_spf = ReceivedSpf::new(
        &spf,
        &SpfParameters::mail_from(
            "192.168.1.1".parse().unwrap(),
            "helo.test\r\nX-Injected-Helo: yes",
            "mx.example.org",
            "a@evil.test\r\nX-Injected: yes\r\nReply-To: attacker@evil.test",
        ),
    );
    assert_eq!(received_spf.received_spf.matches("\r\n").count(), 1);
    assert!(
        !received_spf.received_spf.contains('"')
            || received_spf.received_spf.matches('"').count() == 2
    );
}
