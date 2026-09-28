/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Envelope, MAX_CHAIN_LENGTH, flag_violation};
use crate::dkim2::{ChainBinding, Dkim2Signed};
use crate::{
    AuthenticatedMessage, Dkim2Result, Error, MessageAuthenticator,
    crypto::HashAlgorithm,
    dkim::DomainKey,
    dkim2::{Dkim2Error, Flag, MessageHash, MessageInstance, Signature},
    dns::cache::test::DummyCaches,
    headers::Header,
    parse::TxtRecordParser,
};

fn wrap_sigs(s: &[Signature]) -> Vec<Header<'static, Signature>> {
    s.iter()
        .map(|x| Header::new(b"".as_slice(), b"".as_slice(), x.clone()))
        .collect()
}

fn wrap_mis(m: &[MessageInstance]) -> Vec<Header<'static, MessageInstance>> {
    m.iter()
        .map(|x| Header::new(b"".as_slice(), b"".as_slice(), x.clone()))
        .collect()
}

#[test]
fn flag_violation_single_pass() {
    let alg = HashAlgorithm::Sha256;
    let mi = |m: u32, h: &[u8]| MessageInstance {
        m,
        hashes: vec![MessageHash {
            name: Some(alg),
            header_hash: h.to_vec(),
            body_hash: h.to_vec(),
        }],
        recipe: None,
    };
    let sig = |i: u32, m: u32, flags: Vec<Flag>| Signature {
        i,
        m,
        flags,
        ..Default::default()
    };

    let changed = [mi(1, b"a"), mi(2, b"b")];
    let unchanged = [mi(1, b"a")];

    let donotmodify = [sig(1, 1, vec![Flag::DoNotModify]), sig(2, 2, vec![])];
    assert_eq!(
        flag_violation(&wrap_sigs(&donotmodify), &wrap_mis(&changed), alg),
        Some(Dkim2Error::Modified)
    );
    assert_eq!(
        flag_violation(&wrap_sigs(&donotmodify[..1]), &wrap_mis(&unchanged), alg),
        None
    );

    let explode = [
        sig(1, 1, vec![Flag::DoNotExplode]),
        sig(2, 1, vec![Flag::Exploded]),
    ];
    assert_eq!(
        flag_violation(&wrap_sigs(&explode), &wrap_mis(&unchanged), alg),
        Some(Dkim2Error::Exploded)
    );
    let explode_before = [
        sig(1, 1, vec![Flag::Exploded]),
        sig(2, 1, vec![Flag::DoNotExplode]),
    ];
    assert_eq!(
        flag_violation(&wrap_sigs(&explode_before), &wrap_mis(&unchanged), alg),
        None
    );
}
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

const NOW: u64 = 1740002100;

fn resource(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources/dkim2");
    for part in parts {
        path.push(part);
    }
    path
}

fn load_caches() -> DummyCaches {
    let caches = DummyCaches::new();
    let dns = std::fs::read(resource(&["dns.json"])).unwrap();
    let dns: serde_json::Value = serde_json::from_slice(&dns).unwrap();
    let valid_until = Instant::now() + Duration::new(3600, 0);
    for (domain, selectors) in dns.as_object().unwrap() {
        for (selector, records) in selectors.as_object().unwrap() {
            let record = records[0][1].as_str().unwrap();
            let name = format!("{selector}.{domain}.");
            caches.txt_add(
                name,
                DomainKey::parse(record.as_bytes()).unwrap(),
                valid_until,
            );
        }
    }
    caches
}

async fn verify_file<A, R>(
    resolver: &MessageAuthenticator,
    caches: &DummyCaches,
    name: &str,
    envelope: Envelope<A, R>,
) -> Dkim2Result
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    let raw = std::fs::read(resource(&["expected", name])).unwrap();
    let message = AuthenticatedMessage::parse(&raw).unwrap();
    let params = caches.parameters(&message);
    resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await
        .result()
        .clone()
}

fn top_envelope(name: &str) -> (String, Vec<String>) {
    let raw = std::fs::read(resource(&["expected", name])).unwrap();
    let message = AuthenticatedMessage::parse(&raw).unwrap();
    let top = message
        .dkim2_signatures
        .iter()
        .map(|h| &h.header)
        .max_by_key(|s| s.i)
        .unwrap();
    match &top.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => (mail_from.clone(), rcpt_to.clone()),
        ChainBinding::NextDomain(_) => panic!("top signature has nd="),
    }
}

#[tokio::test]
async fn verify_golden_vectors() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();

    verify_pass_list(
        &resolver,
        &caches,
        &[
            "simple-ed25519.eml",
            "simple-rsa2048.eml",
            "simple-sel2.eml",
            "simple-sel3.eml",
            "multiheader-ed25519.eml",
            "trailingblank-ed25519.eml",
            "emptybody-ed25519.eml",
            "multirecipient-ed25519.eml",
            "dsn-ed25519.eml",
            "dupheaders-ed25519.eml",
        ],
    )
    .await;

    let _lenient = super::test_reverse_path::LenientReversePath::new();
    verify_pass_list(
        &resolver,
        &caches,
        &[
            "simple-rsa1024.eml",
            "multihop-header-add.eml",
            "multihop-body-footer.eml",
            "multihop-header-replace.eml",
            "multihop-dup-headers.eml",
            "multihop-3hop-dup-headers.eml",
        ],
    )
    .await;
}

async fn verify_pass_list(resolver: &MessageAuthenticator, caches: &DummyCaches, names: &[&str]) {
    for &name in names {
        let (mail_from, rcpt_to) = top_envelope(name);
        let result = verify_file(resolver, caches, name, Envelope::new(&mail_from, &rcpt_to)).await;
        assert_eq!(result, Dkim2Result::Pass, "vector {name}");
    }
}

fn prepend(signed: &Dkim2Signed, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 512);
    signed.write(&mut out);
    out.extend_from_slice(message);
    out
}

#[tokio::test]
async fn sign_then_verify_multi_hop() {
    use crate::{
        crypto::Ed25519Key,
        dkim2::{Dkim2Signer, Envelope, Hop},
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

    let load = |domain: &str, selector: &str| {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    };

    let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();

    let hop1 = Dkim2Signer::from_key(load("test1.dkim2.com", "ed25519"))
        .domain("test1.dkim2.com")
        .selector("ed25519");
    let sign1 = hop1
        .sign(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
        )
        .unwrap();
    let message1 = prepend(&sign1, &original);

    let hop2 = Dkim2Signer::from_key(load("test2.dkim2.com", "ed25519"))
        .domain("test2.dkim2.com")
        .selector("ed25519");
    let sign2 = hop2
        .sign(
            &message1,
            Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
        )
        .unwrap();
    let message2 = prepend(&sign2, &message1);

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let message = AuthenticatedMessage::parse(&message2).unwrap();
    let params = caches.parameters(&message);
    let envelope = Envelope::new("relay@test2.dkim2.com", ["recipient@example.com"]);
    let output = resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await;
    assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
    assert_eq!(output.chain().len(), 2);
}

/// test1 delivers to test2, which hands the message to test3 without an SMTP
/// transaction; test3 then delivers to example.com.
#[tokio::test]
async fn sign_then_verify_imaginary_hop() {
    use crate::{
        crypto::Ed25519Key,
        dkim2::{Dkim2Signer, Envelope, Hop},
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

    let load = |domain: &str| {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("ed25519._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    };
    let signer = |domain: &'static str| {
        Dkim2Signer::from_key(load(domain))
            .domain(domain)
            .selector("ed25519")
    };

    let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();
    let sign1 = signer("test1.dkim2.com")
        .sign(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
        )
        .unwrap();
    let message1 = prepend(&sign1, &original);

    let sign2 = signer("test2.dkim2.com")
        .sign(&message1, Hop::imaginary("test3.dkim2.com"))
        .unwrap();
    let message2 = prepend(&sign2, &message1);
    assert!(matches!(sign2.signature.chain, ChainBinding::NextDomain(_)));

    let sign3 = signer("test3.dkim2.com")
        .sign(
            &message2,
            Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
        )
        .unwrap();
    let message3 = prepend(&sign3, &message2);

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let message = AuthenticatedMessage::parse(&message3).unwrap();
    let params = caches.parameters(&message);
    let envelope = Envelope::new("relay@test3.dkim2.com", ["recipient@example.com"]);
    let output = resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await;
    assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
    assert_eq!(output.chain().len(), 3);
}

/// test4 was never a recipient of the previous hop, so its `nd=` signature
/// does not continue the chain of custody.
#[tokio::test]
async fn verify_rejects_imaginary_hop_outside_custody() {
    use crate::{
        crypto::Ed25519Key,
        dkim2::{Dkim2Signer, Envelope, Hop},
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

    let load = |domain: &str| {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("ed25519._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    };
    let signer = |domain: &'static str| {
        Dkim2Signer::from_key(load(domain))
            .domain(domain)
            .selector("ed25519")
    };

    let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();
    let sign1 = signer("test1.dkim2.com")
        .sign(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
        )
        .unwrap();
    let message1 = prepend(&sign1, &original);

    let sign2 = signer("test4.dkim2.com")
        .sign(&message1, Hop::imaginary("test3.dkim2.com"))
        .unwrap();
    let message2 = prepend(&sign2, &message1);

    let sign3 = signer("test3.dkim2.com")
        .sign(
            &message2,
            Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
        )
        .unwrap();
    let message3 = prepend(&sign3, &message2);

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let message = AuthenticatedMessage::parse(&message3).unwrap();
    let params = caches.parameters(&message);
    let envelope = Envelope::new("relay@test3.dkim2.com", ["recipient@example.com"]);
    let result = resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await;

    assert_eq!(
        result.result(),
        &Dkim2Result::PermError(Error::Dkim2(Dkim2Error::CustodyBreak(2))),
        "{:?}",
        result.error()
    );
}

#[tokio::test]
async fn sign_multi_algorithm_then_verify() {
    use crate::{
        crypto::{Algorithm, Ed25519Key, RsaKey, Sha256},
        dkim2::{Dkim2Signer, Envelope, Hop},
    };
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

    let load_ed = |domain: &str, selector: &str| {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
            panic!("expected PKCS8 key");
        };
        Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
    };
    let load_rsa = |domain: &str, selector: &str| {
        let pem = std::fs::read(resource(&[
            "keys",
            &format!("{selector}._domainkey.{domain}.pem"),
        ]))
        .unwrap();
        RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(&pem).unwrap()).unwrap()
    };

    let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();

    let signed = Dkim2Signer::from_key(load_ed("test1.dkim2.com", "ed25519"))
        .domain("test1.dkim2.com")
        .selector("ed25519")
        .additional_key(load_rsa("test1.dkim2.com", "sel1"), "sel1")
        .sign(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
        )
        .unwrap();

    assert_eq!(signed.signature.s.len(), 2);
    assert_eq!(signed.signature.s[0].selector, "ed25519");
    assert_eq!(signed.signature.s[0].a, Algorithm::Ed25519Sha256);
    assert_eq!(signed.signature.s[1].selector, "sel1");
    assert_eq!(signed.signature.s[1].a, Algorithm::RsaSha256);

    let message = prepend(&signed, &original);
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let parsed = AuthenticatedMessage::parse(&message).unwrap();
    let params = caches.parameters(&parsed);
    let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
    let output = resolver
        .verify_dkim2_(&parsed, envelope, params.txt_cache(), NOW, true)
        .await;
    assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
}

#[tokio::test]
async fn verify_rejects_wrong_envelope() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let envelope = Envelope::new("attacker@evil.example", ["recipient@example.com"]);
    let result = verify_file(&resolver, &caches, "simple-ed25519.eml", envelope).await;
    assert!(
        matches!(result, Dkim2Result::PermError(_)),
        "got {result:?}"
    );
}

#[tokio::test]
async fn verify_rejects_long_chains() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();

    for (count, expect_too_long) in [
        (MAX_CHAIN_LENGTH, false),
        (MAX_CHAIN_LENGTH + 1, true),
        (MAX_CHAIN_LENGTH * 4, true),
    ] {
        let mut raw = Vec::new();
        for i in 1..=count {
            raw.extend_from_slice(
                format!(
                    "DKIM2-Signature: i={i}; m={i}; t={NOW}; d=ex{i}.com; nd=ex{}.com; \
                         s=sel:rsa-sha256:QQ==;\r\n",
                    i + 1
                )
                .as_bytes(),
            );
        }
        raw.extend_from_slice(b"From: sender@test1.dkim2.com\r\n\r\nHello\r\n");

        let message = AuthenticatedMessage::parse(&raw).unwrap();
        assert_eq!(message.dkim2_signatures.len(), count);

        let params = caches.parameters(&message);
        let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
        let result = resolver
            .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
            .await;

        assert_eq!(
            matches!(
                result.result(),
                Dkim2Result::PermError(Error::Dkim2(Dkim2Error::ChainTooLong))
            ),
            expect_too_long,
            "count={count} got {:?}",
            result.result()
        );
    }
}

#[tokio::test]
async fn verify_rejects_tampered_body() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let raw = std::fs::read(resource(&["expected", "simple-ed25519.eml"])).unwrap();
    let mut tampered = raw.clone();
    let pos = tampered.windows(5).position(|w| w == b"Hello").unwrap();
    tampered[pos] = b'J';
    let message = AuthenticatedMessage::parse(&tampered).unwrap();
    let params = caches.parameters(&message);
    let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
    let result = resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await;
    assert!(
        matches!(result.result(), Dkim2Result::Fail(_)),
        "got {:?}",
        result.result()
    );
}

#[tokio::test]
async fn verify_rejects_tampered_header() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let raw = std::fs::read(resource(&["expected", "simple-ed25519.eml"])).unwrap();
    let mut tampered = raw.clone();
    let pos = tampered.windows(6).position(|w| w == b"Simple").unwrap();
    tampered[pos] = b'X';
    let message = AuthenticatedMessage::parse(&tampered).unwrap();
    let params = caches.parameters(&message);
    let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
    let result = resolver
        .verify_dkim2_(&message, envelope, params.txt_cache(), NOW, true)
        .await;
    assert!(
        matches!(
            result.result(),
            Dkim2Result::Fail(Error::Dkim2(Dkim2Error::HeaderHashMismatch(_)))
        ),
        "got {:?}",
        result.result()
    );
}

#[tokio::test]
async fn verify_rejects_rcpt_not_in_rt() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let envelope = Envelope::new("sender@test1.dkim2.com", ["someone-else@example.com"]);
    let result = verify_file(&resolver, &caches, "simple-ed25519.eml", envelope).await;
    assert!(
        matches!(
            result,
            Dkim2Result::PermError(Error::Dkim2(Dkim2Error::RcptToMismatch(_)))
        ),
        "got {result:?}"
    );
}

fn state_matches(expected: &str, result: &Dkim2Result) -> bool {
    match expected {
        "pass" => matches!(result, Dkim2Result::Pass),
        "fail" => matches!(result, Dkim2Result::Fail(_)),
        "permerror" => matches!(result, Dkim2Result::PermError(_)),
        "temperror" => matches!(result, Dkim2Result::TempError(_)),
        other => panic!("unknown expected state {other}"),
    }
}

#[tokio::test]
async fn test_vectors() {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();

    let cases = std::fs::read(resource(&["cases.json"])).unwrap();
    let cases: serde_json::Value = serde_json::from_slice(&cases).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(!cases.is_empty(), "no imported vectors found");

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let file = case["file"].as_str().unwrap();
        let mail_from = case["mail_from"].as_str().unwrap().to_string();
        let rcpt_to: Vec<String> = case["rcpt_to"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();

        let now = case["now"]
            .as_u64()
            .expect("vector manifest must carry now");
        let strict = case["strict"].as_bool().unwrap_or(true);

        let raw = std::fs::read(resource(&["expected", file])).unwrap();
        let Some(message) = AuthenticatedMessage::parse(&raw) else {
            failures.push(format!("{name}: message failed to parse"));
            continue;
        };
        let params = caches.parameters(&message);
        let envelope = Envelope::new(&mail_from, &rcpt_to);
        let lenient = (!strict).then(super::test_reverse_path::LenientReversePath::new);
        let output = resolver
            .verify_dkim2_(&message, envelope, params.txt_cache(), now, true)
            .await;
        drop(lenient);
        if !state_matches(expected, output.result()) {
            failures.push(format!(
                "{name}: expected {expected}, got {:?} ({:?})",
                output.result(),
                output.error()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors diverged:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
