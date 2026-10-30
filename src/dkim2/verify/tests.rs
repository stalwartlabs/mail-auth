/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    CanonicalizedHeaderWriter, Envelope, MAX_CHAIN_LENGTH, strip_and_canonicalize_signature,
};
use crate::dkim2::{ChainBinding, Dkim2Output, Dkim2Signed, Verification};
use crate::{
    AuthenticatedMessage, Dkim2Result, DnsError, Error, MessageAuthenticator,
    crypto::{DkimKey, Ed25519Key, MlDsa44Key, RsaKey, Sha256, SigningKey},
    dkim::{DkimError, DomainKey},
    dkim2::{Dkim2Error, Dkim2Hash, Dkim2Signer, Flag, Hop},
    dns::{TxtRecord, cache::test::DummyCaches},
    headers::Writer,
    parse::TxtRecordParser,
    signer::Ready,
};
use encodify::base64;
use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

const NOW: u64 = 1740002100;
const DAY: u64 = 86400;

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

fn pem(domain: &str, selector: &str) -> Vec<u8> {
    std::fs::read(resource(&[
        "keys",
        &format!("{selector}._domainkey.{domain}.pem"),
    ]))
    .unwrap()
}

fn pkcs8(domain: &str, selector: &str) -> Vec<u8> {
    let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem(domain, selector)).unwrap()
    else {
        panic!("expected PKCS8 key");
    };
    der.secret_pkcs8_der().to_vec()
}

fn load_ed25519(domain: &str, selector: &str) -> Ed25519Key {
    Ed25519Key::from_pkcs8_maybe_unchecked_der(&pkcs8(domain, selector)).unwrap()
}

fn load_rsa(domain: &str, selector: &str) -> RsaKey<Sha256> {
    RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(&pem(domain, selector)).unwrap())
        .unwrap()
}

fn load_mldsa() -> MlDsa44Key {
    MlDsa44Key::from_pkcs8_der(&pkcs8("test1.dkim2.com", "mldsa44")).unwrap()
}

fn signer(domain: &str) -> Dkim2Signer<Ready> {
    signer_with(load_ed25519(domain, "ed25519"), domain, "ed25519")
}

fn signer_with(key: impl Into<DkimKey>, domain: &str, selector: &str) -> Dkim2Signer<Ready> {
    Dkim2Signer::from_key(key).domain(domain).selector(selector)
}

fn prepend(signed: &Dkim2Signed, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 512);
    signed.write(&mut out);
    out.extend_from_slice(message);
    out
}

fn original() -> Vec<u8> {
    std::fs::read(resource(&["emails", "simple.eml"])).unwrap()
}

async fn verify<'x>(
    message: &'x AuthenticatedMessage<'x>,
    mail_from: &str,
    rcpt_to: &[&str],
    verification: Verification,
) -> Dkim2Output<'x> {
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let params = caches.parameters(message);
    resolver
        .verify_dkim2_(
            message,
            Envelope::new(mail_from, rcpt_to),
            params.txt_cache(),
            NOW,
            true,
            verification,
        )
        .await
}

async fn verify_raw(raw: &[u8], mail_from: &str, rcpt_to: &[&str]) -> Dkim2Result {
    let message = AuthenticatedMessage::parse(raw).unwrap();
    verify(&message, mail_from, rcpt_to, Verification::Full)
        .await
        .result()
        .clone()
}

fn perm(error: Dkim2Error) -> Dkim2Result {
    Dkim2Result::PermError(Error::Dkim2(error))
}

fn fail(error: Dkim2Error) -> Dkim2Result {
    Dkim2Result::Fail(Error::Dkim2(error))
}

async fn verify_file<A, R>(name: &str, envelope: Envelope<A, R>) -> Dkim2Result
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    let raw = std::fs::read(resource(&["expected", name])).unwrap();
    let message = AuthenticatedMessage::parse(&raw).unwrap();
    let params = caches.parameters(&message);
    resolver
        .verify_dkim2_(
            &message,
            envelope,
            params.txt_cache(),
            NOW,
            true,
            Verification::Full,
        )
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
    verify_pass_list(&[
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
        "simple-mldsa44.eml",
        "simple-sha512.eml",
        "simple-sha256-sha512.eml",
    ])
    .await;

    let _lenient = super::test_reverse_path::LenientReversePath::new();
    verify_pass_list(&[
        "simple-rsa1024.eml",
        "multihop-header-add.eml",
        "multihop-body-footer.eml",
        "multihop-header-replace.eml",
        "multihop-dup-headers.eml",
        "multihop-3hop-dup-headers.eml",
    ])
    .await;
}

async fn verify_pass_list(names: &[&str]) {
    for &name in names {
        let (mail_from, rcpt_to) = top_envelope(name);
        let result = verify_file(name, Envelope::new(&mail_from, &rcpt_to)).await;
        assert_eq!(result, Dkim2Result::Pass, "vector {name}");
    }
}

// A forwarder signs with the proof of a passing verification of the received message.
#[tokio::test]
async fn sign_then_verify_multi_hop() {
    let original = original();
    let sign1 = signer("test1.dkim2.com")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
            None,
            NOW,
        )
        .unwrap();
    let message1 = prepend(&sign1, &original);
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;
    assert_eq!(proof.result(), &Dkim2Result::Pass, "{:?}", proof.error());

    let sign2 = signer("test2.dkim2.com")
        .sign_at(
            &message1,
            Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
            Some(&proof),
            NOW,
        )
        .unwrap();
    let message2 = prepend(&sign2, &message1);
    let parsed2 = AuthenticatedMessage::parse(&message2).unwrap();
    let output = verify(
        &parsed2,
        "relay@test2.dkim2.com",
        &["recipient@example.com"],
        Verification::Full,
    )
    .await;
    assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
    assert_eq!(output.chain().len(), 2);
}

// An exploded hop sets the exploded flag on single-recipient copies, but never on i=1.
#[tokio::test]
async fn exploded_hop_flag() {
    let original = original();
    let sign1 = signer("test1.dkim2.com")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]).exploded(),
            None,
            NOW,
        )
        .unwrap();
    assert!(sign1.signature.flags.is_empty());
    let message1 = prepend(&sign1, &original);
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;
    assert_eq!(proof.result(), &Dkim2Result::Pass, "{:?}", proof.error());

    for (hop, flags) in [
        (
            Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]).exploded(),
            vec![Flag::Exploded],
        ),
        (
            Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
            vec![],
        ),
    ] {
        let sign2 = signer("test2.dkim2.com")
            .sign_at(&message1, hop, Some(&proof), NOW)
            .unwrap();
        assert_eq!(sign2.signature.flags, flags);
        let message2 = prepend(&sign2, &message1);
        let parsed2 = AuthenticatedMessage::parse(&message2).unwrap();
        let output = verify(
            &parsed2,
            "relay@test2.dkim2.com",
            &["recipient@example.com"],
            Verification::Full,
        )
        .await;
        assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
    }
    assert_eq!(
        Hop::imaginary("test3.dkim2.com").exploded(),
        Hop::imaginary("test3.dkim2.com")
    );
}

// Signing a message with DKIM2 header fields needs a passing full verification of that message.
#[tokio::test]
async fn signer_requires_validity_proof() {
    let original = original();
    let hop1 = Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]);
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(&original, hop1.clone(), None, NOW)
            .unwrap(),
        &original,
    );
    let other = prepend(
        &signer("test1.dkim2.com")
            .sign_at(&original, hop1, None, NOW + 1)
            .unwrap(),
        &original,
    );
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let parsed_other = AuthenticatedMessage::parse(&other).unwrap();
    let envelope = ("sender@test1.dkim2.com", ["list@test2.dkim2.com"]);
    let proof = verify(&parsed1, envelope.0, &envelope.1, Verification::Full).await;
    let provisional = verify(&parsed1, envelope.0, &envelope.1, Verification::Provisional).await;
    let other_proof = verify(&parsed_other, envelope.0, &envelope.1, Verification::Full).await;
    let failed = verify(
        &parsed1,
        "x@test1.dkim2.com",
        &envelope.1,
        Verification::Full,
    )
    .await;
    assert_eq!(provisional.result(), &Dkim2Result::Pass);
    assert_eq!(other_proof.result(), &Dkim2Result::Pass);

    let hop2 = || Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]);
    for (label, verified) in [
        ("none", None),
        ("provisional", Some(&provisional)),
        ("other message", Some(&other_proof)),
        ("failed", Some(&failed)),
    ] {
        assert_eq!(
            signer("test2.dkim2.com")
                .sign_at(&message1, hop2(), verified, NOW)
                .unwrap_err(),
            Error::Dkim2(Dkim2Error::NotFullyVerified),
            "{label}"
        );
    }
    signer("test2.dkim2.com")
        .sign_at(&message1, hop2(), Some(&proof), NOW)
        .unwrap();
    signer("test2.dkim2.com")
        .out_of_band_arrangement()
        .sign_at(&message1, hop2(), None, NOW)
        .unwrap();
}

// A message changed after its most recent Message-Instance cannot be signed without a new instance.
#[tokio::test]
async fn signer_detects_unrecorded_changes() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;
    let mut modified = message1.clone();
    modified.extend_from_slice(b"Footer\r\n");
    let hop2 = || Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]);

    assert_eq!(
        signer("test2.dkim2.com")
            .sign_at(&modified, hop2(), Some(&proof), NOW)
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::BodyHashMismatch {
            m: 1,
            hash: Dkim2Hash::Sha256
        })
    );
    let copy = message1.clone();
    signer("test2.dkim2.com")
        .sign_at(&copy, hop2(), Some(&proof), NOW)
        .unwrap();
    let revised = signer("test2.dkim2.com")
        .sign_revised_at(&message1, &modified, hop2(), Some(&proof), NOW)
        .unwrap();
    assert_eq!(revised.message_instance.as_ref().map(|mi| mi.m), Some(2));
}

// Local checks of the signer: chain of custody, mf=/d=, exploded flag, selectors and nonce.
#[tokio::test]
async fn signer_local_checks() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let oob = |domain| signer(domain).out_of_band_arrangement();
    let err = |result: crate::Result<Dkim2Signed>| match result.unwrap_err() {
        Error::Dkim2(error) => error,
        other => panic!("unexpected {other:?}"),
    };

    assert_eq!(
        err(oob("test3.dkim2.com").sign_at(
            &message1,
            Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
            None,
            NOW
        )),
        Dkim2Error::CustodyMailFromMismatch { i: 2, previous: 1 }
    );
    assert_eq!(
        err(oob("test2.dkim2.com").sign_at(
            &message1,
            Hop::real("relay@other.example", ["recipient@example.com"]),
            None,
            NOW
        )),
        Dkim2Error::MailFromDomainMismatch(2)
    );
    assert_eq!(
        err(oob("test3.dkim2.com").sign_at(
            &message1,
            Hop::imaginary("test4.dkim2.com"),
            None,
            NOW
        )),
        Dkim2Error::CustodyDomainMismatch { i: 2, previous: 1 }
    );
    assert_eq!(
        err(signer("test1.dkim2.com").flags([Flag::Exploded]).sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["a@example.com"]),
            None,
            NOW
        )),
        Dkim2Error::SignatureTagUnexpected { i: 1, tag: "f" }
    );
    assert_eq!(
        err(signer("test1.dkim2.com")
            .additional_key(load_ed25519("test1.dkim2.com", "ed25519"), "ED25519")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["a@example.com"]),
                None,
                NOW
            )),
        Dkim2Error::DuplicateSelector(1)
    );
    let same_algorithm = (1..8).fold(signer("test1.dkim2.com"), |signer, n| {
        signer.additional_key(load_ed25519("test1.dkim2.com", "ed25519"), format!("s{n}"))
    });
    assert!(
        same_algorithm
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["a@example.com"]),
                None,
                NOW
            )
            .is_ok()
    );
    assert_eq!(
        err((1..9)
            .fold(signer("test1.dkim2.com"), |signer, n| {
                signer.hybrid_key(load_ed25519("test1.dkim2.com", "ed25519"), format!("s{n}"))
            })
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["a@example.com"]),
                None,
                NOW
            )),
        Dkim2Error::TooManySelectors(1)
    );
    assert_eq!(
        err(signer("test1.dkim2.com").nonce("semi;colon").sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["a@example.com"]),
            None,
            NOW
        )),
        Dkim2Error::SignatureSyntax(1)
    );

    let exploded = oob("test2.dkim2.com")
        .sign_at(
            &message1,
            Hop::real("relay@test2.dkim2.com", ["a@example.com", "b@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(exploded.signature.flags, vec![Flag::Exploded]);
    let single = signer("test1.dkim2.com")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["a@example.com", "b@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert!(single.signature.flags.is_empty());
}

/// test1 delivers to test2, which hands the message to test3 without an SMTP
/// transaction; test3 then delivers to example.com.
#[tokio::test]
async fn sign_then_verify_imaginary_hop() {
    let original = original();
    let sign1 = signer("test1.dkim2.com")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
            None,
            NOW,
        )
        .unwrap();
    let message1 = prepend(&sign1, &original);
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;

    let sign2 = signer("test2.dkim2.com")
        .sign_at(
            &message1,
            Hop::imaginary("test3.dkim2.com"),
            Some(&proof),
            NOW,
        )
        .unwrap();
    let message2 = prepend(&sign2, &message1);
    assert!(matches!(sign2.signature.chain, ChainBinding::NextDomain(_)));

    assert_eq!(
        signer("test3.dkim2.com")
            .sign_at(
                &message2,
                Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::NotFullyVerified)
    );
    let sign3 = signer("test3.dkim2.com")
        .out_of_band_arrangement()
        .sign_at(
            &message2,
            Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    let message3 = prepend(&sign3, &message2);

    let parsed = AuthenticatedMessage::parse(&message3).unwrap();
    let output = verify(
        &parsed,
        "relay@test3.dkim2.com",
        &["recipient@example.com"],
        Verification::Full,
    )
    .await;
    assert_eq!(output.result(), &Dkim2Result::Pass, "{:?}", output.error());
    assert_eq!(output.chain().len(), 3);
}

// §7.1: an nd= signature matches when the previous rt= domain is d= or a subdomain of it.
#[tokio::test]
async fn verify_imaginary_hop_relaxed_direction() {
    let original = original();
    let chain = |rcpt: &'static str, nd_domain: &'static str| {
        let message1 = prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    &original,
                    Hop::real("sender@test1.dkim2.com", [rcpt]),
                    None,
                    NOW,
                )
                .unwrap(),
            &original,
        );
        let message2 = prepend(
            &signer(nd_domain)
                .out_of_band_arrangement()
                .sign_at(&message1, Hop::imaginary("test3.dkim2.com"), None, NOW)
                .unwrap(),
            &message1,
        );
        prepend(
            &signer("test3.dkim2.com")
                .out_of_band_arrangement()
                .sign_at(
                    &message2,
                    Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            &message2,
        )
    };

    let message = chain("list@mail.test2.dkim2.com", "test2.dkim2.com");
    assert_eq!(
        verify_raw(
            &message,
            "relay@test3.dkim2.com",
            &["recipient@example.com"]
        )
        .await,
        Dkim2Result::Pass
    );

    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    assert_eq!(
        signer("test4.dkim2.com")
            .out_of_band_arrangement()
            .sign_at(&message1, Hop::imaginary("test3.dkim2.com"), None, NOW)
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::CustodyDomainMismatch { i: 2, previous: 1 })
    );
}

// The verifier strips labels from the rt= domain, not from d=, for nd= signatures.
#[tokio::test]
async fn verify_rejects_imaginary_hop_from_subdomain() {
    let raw = concat!(
        "DKIM2-Signature: i=2; m=1; t=1740002100; d=sub.test2.dkim2.com; nd=test3.dkim2.com; s=a:ed25519-sha256:QQ==;\r\n",
        "DKIM2-Signature: i=1; m=1; t=1740002100; d=test1.dkim2.com; mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+; rt=PGxpc3RAdGVzdDIuZGtpbTIuY29tPg==; s=a:ed25519-sha256:QQ==;\r\n",
        "DKIM2-Signature: i=3; m=1; t=1740002100; d=test3.dkim2.com; mf=PHJlbGF5QHRlc3QzLmRraW0yLmNvbT4=; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=a:ed25519-sha256:QQ==;\r\n",
        "Message-Instance: m=1; h=sha256:QQ==:QQ==;\r\n",
        "From: sender@test1.dkim2.com\r\n\r\nbody\r\n",
    );
    assert_eq!(
        verify_raw(
            raw.as_bytes(),
            "relay@test3.dkim2.com",
            &["recipient@example.com"]
        )
        .await,
        fail(Dkim2Error::CustodyDomainMismatch { i: 2, previous: 1 })
    );
}

// §7.1: a null mf= mid-chain matches the previous rt= domain against d=.
#[tokio::test]
async fn verify_null_mail_from_mid_chain() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["bounces@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let message2 = prepend(
        &signer("test2.dkim2.com")
            .out_of_band_arrangement()
            .sign_at(
                &message1,
                Hop::real("<>", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &message1,
    );
    assert_eq!(
        verify_raw(&message2, "<>", &["recipient@example.com"]).await,
        Dkim2Result::Pass
    );

    let message2 = prepend(
        &signer("test3.dkim2.com")
            .out_of_band_arrangement()
            .sign_at(
                &prepend(
                    &signer("test1.dkim2.com")
                        .sign_at(
                            &original,
                            Hop::real("sender@test1.dkim2.com", ["bounces@test3.dkim2.com"]),
                            None,
                            NOW,
                        )
                        .unwrap(),
                    &original,
                ),
                Hop::real("<>", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &message1,
    );
    assert_eq!(
        verify_raw(&message2, "<>", &["recipient@example.com"]).await,
        fail(Dkim2Error::CustodyDomainMismatch { i: 2, previous: 1 })
    );
}

// §14.3: timestamps more than one day ahead are rejected.
#[tokio::test]
async fn verify_rejects_future_timestamp() {
    let original = original();
    for (t, expected) in [
        (NOW + DAY - 1, Dkim2Result::Pass),
        (NOW + DAY + 1, fail(Dkim2Error::SignatureFromFuture(1))),
        (NOW - 15 * DAY, fail(Dkim2Error::SignatureExpired(1))),
    ] {
        let message = prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    &original,
                    Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                    None,
                    t,
                )
                .unwrap(),
            &original,
        );
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            expected,
            "t={t}"
        );
    }
}

// §11: the From domain must relaxed-match d= of the signature that covers it.
#[tokio::test]
async fn verify_from_is_authentic() {
    let foreign = b"From: someone@other.example\r\nSubject: x\r\n\r\nbody\r\n";
    assert_eq!(
        signer("test1.dkim2.com")
            .sign_at(
                foreign.as_slice(),
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::FromNotAuthentic(1)),
        "the signer refuses a From it cannot make Authentic (§12.4)"
    );
    let _lenient = crate::dkim2::sign::test_authentic_from::LenientFrom::new();
    let message = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                foreign.as_slice(),
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap(),
        foreign,
    );
    assert_eq!(
        verify_raw(
            &message,
            "sender@test1.dkim2.com",
            &["recipient@example.com"]
        )
        .await,
        fail(Dkim2Error::FromNotAuthentic(1))
    );
    let parsed = AuthenticatedMessage::parse(&message).unwrap();
    assert_eq!(
        verify(
            &parsed,
            "sender@test1.dkim2.com",
            &["recipient@example.com"],
            Verification::Provisional
        )
        .await
        .result(),
        &Dkim2Result::Pass
    );

    for (from, expected) in [
        ("sender@mail.test1.dkim2.com", Dkim2Result::Pass),
        (
            "a@test1.dkim2.com, b@test1.dkim2.com",
            fail(Dkim2Error::FromNotAuthentic(1)),
        ),
        ("a@[192.0.2.1]", fail(Dkim2Error::FromNotAuthentic(1))),
    ] {
        let raw = format!("From: {from}\r\nSubject: x\r\n\r\nbody\r\n");
        let message = prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    raw.as_bytes(),
                    Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            raw.as_bytes(),
        );
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            expected,
            "{from}"
        );
    }
}

// A Reviser that rewrites From must sign with a domain that makes the new From Authentic.
#[tokio::test]
async fn verify_rewritten_from() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;

    let text = String::from_utf8(message1.clone()).unwrap();
    let foreign = text.replace("From: sender@test1.dkim2.com", "From: list@other.example");
    assert_eq!(
        signer("test2.dkim2.com")
            .sign_revised_at(
                &message1,
                foreign.as_bytes(),
                Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                Some(&proof),
                NOW,
            )
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::FromNotAuthentic(2))
    );

    let _lenient = crate::dkim2::sign::test_authentic_from::LenientFrom::new();
    for (new_from, expected) in [
        ("list@test2.dkim2.com", Dkim2Result::Pass),
        ("list@other.example", fail(Dkim2Error::FromNotAuthentic(2))),
    ] {
        let modified = text.replace("From: sender@test1.dkim2.com", &format!("From: {new_from}"));
        let signed = signer("test2.dkim2.com")
            .sign_revised_at(
                &message1,
                modified.as_bytes(),
                Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                Some(&proof),
                NOW,
            )
            .unwrap();
        let message2 = prepend(&signed, modified.as_bytes());
        assert_eq!(
            verify_raw(
                &message2,
                "relay@test2.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            expected,
            "{new_from}"
        );
    }
}

// SHA-512 and SHA-256 Message-Instance hashes are both checked; any mismatch is a failure.
#[tokio::test]
async fn verify_sha512_hashes() {
    let original = original();
    for hashes in [
        vec![Dkim2Hash::Sha512],
        vec![Dkim2Hash::Sha256, Dkim2Hash::Sha512],
    ] {
        let signed = signer("test1.dkim2.com")
            .hashes(hashes.iter().copied())
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap();
        assert_eq!(
            signed
                .message_instance
                .as_ref()
                .unwrap()
                .hashes
                .iter()
                .map(|hash| hash.name.known().unwrap())
                .collect::<Vec<_>>(),
            hashes
        );
        let message = prepend(&signed, &original);
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            Dkim2Result::Pass
        );
        let mut tampered = message.clone();
        tampered.extend_from_slice(b"tampered\r\n");
        assert_eq!(
            verify_raw(
                &tampered,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            fail(Dkim2Error::BodyHashMismatch {
                m: 1,
                hash: hashes[0]
            })
        );
    }
}

// ML-DSA-44 signs and verifies alone, as an alternative to Ed25519 and as a hybrid with it.
#[tokio::test]
async fn sign_then_verify_mldsa44() {
    let original = original();
    for signer in [
        signer_with(load_mldsa(), "test1.dkim2.com", "mldsa44"),
        signer_with(load_mldsa(), "test1.dkim2.com", "mldsa44")
            .additional_key(load_ed25519("test1.dkim2.com", "ed25519"), "ed25519")
            .hashes([Dkim2Hash::Sha512]),
        signer_with(load_mldsa(), "test1.dkim2.com", "mldsa44")
            .hybrid_key(load_ed25519("test1.dkim2.com", "ed25519"), "ed25519"),
    ] {
        let signed = signer
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap();
        assert_eq!(signed.signature.s[0].b.len(), 2420);
        let message = prepend(&signed, &original);
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            Dkim2Result::Pass
        );
    }
}

// §14.6: "|" groups pass if any group passes, "," groups only if every entry passes.
#[tokio::test]
async fn verify_signature_groups() {
    let original = original();
    let hop = || Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]);
    let verify = |signed: &Dkim2Signed| {
        let message = prepend(signed, &original);
        async move {
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"],
            )
            .await
        }
    };

    let alternatives = signer("test1.dkim2.com")
        .additional_key(load_rsa("test1.dkim2.com", "sel1"), "sel1")
        .sign_at(&original, hop(), None, NOW)
        .unwrap();
    assert!(
        alternatives
            .to_header()
            .contains("s=ed25519:ed25519-sha256:")
    );
    assert_eq!(
        alternatives
            .signature
            .s
            .iter()
            .map(|value| value.group)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let mut wrong_ed25519 = alternatives.clone();
    wrong_ed25519.signature.s[0].b[0] ^= 1;
    assert_eq!(verify(&wrong_ed25519).await, Dkim2Result::Pass);
    let mut both_wrong = wrong_ed25519.clone();
    both_wrong.signature.s[1].b[0] ^= 1;
    assert_eq!(
        verify(&both_wrong).await,
        fail(Dkim2Error::NoSignatureGroupPassed(1))
    );

    let hybrid = signer("test1.dkim2.com")
        .hybrid_key(load_rsa("test1.dkim2.com", "sel1"), "sel1")
        .sign_at(&original, hop(), None, NOW)
        .unwrap();
    assert_eq!(
        hybrid
            .signature
            .s
            .iter()
            .map(|value| value.group)
            .collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert_eq!(verify(&hybrid).await, Dkim2Result::Pass);
    let mut wrong_rsa = hybrid.clone();
    wrong_rsa.signature.s[1].b[0] ^= 1;
    assert_eq!(
        verify(&wrong_rsa).await,
        fail(Dkim2Error::IncorrectSignature {
            i: 1,
            selector: "sel1".into()
        })
    );
}

// §14.5: key record problems are reported with the selector.
#[tokio::test]
async fn verify_public_key_errors() {
    let original = original();
    let message = prepend(
        &signer_with(
            load_ed25519("test1.dkim2.com", "ed25519"),
            "test1.dkim2.com",
            "broken",
        )
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap(),
        &original,
    );
    let parsed = AuthenticatedMessage::parse(&message).unwrap();
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let selector = || -> Box<str> { "broken".into() };
    let ed25519 = "v=DKIM1; k=ed25519; p=hwjviTXyzUXSCWayBqE17s/4NSynQKxw58jayHudRAI=";
    for (record, expected) in [
        (
            TxtRecord::Error(Error::Dkim(DkimError::PublicKeyRevoked)),
            perm(Dkim2Error::PublicKeyRevoked {
                i: 1,
                selector: selector(),
            }),
        ),
        (
            TxtRecord::Error(Error::Dkim(DkimError::UnsupportedKeyType)),
            perm(Dkim2Error::PublicKeyAlgorithmMismatch {
                i: 1,
                selector: selector(),
            }),
        ),
        (
            TxtRecord::Error(Error::Dns(crate::DnsError::InvalidRecordType)),
            perm(Dkim2Error::PublicKeySyntax {
                i: 1,
                selector: selector(),
            }),
        ),
        (
            DomainKey::parse_records(&[ed25519.as_bytes().to_vec(), b"v=spf1".to_vec()])
                .unwrap()
                .into(),
            perm(Dkim2Error::PublicKeyMultiple {
                i: 1,
                selector: selector(),
            }),
        ),
        (
            DomainKey::parse(b"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMuHH9dIAKbCbFmeaJuG4NV5ROugoU7FHlnfEXVuT6QAYUCm8tGXeU2ijSpqspkEO9V2wTFrTJYRBfi6cSAyO10CAwEAAQ==")
                .unwrap()
                .into(),
            perm(Dkim2Error::PublicKeyAlgorithmMismatch {
                i: 1,
                selector: selector(),
            }),
        ),
    ] {
        let caches = DummyCaches::new();
        caches.txt_add(
            "broken._domainkey.test1.dkim2.com.",
            record,
            Instant::now() + Duration::new(3600, 0),
        );
        let params = caches.parameters(&parsed);
        let output = resolver
            .verify_dkim2_(
                &parsed,
                Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]),
                params.txt_cache(),
                NOW,
                true,
                Verification::Full,
            )
            .await;
        assert_eq!(output.result(), &expected);
    }
}

// §14.2: numbering gaps and instances without signatures are errors; no DKIM2 fields is none.
#[tokio::test]
async fn verify_header_field_presence() {
    let instance = "Message-Instance: m=1; h=sha256:QQ==:QQ==;\r\n";
    let signature = |i: u32| {
        format!(
            "DKIM2-Signature: i={i}; m=1; t={NOW}; d=test1.dkim2.com; mf=PHNlbmRlckB0ZXN0MS5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:QQ==;\r\n"
        )
    };
    let body = "From: sender@test1.dkim2.com\r\n\r\nbody\r\n";
    for (raw, expected) in [
        (body.to_string(), Dkim2Result::None),
        (
            format!("{instance}{body}"),
            perm(Dkim2Error::SignatureMissing(1)),
        ),
        (
            format!("{}{}{instance}{body}", signature(1), signature(3)),
            perm(Dkim2Error::SequenceGap(2)),
        ),
        (
            format!("{}{body}", signature(1)),
            perm(Dkim2Error::InstanceMissing(1)),
        ),
        (
            format!(
                "{}{instance}Message-Instance: m=2; h=sha256:QQ==:QQ==;\r\n{body}",
                signature(1)
            ),
            perm(Dkim2Error::InstanceNotSigned(2)),
        ),
        (
            format!(
                "{}{}{instance}Message-Instance: m=2; h=sha256:QQ==:QQ==;\r\n{body}",
                signature(1).replace("m=1", "m=2"),
                signature(2)
            ),
            perm(Dkim2Error::SignatureSyntax(2)),
        ),
        (
            format!(
                "Message-Instance: garbage\r\n{}{instance}{body}",
                signature(1)
            ),
            perm(Dkim2Error::InstanceSyntax(0)),
        ),
    ] {
        assert_eq!(
            verify_raw(
                raw.as_bytes(),
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            expected,
            "{raw}"
        );
    }
}

// A null body recipe stops body checks below it but header hashes and signatures are still verified.
#[tokio::test]
async fn verify_null_body_recipe() {
    use crate::dkim2::{BodyRecipe, Recipe};

    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["gw@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["gw@test2.dkim2.com"],
        Verification::Full,
    )
    .await;
    let text = String::from_utf8(message1.clone()).unwrap();
    let modified = text.replace("Hello, this is", "[scanned] Hello, this was");
    let signed = signer("test2.dkim2.com")
        .sign_with_recipe_at(
            modified.as_bytes(),
            Recipe {
                headers: vec![],
                body: BodyRecipe::Unreconstructable,
            },
            Hop::real("gw@test2.dkim2.com", ["recipient@example.com"]),
            Some(&proof),
            NOW,
        )
        .unwrap();
    let message2 = prepend(&signed, modified.as_bytes());
    assert_eq!(
        verify_raw(&message2, "gw@test2.dkim2.com", &["recipient@example.com"]).await,
        fail(Dkim2Error::NullBodyRecipe(2))
    );
}

#[tokio::test]
async fn sign_multi_algorithm_then_verify() {
    use crate::crypto::Algorithm;

    let original = original();
    let signed = signer("test1.dkim2.com")
        .additional_key(load_rsa("test1.dkim2.com", "sel1"), "sel1")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();

    assert_eq!(signed.signature.s.len(), 2);
    assert_eq!(signed.signature.s[0].selector, "ed25519");
    assert_eq!(signed.signature.s[0].a, Algorithm::Ed25519Sha256.into());
    assert_eq!(signed.signature.s[1].selector, "sel1");
    assert_eq!(signed.signature.s[1].a, Algorithm::RsaSha256.into());

    let message = prepend(&signed, &original);
    assert_eq!(
        verify_raw(
            &message,
            "sender@test1.dkim2.com",
            &["recipient@example.com"]
        )
        .await,
        Dkim2Result::Pass
    );
}

#[tokio::test]
async fn verify_rejects_wrong_envelope() {
    let envelope = Envelope::new("attacker@evil.example", ["recipient@example.com"]);
    let result = verify_file("simple-ed25519.eml", envelope).await;
    assert!(matches!(result, Dkim2Result::Fail(_)), "got {result:?}");
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
            .verify_dkim2_(
                &message,
                envelope,
                params.txt_cache(),
                NOW,
                true,
                Verification::Full,
            )
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
        .verify_dkim2_(
            &message,
            envelope,
            params.txt_cache(),
            NOW,
            true,
            Verification::Full,
        )
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
        .verify_dkim2_(
            &message,
            envelope,
            params.txt_cache(),
            NOW,
            true,
            Verification::Full,
        )
        .await;
    assert!(
        matches!(
            result.result(),
            Dkim2Result::Fail(Error::Dkim2(Dkim2Error::HeaderHashMismatch { .. }))
        ),
        "got {:?}",
        result.result()
    );
}

#[tokio::test]
async fn verify_rejects_rcpt_not_in_rt() {
    let envelope = Envelope::new("sender@test1.dkim2.com", ["someone-else@example.com"]);
    let result = verify_file("simple-ed25519.eml", envelope).await;
    assert!(
        matches!(
            result,
            Dkim2Result::Fail(Error::Dkim2(Dkim2Error::RcptToMismatch { .. }))
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
            .verify_dkim2_(
                &message,
                envelope,
                params.txt_cache(),
                now,
                true,
                Verification::Full,
            )
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

// Writes the -07 vectors listed in resources/dkim2/cases.json; run with REGEN_DKIM2=1.
#[tokio::test]
async fn regen_dkim2_07_vectors() {
    if std::env::var("REGEN_DKIM2").is_err() {
        return;
    }
    let write = |name: &str, raw: &[u8]| {
        std::fs::write(resource(&["expected", &format!("{name}.eml")]), raw).unwrap();
    };
    let original = original();
    let first = |rcpt: &'static str| {
        prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    &original,
                    Hop::real("sender@test1.dkim2.com", [rcpt]),
                    None,
                    NOW,
                )
                .unwrap(),
            &original,
        )
    };
    let oob = |domain| signer(domain).out_of_band_arrangement();

    let message1 = first("list@mail.test2.dkim2.com");
    let message2 = prepend(
        &oob("test2.dkim2.com")
            .sign_at(&message1, Hop::imaginary("test3.dkim2.com"), None, NOW)
            .unwrap(),
        &message1,
    );
    write(
        "d2_07_nd_rt_subdomain",
        &prepend(
            &oob("test3.dkim2.com")
                .sign_at(
                    &message2,
                    Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            &message2,
        ),
    );

    let message1 = first("bounces@test2.dkim2.com");
    write(
        "d2_07_null_mf_mid_chain",
        &prepend(
            &oob("test2.dkim2.com")
                .sign_at(
                    &message1,
                    Hop::real("<>", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            &message1,
        ),
    );

    write(
        "d2_07_future_timestamp",
        &prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    &original,
                    Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW + 2 * DAY,
                )
                .unwrap(),
            &original,
        ),
    );

    let lenient = crate::dkim2::sign::test_authentic_from::LenientFrom::new();
    let foreign = String::from_utf8(original.clone())
        .unwrap()
        .replace("From: sender@test1.dkim2.com", "From: sender@other.example");
    write(
        "d2_07_from_not_authentic",
        &prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    foreign.as_bytes(),
                    Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            foreign.as_bytes(),
        ),
    );

    drop(lenient);
    let message1 = first("list@test2.dkim2.com");
    let rewritten = String::from_utf8(message1.clone())
        .unwrap()
        .replace("From: sender@test1.dkim2.com", "From: list@test2.dkim2.com");
    write(
        "d2_07_from_rewritten",
        &prepend(
            &oob("test2.dkim2.com")
                .sign_revised_at(
                    &message1,
                    rewritten.as_bytes(),
                    Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            rewritten.as_bytes(),
        ),
    );

    let binary_original =
        b"From: sender@test1.dkim2.com\r\nSubject: bytes\r\n\r\nline \xff one\r\nline two\r\n"
            .to_vec();
    let binary_message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &binary_original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &binary_original,
    );
    let mut binary_modified = binary_message1.clone();
    let footer = binary_modified
        .windows(9)
        .position(|w| w == b"line \xff on")
        .unwrap();
    binary_modified.splice(footer..footer + 9, b"LINE \xfe ON".iter().copied());
    let revised = oob("test2.dkim2.com")
        .sign_revised_at(
            &binary_message1,
            &binary_modified,
            Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    let recipe = revised
        .message_instance
        .as_ref()
        .and_then(|mi| mi.recipe.as_ref())
        .unwrap();
    assert!(matches!(
        &recipe.body,
        crate::dkim2::BodyRecipe::Steps(steps) if steps.iter().any(|step| matches!(step, crate::dkim2::Step::Bytes(_)))
    ));
    write("d2_07_u_step", &prepend(&revised, &binary_modified));

    let signed = signer("test1.dkim2.com")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    let text = String::from_utf8(prepend(&signed, &original)).unwrap();
    let (sig_line, rest) = text.split_once("\r\n").unwrap();
    let (mi_line, body) = rest.split_once("\r\n").unwrap();
    let sig_entry = sig_line.split_once("s=").unwrap().1.trim_end_matches(';');
    write(
        "d2_07_duplicate_selector",
        format!("{sig_line} \r\n\ts=ed25519:rsa-sha256:QQ==;\r\n{mi_line}\r\n{body}")
            .replace(
                &format!("s={sig_entry}; \r\n\ts="),
                &format!("s={sig_entry},"),
            )
            .as_bytes(),
    );
    write(
        "d2_07_too_many_selectors",
        sig_line
            .replace(
                &format!("s={sig_entry};"),
                &format!("s={sig_entry},a:ed25519-sha256:QQ==,b:ed25519-sha256:QQ==;"),
            )
            .chars()
            .chain("\r\n".chars())
            .chain(mi_line.chars())
            .chain("\r\n".chars())
            .chain(body.chars())
            .collect::<String>()
            .as_bytes(),
    );
    let hash = mi_line.split_once("h=").unwrap().1.trim_end_matches(';');
    write(
        "d2_07_duplicate_hash",
        format!(
            "{sig_line}\r\n{}\r\n{body}",
            mi_line.replace(&format!("h={hash}"), &format!("h={hash},{hash}"))
        )
        .as_bytes(),
    );
    write(
        "d2_07_duplicate_tag",
        format!(
            "{}\r\n{mi_line}\r\n{body}",
            sig_line.replace("; t=", "; i=1; t=")
        )
        .as_bytes(),
    );

    let signed = signer("test1.dkim2.com")
        .flags([Flag::Feedback])
        .nonce("banana")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    let text = String::from_utf8(prepend(&signed, &original)).unwrap();
    let (sig_line, rest) = text.split_once("\r\n").unwrap();
    let (mi_line, body) = rest.split_once("\r\n").unwrap();
    let (mi_name, mi_value) = mi_line.split_once(':').unwrap();
    let specs = sig_line
        .split_once(':')
        .unwrap()
        .1
        .split(';')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
        .collect::<Vec<_>>();
    let key = load_ed25519("test1.dkim2.com", "ed25519");
    let selector = "s=ed25519:ed25519-sha256:";
    let resign = |specs: &[&str]| {
        let value = specs
            .iter()
            .map(|spec| {
                if spec.starts_with(selector) {
                    selector
                } else {
                    spec
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
            + ";";
        let mut input = Vec::new();
        let mut w = CanonicalizedHeaderWriter::new(&mut input, mi_name.as_bytes());
        w.write(mi_value.as_bytes());
        w.finalize();
        strip_and_canonicalize_signature(value.as_bytes(), &mut input);
        let mut b = String::new();
        base64::STANDARD.encode_append(key.sign(input.as_slice()).unwrap(), &mut b);
        format!(
            "DKIM2-Signature: {}\r\n{mi_line}\r\n{body}",
            value.replace(selector, &format!("{selector}{b}"))
        )
    };
    assert_eq!(resign(&specs), text);
    for tag in ["d", "f", "i", "m", "mf", "n", "rt", "s", "t"] {
        let prefix = format!("{tag}=");
        let mut duplicated = Vec::with_capacity(specs.len() + 1);
        for &spec in &specs {
            duplicated.push(spec);
            if spec.starts_with(&prefix) {
                duplicated.push(spec);
            }
        }
        assert_eq!(duplicated.len(), specs.len() + 1, "tag {tag}");
        write(
            &format!("d2_07_duplicate_{tag}_tag"),
            resign(&duplicated).as_bytes(),
        );
    }
    let mut upper = specs.clone();
    upper.extend([
        "I=2",
        "M=7",
        "T=0",
        "D=example.com",
        "MF=PD4=",
        "RT=PHVua25vd25AZXhhbXBsZS5jb20+",
        "N=apple",
        "F=exploded",
        "S=other:ed25519-sha256:QQ==",
    ]);
    write("d2_07_upper_case_tags_ignored", resign(&upper).as_bytes());
    let mixed = specs
        .iter()
        .map(|spec| {
            let mut spec = spec.to_string();
            if let Some(first) = spec.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            spec
        })
        .collect::<Vec<_>>()
        .join("; ");
    write(
        "d2_07_mixed_case_tags",
        format!("DKIM2-Signature: {mixed};\r\n{mi_line}\r\n{body}").as_bytes(),
    );

    let chain_original = std::fs::read(resource(&["emails", "chain-original.eml"])).unwrap();
    let rsa_signer = |selector: &str| {
        signer_with(
            load_rsa("test1.dkim2.com", selector),
            "test1.dkim2.com",
            selector,
        )
    };
    write(
        "d2_07_originator_multipart",
        &prepend(
            &rsa_signer("sel3")
                .sign_at(
                    &chain_original,
                    Hop::real("sender@test1.dkim2.com", ["foo@test2.dkim2.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            &chain_original,
        ),
    );

    let message1 = prepend(
        &rsa_signer("sel1")
            .sign_at(
                &chain_original,
                Hop::real("brong@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &chain_original,
    );
    write("d2_07_chain_hop1", &message1);

    let list = [
        message1.strip_suffix(chain_original.as_slice()).unwrap(),
        &std::fs::read(resource(&["emails", "chain-list.eml"])).unwrap(),
    ]
    .concat();
    let signed2 = oob("test2.dkim2.com")
        .sign_revised_at(
            &message1,
            &list,
            Hop::real("bounces@test2.dkim2.com", ["user@test3.dkim2.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert!(
        signed2
            .message_instance
            .as_ref()
            .and_then(|mi| mi.recipe.as_ref())
            .is_some_and(|recipe| recipe
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("from")))
    );
    let message2 = String::from_utf8(prepend(&signed2, &list)).unwrap();
    write("d2_07_chain_hop2", message2.as_bytes());

    let (headers2, body2) = message2.split_once("\r\n\r\n").unwrap();
    let mut lines = body2.split_inclusive("\r\n");
    let modified3 = format!(
        "Extra-Header: yes\r\n{headers2}\r\n\r\n{}Here's some extra text.\r\n\r\n{}",
        lines.by_ref().take(15).collect::<String>(),
        lines.collect::<String>()
    );
    let message3 = String::from_utf8(prepend(
        &oob("test3.dkim2.com")
            .sign_revised_at(
                message2.as_bytes(),
                modified3.as_bytes(),
                Hop::real("relay@test3.dkim2.com", ["user@test4.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        modified3.as_bytes(),
    ))
    .unwrap();
    write("d2_07_chain_hop3", message3.as_bytes());

    let modified4 = message3.replacen("Extra-Header: yes\r\n", "", 1).replacen(
        "Here's some extra text.\r\n\r\n",
        "",
        1,
    );
    let message4 = prepend(
        &oob("test4.dkim2.com")
            .sign_revised_at(
                message3.as_bytes(),
                modified4.as_bytes(),
                Hop::real("relay@test4.dkim2.com", ["user@test5.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        modified4.as_bytes(),
    );
    write("d2_07_chain_hop4", &message4);

    let modified5 = [
        b"Return-Path: <relay@test4.dkim2.com>\r\n\
        Received-SPF: pass (test4.dkim2.com: 192.0.2.1 is authorized to use \
        'relay@test4.dkim2.com') receiver=mx.test5.dkim2.com; identity=mailfrom\r\n\
        Authentication-Results: mx.test5.dkim2.com; dkim2=pass header.d=test4.dkim2.com\r\n\
        X-Delivered-To: brong@test1.dkim2.com\r\n\
        Received: from mx.test4.dkim2.com (mx.test4.dkim2.com [192.0.2.1])\r\n\
        \tby mx.test5.dkim2.com; Thu, 08 Aug 2024 01:23:34 +0000\r\n"
            .as_slice(),
        &message4,
    ]
    .concat();
    let signed5 = oob("test5.dkim2.com")
        .sign_revised_at(
            &message4,
            &modified5,
            Hop::real("forwarder@test5.dkim2.com", ["brong@test1.dkim2.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert!(signed5.message_instance.is_none());
    let message5 = prepend(&signed5, &modified5);
    write("d2_07_chain_hop5", &message5);

    let signed6 = rsa_signer("sel2")
        .out_of_band_arrangement()
        .sign_at(
            &message5,
            Hop::real("relay@test1.dkim2.com", ["dest@test2.dkim2.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert!(signed6.message_instance.is_none());
    write("d2_07_chain_hop6", &prepend(&signed6, &message5));
}

// A provisional pass only vouches for the most recent signature, never for a forged i=1.
#[tokio::test]
async fn provisional_chain_holds_only_top_signature() {
    use crate::AuthenticationResults;

    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let forged =
        String::from_utf8(message1)
            .unwrap()
            .replacen("d=test1.dkim2.com", "d=bank.example", 1);
    let message2 = prepend(
        &signer("test2.dkim2.com")
            .out_of_band_arrangement()
            .sign_at(
                forged.as_bytes(),
                Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap(),
        forged.as_bytes(),
    );
    let parsed = AuthenticatedMessage::parse(&message2).unwrap();
    let envelope = ("relay@test2.dkim2.com", ["recipient@example.com"]);

    let full = verify(&parsed, envelope.0, &envelope.1, Verification::Full).await;
    assert!(
        matches!(full.result(), Dkim2Result::Fail(_)),
        "{:?}",
        full.result()
    );
    let provisional = verify(&parsed, envelope.0, &envelope.1, Verification::Provisional).await;
    assert_eq!(provisional.result(), &Dkim2Result::Pass);
    assert_eq!(
        provisional
            .chain()
            .iter()
            .map(|link| link.signature.i)
            .collect::<Vec<_>>(),
        vec![2]
    );
    let auth_results = AuthenticationResults::new("mx.example").with_dkim2_result(&provisional);
    assert!(
        auth_results.auth_results.ends_with("dkim2=pass"),
        "{}",
        auth_results.auth_results
    );
}

// A malformed DKIM2 header field does not change which signature the signer treats as the highest.
#[tokio::test]
async fn out_of_band_signer_with_malformed_header() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let message2 = prepend(
        &signer("test2.dkim2.com")
            .out_of_band_arrangement()
            .sign_at(
                &message1,
                Hop::real("relay@test2.dkim2.com", ["fwd@test3.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &message1,
    );
    let mut garbled = b"Message-Instance: garbage\r\n".to_vec();
    garbled.extend_from_slice(&message2);
    let signed = signer("test3.dkim2.com")
        .out_of_band_arrangement()
        .sign_at(
            &garbled,
            Hop::real("relay@test3.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!((signed.signature.i, signed.signature.m), (3, 1));
}

// The signer only emits domains and selectors its own parser accepts, recording U-labels as A-labels.
#[tokio::test]
async fn signer_validates_domains_and_selectors() {
    let original = original();
    let err = |result: crate::Result<Dkim2Signed>| match result.unwrap_err() {
        Error::Dkim2(error) => error,
        other => panic!("unexpected {other:?}"),
    };
    let hop = || Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]);
    for domain in [
        "ex..ample.com",
        "ex_ample.com",
        "ex ample.com",
        "",
        ".",
        "-ex.com",
    ] {
        assert_eq!(
            err(signer_with(
                load_ed25519("test1.dkim2.com", "ed25519"),
                domain,
                "ed25519"
            )
            .sign_at(&original, hop(), None, NOW)),
            Dkim2Error::SignatureSyntax(1),
            "{domain:?}"
        );
    }
    let long_label = format!("{}.test1.dkim2.com", "a".repeat(64));
    assert_eq!(
        err(signer_with(
            load_ed25519("test1.dkim2.com", "ed25519"),
            &long_label,
            "ed25519"
        )
        .sign_at(&original, hop(), None, NOW)),
        Dkim2Error::SignatureSyntax(1)
    );
    for selector in ["my_sel", "", "a..b", "sel ector"] {
        assert_eq!(
            err(signer_with(
                load_ed25519("test1.dkim2.com", "ed25519"),
                "test1.dkim2.com",
                selector
            )
            .sign_at(&original, hop(), None, NOW)),
            Dkim2Error::SignatureSyntax(1),
            "{selector:?}"
        );
    }
    assert_eq!(
        err(signer("test1.dkim2.com").sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", Vec::<&str>::new()),
            None,
            NOW
        )),
        Dkim2Error::SignatureTagMissing { i: 1, tag: "rt" }
    );

    let message = b"From: a@b\xc3\xbccher.example\r\n\r\nbody\r\n";
    let unicode = |domain: &str| {
        signer_with(
            load_ed25519("test1.dkim2.com", "ed25519"),
            domain,
            "ed25519",
        )
    };
    let signed = unicode("B\u{fc}cher.example")
        .sign_at(
            message.as_slice(),
            Hop::real("a@b\u{fc}cher.example", ["list@b\u{fc}cher.example"]),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(signed.signature.d, "xn--bcher-kva.example");
    assert_eq!(
        signed.signature.chain,
        ChainBinding::Envelope {
            mail_from: "<a@xn--bcher-kva.example>".to_string(),
            rcpt_to: vec!["<list@xn--bcher-kva.example>".to_string()],
        }
    );
    let message1 = prepend(&signed, message);
    let imaginary = unicode("b\u{fc}cher.example")
        .out_of_band_arrangement()
        .sign_at(&message1, Hop::imaginary("M\u{fc}ller.example"), None, NOW)
        .unwrap();
    assert_eq!(
        imaginary.signature.chain,
        ChainBinding::NextDomain("xn--mller-kva.example".to_string())
    );
    assert_eq!(
        err(unicode("b\u{fc}cher.example")
            .out_of_band_arrangement()
            .sign_at(&message1, Hop::imaginary("bad domain"), None, NOW)),
        Dkim2Error::SignatureSyntax(2)
    );
}

// A From field is Authentic only when it holds exactly one well-formed mailbox; tricks that show a second domain fail.
#[tokio::test]
async fn from_authenticity_requires_one_clean_mailbox() {
    let sign = |from_lines: &str| {
        let raw = format!("{from_lines}To: r@example.com\r\nSubject: s\r\n\r\nbody\r\n");
        let result = signer("test1.dkim2.com").sign_at(
            raw.as_bytes(),
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        );
        (raw, result)
    };
    for from_lines in [
        "From: ceo@victim.example sender@test1.dkim2.com\r\n",
        "From: <ceo@victim.example> <sender@test1.dkim2.com>\r\n",
        "From: ceo@victim.example <>, sender@test1.dkim2.com\r\n",
        "From: sender@test1.dkim2.com, Bank Support\r\n",
        "From: ceo@victim.example\r\n From: sender@test1.dkim2.com\r\n",
        "From: sender@test1.dkim2.com\r\nFrom : ceo@victim.example\r\n",
        "From: group: sender@test1.dkim2.com;\r\n",
        "From: sender@[192.0.2.1]\r\n",
        "From: <sender@test1.dkim2.com.>\r\n",
        "To: r@example.com\r\n",
    ] {
        let (raw, result) = sign(from_lines);
        assert_eq!(
            result.unwrap_err(),
            Error::Dkim2(Dkim2Error::FromNotAuthentic(1)),
            "signer: {from_lines:?}"
        );
        let _lenient = crate::dkim2::sign::test_authentic_from::LenientFrom::new();
        let message = prepend(&sign(from_lines).1.unwrap(), raw.as_bytes());
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            fail(Dkim2Error::FromNotAuthentic(1)),
            "verifier: {from_lines:?}"
        );
    }
    for from_lines in [
        "From: Sender Name <sender@test1.dkim2.com>\r\n",
        "From: \"Last, First\" <sender@mail.test1.dkim2.com>\r\n",
        "From: sender@TEST1.dkim2.com (comment)\r\n",
    ] {
        let (raw, result) = sign(from_lines);
        let message = prepend(&result.unwrap(), raw.as_bytes());
        assert_eq!(
            verify_raw(
                &message,
                "sender@test1.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            Dkim2Result::Pass,
            "{from_lines:?}"
        );
    }
}

// Flags, recipients and the nonce are only emitted in a form the parser reads back unchanged.
#[tokio::test]
async fn signer_validates_flags_recipients_and_nonce() {
    let original = original();
    let err = |result: crate::Result<Dkim2Signed>| match result.unwrap_err() {
        Error::Dkim2(error) => error,
        other => panic!("unexpected {other:?}"),
    };
    let hop = || Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]);
    for flag in ["a;b", "x y", "x; foo=bar", "", "a,b"] {
        assert_eq!(
            err(signer("test1.dkim2.com")
                .flags([Flag::Unknown(flag.into())])
                .sign_at(&original, hop(), None, NOW)),
            Dkim2Error::SignatureSyntax(1),
            "{flag:?}"
        );
    }
    assert_eq!(
        err(signer("test1.dkim2.com")
            .flags([Flag::Unknown("exploded".into())])
            .sign_at(&original, hop(), None, NOW)),
        Dkim2Error::SignatureTagUnexpected { i: 1, tag: "f" }
    );
    let signed = signer("test1.dkim2.com")
        .flags([
            Flag::Unknown("feedback".into()),
            Flag::Feedback,
            Flag::Unknown("x-new".into()),
        ])
        .sign_at(&original, hop(), None, NOW)
        .unwrap();
    assert_eq!(
        signed.signature.flags,
        vec![Flag::Feedback, Flag::Unknown("x-new".into())]
    );

    for rcpt in ["", "<>", "nobody", "<a@b> <c@d>", "a @b.example"] {
        assert_eq!(
            err(signer("test1.dkim2.com").sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com", rcpt]),
                None,
                NOW
            )),
            Dkim2Error::SignatureSyntax(1),
            "{rcpt:?}"
        );
    }

    let signed = signer("test1.dkim2.com")
        .nonce("")
        .sign_at(&original, hop(), None, NOW)
        .unwrap();
    assert_eq!(signed.signature.n, None);
    assert!(!signed.to_header().contains("; n="));
}

// Content a recipe cannot recreate: a body with bare CR/LF gets a null body recipe, a header refuses to sign.
#[tokio::test]
async fn recipe_generator_handles_bare_line_breaks() {
    for (body, changed) in [
        (
            &b"line1\rmore\r\nline2\r\n"[..],
            &b"changed\r\nline2\r\n"[..],
        ),
        (b"line1\nmore\r\nline2\r\n", b"changed\r\nline2\r\n"),
    ] {
        let mut original =
            b"From: sender@test1.dkim2.com\r\nTo: r@example.com\r\nSubject: s\r\n\r\n".to_vec();
        original.extend_from_slice(body);
        let message1 = prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    &original,
                    Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            &original,
        );
        let mut modified = message1.clone();
        modified.truncate(message1.len() - body.len());
        modified.extend_from_slice(changed);
        let revised = signer("test2.dkim2.com")
            .out_of_band_arrangement()
            .sign_revised_at(
                &message1,
                &modified,
                Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                None,
                NOW,
            )
            .unwrap();
        assert_eq!(
            revised
                .message_instance
                .as_ref()
                .and_then(|instance| instance.recipe.as_ref())
                .map(|recipe| &recipe.body),
            Some(&crate::dkim2::BodyRecipe::Unreconstructable)
        );
        assert_eq!(
            verify_raw(
                &prepend(&revised, &modified),
                "relay@test2.dkim2.com",
                &["recipient@example.com"]
            )
            .await,
            fail(Dkim2Error::NullBodyRecipe(2))
        );
    }

    for (header, replacement) in [
        ("Subject: a\rb", "Subject: c"),
        ("Comments: x\n y", "Comments: z"),
    ] {
        let original = format!(
            "From: sender@test1.dkim2.com\r\nTo: r@example.com\r\n{header}\r\n\r\nbody\r\n"
        );
        let message1 = prepend(
            &signer("test1.dkim2.com")
                .sign_at(
                    original.as_bytes(),
                    Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                    None,
                    NOW,
                )
                .unwrap(),
            original.as_bytes(),
        );
        let modified = String::from_utf8(message1.clone())
            .unwrap()
            .replace(header, replacement);
        assert_eq!(
            signer("test2.dkim2.com")
                .out_of_band_arrangement()
                .sign_revised_at(
                    &message1,
                    modified.as_bytes(),
                    Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
                    None,
                    NOW,
                )
                .unwrap_err(),
            Error::Dkim2(Dkim2Error::HeaderNotRepresentable),
            "{header:?}"
        );
    }
}

// The validity proof covers the raw DKIM2 header fields, not just their parsed values.
#[tokio::test]
async fn validity_proof_is_bound_to_raw_fields() {
    let original = original();
    let message1 = prepend(
        &signer("test1.dkim2.com")
            .sign_at(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
                None,
                NOW,
            )
            .unwrap(),
        &original,
    );
    let parsed1 = AuthenticatedMessage::parse(&message1).unwrap();
    let proof = verify(
        &parsed1,
        "sender@test1.dkim2.com",
        &["list@test2.dkim2.com"],
        Verification::Full,
    )
    .await;
    assert_eq!(proof.result(), &Dkim2Result::Pass);
    let hop2 = || Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]);

    let tampered = String::from_utf8(message1.clone()).unwrap().replacen(
        "DKIM2-Signature: i=1;",
        "DKIM2-Signature: i=1; x=1;",
        1,
    );
    assert_eq!(
        AuthenticatedMessage::parse(tampered.as_bytes())
            .unwrap()
            .dkim2_signatures[0]
            .header,
        parsed1.dkim2_signatures[0].header
    );
    assert_eq!(
        signer("test2.dkim2.com")
            .sign_at(tampered.as_bytes(), hop2(), Some(&proof), NOW)
            .unwrap_err(),
        Error::Dkim2(Dkim2Error::NotFullyVerified)
    );
    let copy = message1.clone();
    signer("test2.dkim2.com")
        .sign_at(&copy, hop2(), Some(&proof), NOW)
        .unwrap();
}

// §14.6 note: a key that cannot be fetched is a TEMPERROR, but it does not hide a FAIL found elsewhere.
#[tokio::test]
async fn temp_error_does_not_hide_fail() {
    let original = original();
    let signed = signer("test1.dkim2.com")
        .hybrid_key(load_rsa("test1.dkim2.com", "sel1"), "unreachable")
        .sign_at(
            &original,
            Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            None,
            NOW,
        )
        .unwrap();
    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();
    caches.txt_add(
        "unreachable._domainkey.test1.dkim2.com.",
        TxtRecord::Error(Error::Dns(DnsError::Resolver("timeout".into()))),
        Instant::now() + Duration::new(3600, 0),
    );
    let verify = |raw: Vec<u8>| {
        let (resolver, caches) = (&resolver, &caches);
        async move {
            let message = AuthenticatedMessage::parse(&raw).unwrap();
            let params = caches.parameters(&message);
            resolver
                .verify_dkim2_(
                    &message,
                    Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]),
                    params.txt_cache(),
                    NOW,
                    true,
                    Verification::Full,
                )
                .await
                .result()
                .clone()
        }
    };
    let mut message = prepend(&signed, &original);
    assert!(matches!(
        verify(message.clone()).await,
        Dkim2Result::TempError(Error::Dkim2(Dkim2Error::PublicKeyFetch { i: 1, .. }))
    ));
    message.extend_from_slice(b"tampered\r\n");
    assert!(matches!(verify(message).await, Dkim2Result::Fail(_)));
}
