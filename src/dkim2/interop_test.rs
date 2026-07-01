/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    AuthenticatedMessage, Dkim2Result, MessageAuthenticator,
    common::{
        cache::test::DummyCaches,
        crypto::{Ed25519Key, RsaKey, Sha256},
        parse::TxtRecordParser,
        verify::DomainKey,
    },
    dkim2::{
        Dkim2Signer, Envelope, Hop, sign::Dkim2Signed,
        verify::test_reverse_path::LenientReversePath,
    },
};
use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use testcontainers::{
    ContainerAsync, GenericBuildableImage, Image, ImageExt,
    core::{ExecCommand, Mount, WaitFor},
    runners::{AsyncBuilder, AsyncRunner},
};

const TS: u64 = 1740002100;
const NOW: u64 = 1740002100;
const READY: &str = "dkim2-interop-dns-ready";

const DOCKERFILE: &str = r#"
FROM golang:1.26-bookworm

# Default branches resolve to upstream HEAD (latest). Pin with a build arg.
ARG GO_DKIM2_REF=
ARG PY_INTEROP_REF=

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir cryptography dnslib

RUN git clone https://forge.turscar.ie/turscar/dkim2.git /src/go \
 && if [ -n "${GO_DKIM2_REF}" ]; then git -C /src/go checkout "${GO_DKIM2_REF}"; fi \
 && go build -C /src/go -o /usr/local/bin/dkim2sign ./cmd/dkim2sign \
 && go build -C /src/go -o /usr/local/bin/dkim2verify ./cmd/dkim2verify

RUN git clone https://github.com/dkim2wg/interop.git /src/interop \
 && if [ -n "${PY_INTEROP_REF}" ]; then git -C /src/interop checkout "${PY_INTEROP_REF}"; fi
ENV PYTHONPATH=/src/interop/python

COPY dns_server.py /usr/local/bin/dns_server.py

CMD ["python3", "/usr/local/bin/dns_server.py", "/res/dns.json"]
"#;

const DNS_SERVER_PY: &str = r#"
import json, sys, time
from dnslib import RR, QTYPE, TXT
from dnslib.server import DNSServer, BaseResolver


def chunks(value):
    raw = value.encode()
    return [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]


class Resolver(BaseResolver):
    def __init__(self, path):
        data = json.load(open(path))
        self.records = {}
        for domain, selectors in data.items():
            for selector_key, items in selectors.items():
                name = f"{selector_key}.{domain}.".lower()
                self.records[name] = items[0][1]

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).lower()
        if not qname.endswith("."):
            qname += "."
        value = self.records.get(qname)
        if value is not None and request.q.qtype in (QTYPE.TXT, QTYPE.ANY):
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, ttl=300, rdata=TXT(chunks(value))))
        return reply


resolver = Resolver(sys.argv[1])
DNSServer(resolver, port=53, address="0.0.0.0").start_thread()
DNSServer(resolver, port=53, address="0.0.0.0", tcp=True).start_thread()
print("dkim2-interop-dns-ready", flush=True)
while True:
    time.sleep(3600)
"#;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Alg {
    Ed25519,
    Rsa,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Im {
    Rust,
    Py,
    Go,
}

impl Im {
    fn name(self) -> &'static str {
        match self {
            Im::Rust => "rust",
            Im::Py => "py",
            Im::Go => "go",
        }
    }
}

const ALL: [Im; 3] = [Im::Rust, Im::Py, Im::Go];

#[derive(Clone, Copy)]
struct HopSpec {
    domain: &'static str,
    selector: &'static str,
    alg: Alg,
    mail_from: &'static str,
    rcpt_to: &'static [&'static str],
}

fn resource(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources/dkim2");
    for part in parts {
        path.push(part);
    }
    path
}

fn load_ed25519(domain: &str, selector: &str) -> Ed25519Key {
    let pem = std::fs::read(resource(&[
        "keys",
        &format!("{selector}._domainkey.{domain}.pem"),
    ]))
    .unwrap();
    let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
        panic!("expected PKCS8 key");
    };
    Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
}

fn load_rsa(domain: &str, selector: &str) -> RsaKey<Sha256> {
    let pem = std::fs::read(resource(&[
        "keys",
        &format!("{selector}._domainkey.{domain}.pem"),
    ]))
    .unwrap();
    RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(&pem).unwrap()).unwrap()
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

fn normalize_crlf(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    let mut iter = message.iter().peekable();
    while let Some(&ch) = iter.next() {
        match ch {
            b'\r' => {
                out.push(b'\r');
                out.push(b'\n');
                if iter.peek() == Some(&&b'\n') {
                    iter.next();
                }
            }
            b'\n' => {
                out.push(b'\r');
                out.push(b'\n');
            }
            _ => out.push(ch),
        }
    }
    out
}

fn prepend(signed: &Dkim2Signed, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 512);
    signed.write(&mut out);
    out.extend_from_slice(message);
    out
}

fn wrap(addr: &str) -> String {
    let addr = addr.trim();
    if addr.starts_with('<') && addr.ends_with('>') {
        addr.to_string()
    } else {
        format!("<{addr}>")
    }
}

fn key_path(hop: &HopSpec) -> String {
    format!("/res/keys/{}._domainkey.{}.pem", hop.selector, hop.domain)
}

fn rust_sign(message: &[u8], hop: &HopSpec) -> Vec<u8> {
    let envelope = Hop::real(hop.mail_from, hop.rcpt_to);
    let signed = match hop.alg {
        Alg::Ed25519 => Dkim2Signer::from_key(load_ed25519(hop.domain, hop.selector))
            .domain(hop.domain)
            .selector(hop.selector)
            .sign_at(message, envelope, TS)
            .unwrap(),
        Alg::Rsa => Dkim2Signer::from_key(load_rsa(hop.domain, hop.selector))
            .domain(hop.domain)
            .selector(hop.selector)
            .sign_at(message, envelope, TS)
            .unwrap(),
    };
    prepend(&signed, message)
}

async fn rust_verify(
    resolver: &MessageAuthenticator,
    caches: &DummyCaches,
    message: &[u8],
    mail_from: &str,
    rcpt_to: &[&str],
) -> (bool, String) {
    let Some(parsed) = AuthenticatedMessage::parse(message) else {
        return (false, "parse failed".to_string());
    };
    let params = caches.parameters(&parsed);
    let envelope = Envelope::new(mail_from, rcpt_to);
    let output = resolver
        .verify_dkim2_(&parsed, envelope, params.cache_txt, NOW, true)
        .await;
    let ok = *output.result() == Dkim2Result::Pass;
    let detail = if ok {
        String::new()
    } else {
        format!(
            "{:?}: {}",
            output.result(),
            output.failure_reason().unwrap_or_default()
        )
    };
    (ok, detail)
}

async fn exec_raw(
    container: &ContainerAsync<impl Image>,
    args: Vec<String>,
) -> (i64, Vec<u8>, Vec<u8>) {
    let mut result = container
        .exec(ExecCommand::new(args))
        .await
        .expect("exec failed");
    let stdout = result.stdout_to_vec().await.expect("stdout");
    let stderr = result.stderr_to_vec().await.expect("stderr");
    let code = result.exit_code().await.expect("exit code").unwrap_or(-1);
    (code, stdout, stderr)
}

async fn ext_sign(
    container: &ContainerAsync<impl Image>,
    work: &std::path::Path,
    idx: u32,
    im: Im,
    message: &[u8],
    hop: &HopSpec,
) -> Option<Vec<u8>> {
    let infile = format!("sign_in_{idx}.eml");
    std::fs::write(work.join(&infile), message).unwrap();
    let container_in = format!("/work/{infile}");

    let args: Vec<String> = match im {
        Im::Py => {
            let mut a = vec![
                "python3".into(),
                "/src/interop/python/dkim2sign.py".into(),
                container_in,
                "-s".into(),
                hop.selector.into(),
                "-d".into(),
                hop.domain.into(),
                "-k".into(),
                key_path(hop),
                "--mailfrom".into(),
                wrap(hop.mail_from),
                "--timestamp".into(),
                TS.to_string(),
            ];
            for rcpt in hop.rcpt_to {
                a.push("--rcptto".into());
                a.push(wrap(rcpt));
            }
            a
        }
        Im::Go => {
            let mut a = vec![
                "dkim2sign".into(),
                "--in".into(),
                container_in,
                "--domain".into(),
                hop.domain.into(),
                "--selector".into(),
                hop.selector.into(),
                "--key".into(),
                key_path(hop),
                "--from".into(),
                wrap(hop.mail_from),
                "--timestamp".into(),
                TS.to_string(),
            ];
            for rcpt in hop.rcpt_to {
                a.push("--to".into());
                a.push(wrap(rcpt));
            }
            a
        }
        Im::Rust => unreachable!(),
    };

    let (code, stdout, stderr) = exec_raw(container, args).await;
    if code != 0 || stdout.is_empty() {
        eprintln!(
            "[{} sign] exit={code} stderr={}",
            im.name(),
            String::from_utf8_lossy(&stderr)
        );
        return None;
    }
    Some(stdout)
}

async fn ext_verify(
    container: &ContainerAsync<impl Image>,
    work: &std::path::Path,
    idx: u32,
    im: Im,
    message: &[u8],
    mail_from: &str,
    rcpt_to: &[&str],
) -> bool {
    let vfile = format!("verify_in_{idx}.eml");
    std::fs::write(work.join(&vfile), message).unwrap();
    let container_in = format!("/work/{vfile}");

    match im {
        Im::Py => {
            let args = vec![
                "python3".into(),
                "/src/interop/python/dkim2verify.py".into(),
                container_in,
                "--dns-json".into(),
                "/res/dns.json".into(),
                "--ignore-timestamps".into(),
            ];
            let (code, _, _) = exec_raw(container, args).await;
            code == 0
        }
        Im::Go => {
            let mut args = vec![
                "dkim2verify".into(),
                "--in".into(),
                container_in,
                "--from".into(),
                wrap(mail_from),
                "--server".into(),
                "127.0.0.1:53".into(),
                "--ignore-timestamp".into(),
            ];
            for rcpt in rcpt_to {
                args.push("--to".into());
                args.push(wrap(rcpt));
            }
            let (_, stdout, stderr) = exec_raw(container, args).await;
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            combined.contains("Authentication result:") && !combined.contains("Error:")
        }
        Im::Rust => unreachable!(),
    }
}

async fn sign_hop(
    container: &ContainerAsync<impl Image>,
    work: &std::path::Path,
    idx: u32,
    im: Im,
    message: &[u8],
    hop: &HopSpec,
) -> Option<Vec<u8>> {
    match im {
        Im::Rust => Some(rust_sign(message, hop)),
        other => ext_sign(container, work, idx, other, message, hop).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_msg(
    container: &ContainerAsync<impl Image>,
    resolver: &MessageAuthenticator,
    caches: &DummyCaches,
    work: &std::path::Path,
    idx: u32,
    im: Im,
    message: &[u8],
    mail_from: &str,
    rcpt_to: &[&str],
) -> (bool, String) {
    match im {
        Im::Rust => rust_verify(resolver, caches, message, mail_from, rcpt_to).await,
        other => (
            ext_verify(container, work, idx, other, message, mail_from, rcpt_to).await,
            String::new(),
        ),
    }
}

/// End-to-end DKIM2 interoperability matrix against the upstream Python
/// (dkim2wg/interop) and Go (turscar/dkim2) reference implementations.
///
/// Run with:
///
///   cargo test --lib dkim2::interop_test -- --ignored --nocapture
///
/// Pin the upstream revisions via Docker build args GO_DKIM2_REF /
/// PY_INTEROP_REF (defaults track upstream HEAD).
#[tokio::test]
#[ignore = "requires Docker and network access to upstream DKIM2 reference repos"]
async fn dkim2_interop_matrix() {
    let _lenient = LenientReversePath::new();

    let res_dir = resource(&[]);
    let work = tempfile::tempdir().expect("tempdir");

    let image = GenericBuildableImage::new("mail-auth-dkim2-interop", "latest")
        .with_dockerfile_string(DOCKERFILE)
        .with_data(DNS_SERVER_PY, "./dns_server.py")
        .build_image()
        .await
        .expect("failed to build interop image (is Docker running?)");

    let container = image
        .with_wait_for(WaitFor::message_on_stdout(READY))
        .with_mount(Mount::bind_mount(
            res_dir.to_string_lossy().into_owned(),
            "/res",
        ))
        .with_mount(Mount::bind_mount(
            work.path().to_string_lossy().into_owned(),
            "/work",
        ))
        .start()
        .await
        .expect("failed to start interop container");

    let resolver = MessageAuthenticator::new_system_conf().unwrap();
    let caches = load_caches();

    let original = normalize_crlf(&std::fs::read(resource(&["emails", "simple.eml"])).unwrap());

    let mut idx = 0u32;
    let mut failures: Vec<String> = Vec::new();

    // Single hop, both algorithms, every producer x every verifier.
    let single_hops = [
        HopSpec {
            domain: "test1.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "sender@test1.dkim2.com",
            rcpt_to: &["recipient@example.com"],
        },
        HopSpec {
            domain: "test1.dkim2.com",
            selector: "sel1",
            alg: Alg::Rsa,
            mail_from: "sender@test1.dkim2.com",
            rcpt_to: &["recipient@example.com"],
        },
    ];

    for hop in &single_hops {
        for signer in ALL {
            idx += 1;
            let Some(signed) = sign_hop(&container, work.path(), idx, signer, &original, hop).await
            else {
                failures.push(format!(
                    "single/{}/{}: SIGN failed",
                    alg_tag(hop.alg),
                    signer.name()
                ));
                continue;
            };
            for verifier in ALL {
                idx += 1;
                let (ok, detail) = verify_msg(
                    &container,
                    &resolver,
                    &caches,
                    work.path(),
                    idx,
                    verifier,
                    &signed,
                    hop.mail_from,
                    hop.rcpt_to,
                )
                .await;
                let label = format!(
                    "single/{}/{}->{}",
                    alg_tag(hop.alg),
                    signer.name(),
                    verifier.name()
                );
                if !ok {
                    failures.push(format!("{label}: VERIFY failed {detail}"));
                }
                println!("{label}: {}", if ok { "pass" } else { "FAIL" });
            }
        }
    }

    // Two-hop chains: every (hop1 signer, hop2 signer) x every verifier.
    let two_hop = [
        HopSpec {
            domain: "test1.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "sender@test1.dkim2.com",
            rcpt_to: &["list@test2.dkim2.com"],
        },
        HopSpec {
            domain: "test2.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "relay@test2.dkim2.com",
            rcpt_to: &["recipient@example.com"],
        },
    ];
    let top = two_hop[two_hop.len() - 1];

    for s1 in ALL {
        for s2 in ALL {
            idx += 1;
            let Some(msg1) =
                sign_hop(&container, work.path(), idx, s1, &original, &two_hop[0]).await
            else {
                failures.push(format!(
                    "multihop2/{}-{}: HOP1 sign failed",
                    s1.name(),
                    s2.name()
                ));
                continue;
            };
            idx += 1;
            let Some(msg2) = sign_hop(&container, work.path(), idx, s2, &msg1, &two_hop[1]).await
            else {
                failures.push(format!(
                    "multihop2/{}-{}: HOP2 sign failed",
                    s1.name(),
                    s2.name()
                ));
                continue;
            };
            for verifier in ALL {
                idx += 1;
                let (ok, detail) = verify_msg(
                    &container,
                    &resolver,
                    &caches,
                    work.path(),
                    idx,
                    verifier,
                    &msg2,
                    top.mail_from,
                    top.rcpt_to,
                )
                .await;
                let label = format!("multihop2/{}-{}->{}", s1.name(), s2.name(), verifier.name());
                if !ok {
                    failures.push(format!("{label}: VERIFY failed {detail}"));
                }
                println!("{label}: {}", if ok { "pass" } else { "FAIL" });
            }
        }
    }

    // Three-hop chains across a representative set of producer combinations.
    let three_hop = [
        HopSpec {
            domain: "test1.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "sender@test1.dkim2.com",
            rcpt_to: &["list@test2.dkim2.com"],
        },
        HopSpec {
            domain: "test2.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "relay@test2.dkim2.com",
            rcpt_to: &["fwd@test3.dkim2.com"],
        },
        HopSpec {
            domain: "test3.dkim2.com",
            selector: "ed25519",
            alg: Alg::Ed25519,
            mail_from: "gateway@test3.dkim2.com",
            rcpt_to: &["recipient@example.com"],
        },
    ];
    let top3 = three_hop[three_hop.len() - 1];
    let patterns = [
        [Im::Rust, Im::Py, Im::Go],
        [Im::Go, Im::Py, Im::Rust],
        [Im::Rust, Im::Rust, Im::Rust],
        [Im::Py, Im::Py, Im::Py],
        [Im::Go, Im::Go, Im::Go],
    ];

    for pattern in patterns {
        idx += 1;
        let mut message = original.clone();
        let mut chain_ok = true;
        for (hop_idx, signer) in pattern.iter().enumerate() {
            idx += 1;
            match sign_hop(
                &container,
                work.path(),
                idx,
                *signer,
                &message,
                &three_hop[hop_idx],
            )
            .await
            {
                Some(next) => message = next,
                None => {
                    failures.push(format!(
                        "multihop3/{}-{}-{}: HOP{} sign failed",
                        pattern[0].name(),
                        pattern[1].name(),
                        pattern[2].name(),
                        hop_idx + 1
                    ));
                    chain_ok = false;
                    break;
                }
            }
        }
        if !chain_ok {
            continue;
        }
        for verifier in ALL {
            idx += 1;
            let (ok, detail) = verify_msg(
                &container,
                &resolver,
                &caches,
                work.path(),
                idx,
                verifier,
                &message,
                top3.mail_from,
                top3.rcpt_to,
            )
            .await;
            let label = format!(
                "multihop3/{}-{}-{}->{}",
                pattern[0].name(),
                pattern[1].name(),
                pattern[2].name(),
                verifier.name()
            );
            if !ok {
                failures.push(format!("{label}: VERIFY failed {detail}"));
            }
            println!("{label}: {}", if ok { "pass" } else { "FAIL" });
        }
    }

    assert!(
        failures.is_empty(),
        "DKIM2 interop matrix had {} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn alg_tag(alg: Alg) -> &'static str {
    match alg {
        Alg::Ed25519 => "ed25519",
        Alg::Rsa => "rsa",
    }
}
