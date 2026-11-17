/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mail_auth::AuthenticatedMessage;
use std::hint::black_box;

const FIXTURES: [(&str, &str, bool); 3] = [
    ("dkim", include_str!("../resources/dkim/001.txt"), true),
    ("arc", include_str!("../resources/arc/001.txt"), true),
    (
        "dkim2",
        include_str!("../resources/dkim2/emails/chain-list.eml"),
        false,
    ),
];
const EXTRA_BODY_LINES: usize = 1000;

fn message(fixture: &str, dns_preamble: bool, extra_body: bool) -> Vec<u8> {
    let raw = match fixture.split_once("\n\n") {
        Some((_, raw)) if dns_preamble => raw,
        _ => fixture,
    };
    let mut message = raw.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes();
    if extra_body {
        for _ in 0..EXTRA_BODY_LINES {
            message.extend_from_slice(
                b"The quick brown fox jumps over the lazy dog, again and again.\r\n",
            );
        }
    }
    message
}

fn parse(c: &mut Criterion) {
    for (name, fixture, dns_preamble) in FIXTURES {
        let mut group = c.benchmark_group(format!("parse/{name}"));
        for (label, extra_body) in [("fixture", false), ("large", true)] {
            let message = message(fixture, dns_preamble, extra_body);
            group.throughput(Throughput::Bytes(message.len() as u64));
            group.bench_function(label, |b| {
                b.iter(|| AuthenticatedMessage::parse(black_box(&message)))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, parse);
criterion_main!(benches);
