/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mail_auth::{
    dkim::Canonicalization,
    testing::{chunked_body_digest, whole_body_digest},
};
use std::hint::black_box;

const BODY_LINES: usize = 2000;
const STREAM_CHUNK: usize = 4096;

fn bodies() -> [(&'static str, Vec<u8>); 3] {
    let mut html = Vec::new();
    let mut text = Vec::new();
    let mut ragged = Vec::new();
    for line in 0..BODY_LINES {
        let indent = line % 8;
        html.extend(std::iter::repeat_n(b' ', indent * 2));
        html.extend_from_slice(
            b"<p class=\"x\">Hello <b>World</b>, your order has shipped.</p>\r\n",
        );
        text.extend_from_slice(
            b"The quick brown fox jumps over the lazy dog, again and again.\r\n",
        );
        if line % 4 == 0 {
            text.extend_from_slice(b"\r\n");
        }
        ragged.extend_from_slice(b"word\t\t  word   word \t\r\n");
        if line % 3 == 0 {
            ragged.extend_from_slice(b"   \t \r\n\r\n");
        }
    }
    ragged.extend_from_slice(b"  \r\n\t\r\n\r\n");
    [("html", html), ("text", text), ("ragged", ragged)]
}

fn canonicalize(c: &mut Criterion) {
    for (name, body) in bodies() {
        let mut group = c.benchmark_group(format!("body/{name}"));
        group.throughput(Throughput::Bytes(body.len() as u64));
        for (label, canonicalization) in [
            ("relaxed", Canonicalization::Relaxed),
            ("simple", Canonicalization::Simple),
        ] {
            group.bench_function(format!("{label}/whole"), |b| {
                b.iter(|| whole_body_digest(canonicalization, black_box(&body), 0))
            });
            group.bench_function(format!("{label}/stream"), |b| {
                b.iter(|| chunked_body_digest(canonicalization, black_box(&body), 0, STREAM_CHUNK))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, canonicalize);
criterion_main!(benches);
