/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mail_auth::dkim2::Recipe;
use std::hint::black_box;

const BODY_LINES: usize = 2000;
const HEADERS: [(&[u8], &[u8]); 2] = [(b"From", b" a@example.org"), (b"Subject", b" test")];
const RECIPES: [(&str, &[u8]); 2] = [
    ("copy-all", br#"{"b":[{"c":[1,4294967295]}]}"#),
    (
        "edited",
        br#"{"b":[{"c":[1,500]},{"d":["changed line"]},{"c":[502,1500]},{"d":["footer"]}]}"#,
    ),
];

fn bodies() -> [(&'static str, Vec<u8>); 3] {
    let mut html = Vec::new();
    let mut text = Vec::new();
    let mut blank = Vec::new();
    for line in 0..BODY_LINES {
        html.extend(std::iter::repeat_n(b' ', (line % 8) * 2));
        html.extend_from_slice(
            b"<p class=\"x\">Hello <b>World</b>, your order has shipped.</p>\r\n",
        );
        text.extend_from_slice(
            b"The quick brown fox jumps over the lazy dog, again and again.\r\n",
        );
        if line % 4 == 0 {
            text.extend_from_slice(b"\r\n");
        }
    }
    for _ in 0..BODY_LINES * 16 {
        blank.extend_from_slice(b"\r\n");
    }
    [("html", html), ("text", text), ("blank", blank)]
}

fn apply(c: &mut Criterion) {
    let recipes = RECIPES.map(|(name, json)| {
        (
            name,
            Recipe::from_json(json).expect("benchmark recipe parses"),
        )
    });
    for (body_name, body) in bodies() {
        let mut group = c.benchmark_group(format!("recipe/{body_name}"));
        group.throughput(Throughput::Bytes(body.len() as u64));
        for (recipe_name, recipe) in &recipes {
            group.bench_function(*recipe_name, |b| {
                b.iter(|| recipe.apply(black_box(&HEADERS), black_box(&body)))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, apply);
criterion_main!(benches);
