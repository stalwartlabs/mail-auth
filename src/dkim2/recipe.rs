/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::AuthenticatedMessage;
use crate::dkim2::Dkim2Error;
use crate::dkim2::canonicalize::{cmp_ignore_ascii_case, is_non_signed_header};
use similar::{Algorithm, DiffOp, capture_diff_slices};
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Recipe {
    pub headers: Vec<HeaderRecipe>,
    pub body: BodyRecipe,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HeaderRecipe {
    pub name: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum BodyRecipe {
    #[default]
    None,
    Steps(Vec<Step>),
    Unreconstructable,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Step {
    Copy { start: u32, end: u32 },
    Data(Vec<String>),
}

struct LowerHeader<'x>(&'x [u8]);

impl<'x> LowerHeader<'x> {
    fn new(header: &'x [u8]) -> Self {
        LowerHeader(header.trim_ascii())
    }
}

impl PartialEq for LowerHeader<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Ord for LowerHeader<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_ignore_ascii_case(self.0, other.0)
    }
}

impl PartialOrd for LowerHeader<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for LowerHeader<'_> {}

impl std::hash::Hash for LowerHeader<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for byte in self.0 {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

#[derive(Default)]
struct HeaderDiff<'x> {
    original: Vec<&'x [u8]>,
    modified: Vec<&'x [u8]>,
}

#[derive(Default)]
struct HeaderApply<'x> {
    current: Vec<&'x [u8]>,
    recipe: Option<&'x HeaderRecipe>,
}

impl Recipe {
    /// Generates the recipe that turns `modified` back into `original`.
    pub fn diff(
        original: &AuthenticatedMessage<'_>,
        modified: &AuthenticatedMessage<'_>,
    ) -> Recipe {
        let mut header_diffs: BTreeMap<LowerHeader<'_>, HeaderDiff> = BTreeMap::new();

        for (name, value) in &original.headers {
            if !is_non_signed_header(name) {
                header_diffs
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .original
                    .push(value.trim_ascii());
            }
        }
        for (name, value) in &modified.headers {
            if !is_non_signed_header(name) {
                header_diffs
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .modified
                    .push(value.trim_ascii());
            }
        }

        let mut headers = Vec::new();
        for (header, mut values) in header_diffs {
            if values.original != values.modified {
                values.original.reverse();
                values.modified.reverse();

                let steps = diff_steps(&values.original, &values.modified);
                headers.push(HeaderRecipe {
                    name: std::str::from_utf8(header.0)
                        .map(str::to_ascii_lowercase)
                        .unwrap_or_else(|_| String::from_utf8_lossy(header.0).to_ascii_lowercase()),
                    steps,
                });
            }
        }

        let orig_body = original.raw_body();
        let mod_body = modified.raw_body();
        let body = if orig_body == mod_body {
            BodyRecipe::None
        } else {
            let orig_lines = body_lines(orig_body);
            let mod_lines = body_lines(mod_body);
            BodyRecipe::Steps(diff_steps(&orig_lines, &mod_lines))
        };

        Recipe { headers, body }
    }

    /// Applies this recipe to reconstruct the previous message state.
    pub fn apply(&self, headers: &[(&[u8], &[u8])], body: &[u8]) -> crate::Result<Vec<u8>> {
        let mut header_apply: BTreeMap<LowerHeader<'_>, HeaderApply> = BTreeMap::new();

        for (name, value) in headers {
            if !is_non_signed_header(name) {
                header_apply
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .current
                    .push(value.trim_ascii());
            }
        }

        for recipe in &self.headers {
            header_apply
                .entry(LowerHeader::new(recipe.name.as_bytes()))
                .or_default()
                .recipe = Some(recipe);
        }

        let mut out = Vec::new();
        for (name, apply) in header_apply {
            let header_values = if let Some(recipe) = apply.recipe {
                apply_header_recipe(&apply.current, &recipe.steps)
            } else {
                apply.current
            };

            for current in header_values {
                out.extend_from_slice(name.0);
                out.extend_from_slice(b": ");
                out.extend_from_slice(current);
                out.extend_from_slice(b"\r\n");
            }
        }

        out.extend_from_slice(b"\r\n");

        match &self.body {
            BodyRecipe::None => {
                out.extend_from_slice(body);
            }
            BodyRecipe::Unreconstructable => {
                return Err(crate::Error::Dkim2(Dkim2Error::Modified));
            }
            BodyRecipe::Steps(steps) => {
                let lines = body_lines(body);
                apply_body_recipe(&lines, steps, &mut out);
            }
        }

        Ok(out)
    }

    pub fn to_json(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        serde_json::to_writer(out, self).map_err(|_| crate::Error::Dkim2(Dkim2Error::Modified))
    }

    pub fn from_json(bytes: &[u8]) -> crate::Result<Recipe> {
        serde_json::from_slice(bytes).map_err(|_| crate::Error::Dkim2(Dkim2Error::Modified))
    }
}

fn body_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::with_capacity(16);

    for line in body.split(|ch| *ch == b'\n') {
        lines.push(line.strip_suffix(b"\r").unwrap_or(line));
    }

    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }

    lines
}

fn apply_header_recipe<'x>(instances: &[&'x [u8]], steps: &'x [Step]) -> Vec<&'x [u8]> {
    let mut emitted: Vec<&'x [u8]> = Vec::new();

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                let high = (*end).min(instances.len() as u32);
                for i in *start..=high {
                    if let Some(line) = instances
                        .len()
                        .checked_sub(i as usize)
                        .and_then(|idx| instances.get(idx))
                    {
                        emitted.push(*line);
                    }
                }
            }
            Step::Data(values) => {
                for value in values {
                    emitted.push(value.as_bytes());
                }
            }
        }
    }

    emitted.reverse();
    emitted
}

fn apply_body_recipe(lines: &[&[u8]], steps: &[Step], out: &mut Vec<u8>) {
    let mark = out.len();

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                let high = (*end).min(lines.len() as u32);
                for i in *start..=high {
                    if let Some(idx) = (i as usize).checked_sub(1)
                        && let Some(line) = lines.get(idx)
                    {
                        out.extend_from_slice(line);
                        out.extend_from_slice(b"\r\n");
                    }
                }
            }
            Step::Data(values) => {
                for value in values {
                    out.extend_from_slice(value.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
    }

    if out.len() == mark {
        out.extend_from_slice(b"\r\n");
    }
}

fn diff_steps(original: &[&[u8]], modified: &[&[u8]]) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    let mut data: Vec<String> = Vec::new();

    for op in capture_diff_slices(Algorithm::Myers, modified, original) {
        match op {
            DiffOp::Equal { old_index, len, .. } => {
                if !data.is_empty() {
                    steps.push(Step::Data(std::mem::take(&mut data)));
                }
                steps.push(Step::Copy {
                    start: old_index as u32 + 1,
                    end: (old_index + len) as u32,
                });
            }
            DiffOp::Insert {
                new_index, new_len, ..
            }
            | DiffOp::Replace {
                new_index, new_len, ..
            } => {
                for line in &original[new_index..new_index + new_len] {
                    data.push(unfold_lossy(line));
                }
            }
            DiffOp::Delete { .. } => {}
        }
    }
    if !data.is_empty() {
        steps.push(Step::Data(data));
    }
    steps
}

fn unfold_lossy(value: &[u8]) -> String {
    let mut result = Vec::with_capacity(value.len());
    let mut last_is_crlf = false;

    for &ch in value {
        match ch {
            b'\r' | b'\n' => {
                last_is_crlf = true;
            }
            _ => {
                if last_is_crlf && !ch.is_ascii_whitespace() && !result.is_empty() {
                    result.push(b' ');
                }
                result.push(ch);
                last_is_crlf = false;
            }
        }
    }

    String::from_utf8(result)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

#[cfg(test)]
mod test {
    use super::*;

    fn r_headers(name: &str, steps: Vec<Step>) -> Recipe {
        Recipe {
            headers: vec![HeaderRecipe {
                name: name.to_string(),
                steps,
            }],
            body: BodyRecipe::None,
        }
    }

    fn json(recipe: &Recipe) -> Vec<u8> {
        let mut out = Vec::new();
        recipe.to_json(&mut out).unwrap();
        out
    }

    #[test]
    fn to_json_byte_equality() {
        let r1 = r_headers("list-unsubscribe", vec![]);
        assert_eq!(json(&r1), b"{\"h\":{\"list-unsubscribe\":[]}}");

        let r2 = Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(vec![Step::Copy { start: 1, end: 1 }]),
        };
        assert_eq!(json(&r2), b"{\"b\":[{\"c\":[1,1]}]}");

        let r3 = r_headers(
            "subject",
            vec![Step::Data(vec![" Simple test message".to_string()])],
        );
        assert_eq!(
            json(&r3),
            b"{\"h\":{\"subject\":[{\"d\":[\" Simple test message\"]}]}}"
        );

        let r4 = r_headers(
            "authentication-results",
            vec![Step::Copy { start: 1, end: 3 }],
        );
        assert_eq!(
            json(&r4),
            b"{\"h\":{\"authentication-results\":[{\"c\":[1,3]}]}}"
        );
    }

    #[test]
    fn from_json_round_trips() {
        let cases: [&[u8]; 4] = [
            b"{\"h\":{\"list-unsubscribe\":[]}}",
            b"{\"b\":[{\"c\":[1,1]}]}",
            b"{\"h\":{\"subject\":[{\"d\":[\" Simple test message\"]}]}}",
            b"{\"h\":{\"authentication-results\":[{\"c\":[1,3]}]}}",
        ];
        for case in cases {
            let recipe = Recipe::from_json(case).unwrap();
            assert_eq!(json(&recipe), case);
        }
    }

    #[test]
    fn from_json_rejects_null_header() {
        assert!(Recipe::from_json(b"{\"h\":null}").is_err());
        assert!(Recipe::from_json(b"{\"h\":{\"subject\":null}}").is_err());
    }

    #[test]
    fn from_json_body_null_unreconstructable() {
        let recipe = Recipe::from_json(b"{\"b\":null}").unwrap();
        assert_eq!(recipe.body, BodyRecipe::Unreconstructable);
    }

    #[test]
    fn from_json_ignores_z_step() {
        let recipe = Recipe::from_json(b"{\"b\":[{\"c\":[1,2]},{\"z\":true}]}").unwrap();
        assert_eq!(
            recipe.body,
            BodyRecipe::Steps(vec![Step::Copy { start: 1, end: 2 }])
        );
    }

    fn diff_bytes(original: &[u8], modified: &[u8]) -> Recipe {
        let o = crate::AuthenticatedMessage::parse(original).unwrap();
        let m = crate::AuthenticatedMessage::parse(modified).unwrap();
        Recipe::diff(&o, &m)
    }

    fn apply_bytes(recipe: &Recipe, message: &[u8]) -> crate::Result<Vec<u8>> {
        let p = crate::AuthenticatedMessage::parse(message).unwrap();
        recipe.apply(&p.headers, p.raw_body())
    }

    fn signed_hashes(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use crate::common::crypto::HashAlgorithm;
        let p = crate::AuthenticatedMessage::parse(message).unwrap();
        (
            HashAlgorithm::Sha256
                .headers_hash(p.headers.iter().copied())
                .as_ref()
                .to_vec(),
            HashAlgorithm::Sha256
                .body_hash(p.raw_body())
                .as_ref()
                .to_vec(),
        )
    }

    #[test]
    fn diff_apply_round_trips() {
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "body_change",
                b"Subject: test\r\n\r\nhello\r\nworld\r\ngoodbye\r\n",
                b"Subject: test\r\n\r\nhello\r\nMODIFIED\r\ngoodbye\r\n",
            ),
            (
                "body_insert_delete",
                b"From: a\r\n\r\nline1\r\nline2\r\nline3\r\nline4\r\n",
                b"From: a\r\n\r\nline1\r\nline3\r\nline4\r\nextra\r\n",
            ),
            (
                "header_add",
                b"Subject: hi\r\nFrom: a\r\nTo: b\r\n\r\nbody\r\n",
                b"From: a\r\nTo: b\r\n\r\nbody\r\n",
            ),
            (
                "header_remove",
                b"From: a\r\nTo: b\r\n\r\nbody\r\n",
                b"From: a\r\nSubject: spam\r\nTo: b\r\n\r\nbody\r\n",
            ),
            (
                "header_value_change",
                b"Subject: original subject\r\nFrom: a\r\n\r\nbody\r\n",
                b"Subject: changed subject\r\nFrom: a\r\n\r\nbody\r\n",
            ),
            (
                "dup_header_change",
                b"From: a\r\nList-Id: one\r\nList-Id: two\r\n\r\nbody\r\n",
                b"From: a\r\nList-Id: one\r\nList-Id: CHANGED\r\n\r\nbody\r\n",
            ),
            (
                "unchanged",
                b"From: a\r\nTo: b\r\n\r\nbody line\r\n",
                b"From: a\r\nTo: b\r\n\r\nbody line\r\n",
            ),
            (
                "header_reorder",
                b"Subject: one\r\nComment: two\r\nSubject: three\r\n\r\nbody\r\n",
                b"Comment: two\r\nSubject: three\r\nSubject: one\r\n\r\nbody\r\n",
            ),
            (
                "body_multi_range",
                b"From: a\r\n\r\none\r\ntwo\r\nthree\r\nfour\r\nfive\r\n",
                b"From: a\r\n\r\nzero\r\none\r\ntwo\r\nthree\r\nbanana\r\nfour\r\n",
            ),
        ];
        for (label, original, modified) in cases {
            let recipe = diff_bytes(original, modified);
            let reconstructed = apply_bytes(&recipe, modified).unwrap();
            assert_eq!(
                signed_hashes(&reconstructed),
                signed_hashes(original),
                "case {label}: recipe={recipe:?} reconstructed={:?}",
                String::from_utf8_lossy(&reconstructed)
            );
        }
    }

    #[test]
    fn myers_diff_serialization() {
        let cases: &[(&str, &[u8], &[u8], &str)] = &[
            (
                "deleted",
                b"Comment: two\r\nSubject: three\r\nSubject: four\r\nSubject: one\r\n\r\nbody\r\n",
                b"Comment: two\r\nSubject: three\r\nSubject: one\r\n\r\nbody\r\n",
                r#"{"h":{"subject":[{"c":[1,1]},{"d":["four"]},{"c":[2,2]}]}}"#,
            ),
            (
                "ranges",
                b"Subject: one\r\nSubject: two\r\nSubject: three\r\nSubject: four\r\nSubject: five\r\n\r\nbody\r\n",
                b"Subject: zero\r\nSubject: one\r\nSubject: two\r\nSubject: three\r\nSubject: banana\r\nSubject: four\r\n\r\nbody\r\n",
                r#"{"h":{"subject":[{"d":["five"]},{"c":[1,1]},{"c":[3,5]}]}}"#,
            ),
            (
                "reorder",
                b"Subject: one\r\nComment: two\r\nSubject: three\r\n\r\nbody\r\n",
                b"Comment: two\r\nSubject: three\r\nSubject: one\r\n\r\nbody\r\n",
                r#"{"h":{"subject":[{"d":["three"]},{"c":[1,1]}]}}"#,
            ),
            (
                "body_multi_range",
                b"From: a\r\n\r\nl1\r\nl2\r\nl3\r\nold-line\r\nl5\r\n",
                b"From: a\r\n\r\nl1\r\nl2\r\nl3\r\nnew-line\r\nl5\r\n",
                r#"{"b":[{"c":[1,3]},{"d":["old-line"]},{"c":[5,5]}]}"#,
            ),
        ];
        for (label, original, modified, want) in cases {
            let recipe = diff_bytes(original, modified);
            let mut json = Vec::new();
            recipe.to_json(&mut json).unwrap();
            assert_eq!(String::from_utf8_lossy(&json), *want, "case {label}");
            let reconstructed = apply_bytes(&recipe, modified).unwrap();
            assert_eq!(
                signed_hashes(&reconstructed),
                signed_hashes(original),
                "case {label} round-trip"
            );
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn apply_header_oracles() {
        fn headers_of(message: &[u8]) -> Vec<(String, String)> {
            let p = crate::AuthenticatedMessage::parse(message).unwrap();
            let mut headers: Vec<(String, String)> = p
                .headers
                .iter()
                .map(|(n, v)| {
                    (
                        String::from_utf8_lossy(n).trim().to_ascii_lowercase(),
                        String::from_utf8_lossy(v).trim().to_string(),
                    )
                })
                .collect();
            headers.sort();
            headers
        }

        let input = b"Subject: one\r\nComment: two\r\nSubject: three\r\n\r\n";
        let cases: &[(&str, &[u8], &[(&str, &str)])] = &[
            (
                "copy_one",
                br#"{"h":{"subject":[{"c":[2,2]}],"comment":[]}}"#,
                &[("subject", "one")],
            ),
            (
                "preserve_unmentioned",
                br#"{"h":{"comment":[]}}"#,
                &[("subject", "one"), ("subject", "three")],
            ),
            (
                "no_change",
                br#"{}"#,
                &[("comment", "two"), ("subject", "one"), ("subject", "three")],
            ),
        ];

        for (label, json, want) in cases {
            let recipe = Recipe::from_json(json).unwrap();
            let reconstructed = apply_bytes(&recipe, input).unwrap();
            let mut want: Vec<(String, String)> = want
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
            want.sort();
            assert_eq!(
                headers_of(&reconstructed),
                want,
                "case {label}: {}",
                String::from_utf8_lossy(&reconstructed)
            );
        }
    }

    #[test]
    fn apply_unreconstructable_errors() {
        let recipe = Recipe {
            headers: vec![],
            body: BodyRecipe::Unreconstructable,
        };
        assert!(apply_bytes(&recipe, b"From: a\r\n\r\nbody\r\n").is_err());
    }

    #[test]
    fn to_json_non_ascii_round_trips() {
        let recipe = r_headers("subject", vec![Step::Data(vec!["café \u{1}".to_string()])]);
        let encoded = json(&recipe);
        assert_eq!(
            encoded,
            "{\"h\":{\"subject\":[{\"d\":[\"café \\u0001\"]}]}}".as_bytes()
        );
        let decoded = Recipe::from_json(&encoded).unwrap();
        assert_eq!(decoded.headers[0].steps, recipe.headers[0].steps);
    }

    #[test]
    fn copy_range_huge_end_is_bounded() {
        let recipe = Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(vec![Step::Copy {
                start: 1,
                end: u32::MAX,
            }]),
        };
        let start = std::time::Instant::now();
        let out = apply_bytes(&recipe, b"From: a\r\n\r\nline1\r\nline2\r\n").unwrap();
        assert!(start.elapsed().as_secs() < 1);
        assert!(out.windows(5).any(|w| w == b"line1"));
    }

    #[test]
    fn non_utf8_body_round_trips() {
        let original: &[u8] = b"From: a\r\n\r\nhel\x80lo\r\nworld\r\n";
        let modified: &[u8] = b"From: a\r\n\r\nhel\x80lo\r\nWORLD\r\n";
        let recipe = diff_bytes(original, modified);
        let reconstructed = apply_bytes(&recipe, modified).unwrap();
        assert_eq!(signed_hashes(&reconstructed), signed_hashes(original));
        assert!(reconstructed.contains(&0x80));
    }

    #[test]
    fn copy_out_of_range_does_not_panic() {
        let recipe = Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(vec![Step::Copy { start: 5, end: 10 }]),
        };
        let out = apply_bytes(&recipe, b"From: a\r\n\r\nline1\r\nline2\r\n").unwrap();
        assert!(String::from_utf8_lossy(&out).contains("\r\n\r\n"));
    }

    #[test]
    fn copy_zero_start_does_not_panic() {
        let recipe = Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(vec![Step::Copy { start: 0, end: 2 }]),
        };
        apply_bytes(&recipe, b"X: y\r\n\r\nl1\r\nl2\r\n").unwrap();
    }

    #[test]
    fn from_json_huge_copy_is_bounded_on_apply() {
        let r = Recipe::from_json(b"{\"b\":[{\"c\":[4294967295,4294967295]}]}").unwrap();
        let out = apply_bytes(&r, b"X: y\r\n\r\nl1\r\n").unwrap();
        assert!(String::from_utf8_lossy(&out).contains("\r\n\r\n"));
    }

    #[test]
    fn apply_inserts_missing_header() {
        let recipe = Recipe {
            headers: vec![HeaderRecipe {
                name: "subject".to_string(),
                steps: vec![Step::Data(vec!["Injected".to_string()])],
            }],
            body: BodyRecipe::None,
        };
        let out = apply_bytes(&recipe, b"From: a\r\nTo: b\r\n\r\nbody\r\n").unwrap();
        assert!(String::from_utf8_lossy(&out).contains("subject: Injected"));
    }

    fn assert_chain_reconstructs(versions: &[&[u8]], via_json: bool) {
        assert!(versions.len() >= 2, "a chain needs at least two versions");

        let recipes: Vec<Recipe> = versions
            .windows(2)
            .map(|pair| {
                let recipe = diff_bytes(pair[0], pair[1]);
                if via_json {
                    Recipe::from_json(&json(&recipe)).unwrap()
                } else {
                    recipe
                }
            })
            .collect();

        let mut current = versions[versions.len() - 1].to_vec();
        for (hop, recipe) in recipes.iter().enumerate().rev() {
            let reconstructed = apply_bytes(recipe, &current).unwrap();
            let expected = versions[hop];
            assert_eq!(
                signed_hashes(&reconstructed),
                signed_hashes(expected),
                "hop {hop} (via_json={via_json}) recipe={recipe:?}\n  reconstructed={:?}\n  expected={:?}",
                String::from_utf8_lossy(&reconstructed),
                String::from_utf8_lossy(expected),
            );
            current = reconstructed;
        }
    }

    fn assert_chain(versions: &[&[u8]]) {
        assert_chain_reconstructs(versions, false);
        assert_chain_reconstructs(versions, true);
    }

    #[test]
    fn chain_header_value_changes() {
        assert_chain(&[
            b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: v0\r\n\r\nHello world\r\n",
            b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: v1\r\n\r\nHello world\r\n",
            b"From: alice@example.com\r\nTo: carol@example.com\r\nSubject: v2\r\n\r\nHello world\r\n",
            b"From: alice@example.com\r\nTo: carol@example.com\r\nSubject: final\r\n\r\nHello world\r\n",
        ]);
    }

    #[test]
    fn chain_header_insertions() {
        assert_chain(&[
            b"From: a\r\nTo: b\r\n\r\nbody\r\n",
            b"From: a\r\nTo: b\r\nSubject: added\r\n\r\nbody\r\n",
            b"From: a\r\nReply-To: r\r\nTo: b\r\nSubject: added\r\n\r\nbody\r\n",
            b"From: a\r\nReply-To: r\r\nTo: b\r\nSubject: added\r\nList-Id: <l>\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_header_deletions() {
        assert_chain(&[
            b"From: a\r\nReply-To: r\r\nTo: b\r\nSubject: s\r\nList-Id: <l>\r\n\r\nbody\r\n",
            b"From: a\r\nTo: b\r\nSubject: s\r\nList-Id: <l>\r\n\r\nbody\r\n",
            b"From: a\r\nTo: b\r\nList-Id: <l>\r\n\r\nbody\r\n",
            b"From: a\r\nTo: b\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_mixed_header_insert_change_delete() {
        assert_chain(&[
            b"From: a\r\nTo: b\r\nSubject: original\r\n\r\nbody\r\n",
            b"From: a\r\nReply-To: r\r\nTo: b\r\nSubject: original\r\n\r\nbody\r\n",
            b"From: a\r\nReply-To: r\r\nTo: b\r\nSubject: edited\r\n\r\nbody\r\n",
            b"From: a\r\nReply-To: r\r\nTo: b\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_duplicate_header_evolution() {
        assert_chain(&[
            b"From: a\r\nComments: alpha\r\nComments: beta\r\n\r\nbody\r\n",
            b"From: a\r\nComments: alpha\r\nComments: beta\r\nComments: gamma\r\n\r\nbody\r\n",
            b"From: a\r\nComments: alpha\r\nComments: gamma\r\n\r\nbody\r\n",
            b"From: a\r\nComments: ALPHA\r\nComments: gamma\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_duplicate_header_interleaved_changes() {
        assert_chain(&[
            b"From: a\r\nReceived-SPF: a\r\nComments: 1\r\nComments: 2\r\nComments: 3\r\nComments: 4\r\nComments: 5\r\n\r\nbody\r\n",
            b"From: a\r\nReceived-SPF: a\r\nComments: 1\r\nComments: 2\r\nComments: THREE\r\nComments: 4\r\nComments: 5\r\n\r\nbody\r\n",
            b"From: a\r\nReceived-SPF: a\r\nComments: 1\r\nComments: THREE\r\nComments: 5\r\n\r\nbody\r\n",
            b"From: a\r\nReceived-SPF: a\r\nComments: 0\r\nComments: 1\r\nComments: THREE\r\nComments: 5\r\nComments: 6\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_body_line_changes() {
        assert_chain(&[
            b"From: a\r\n\r\nline1\r\nline2\r\nline3\r\n",
            b"From: a\r\n\r\nline1\r\nCHANGED\r\nline3\r\n",
            b"From: a\r\n\r\nFIRST\r\nCHANGED\r\nlast\r\n",
            b"From: a\r\n\r\nFIRST\r\nCHANGED\r\nLAST\r\n",
        ]);
    }

    #[test]
    fn chain_body_insertions() {
        assert_chain(&[
            b"From: a\r\n\r\nline1\r\nline2\r\n",
            b"From: a\r\n\r\nline1\r\ninserted\r\nline2\r\n",
            b"From: a\r\n\r\nline1\r\ninserted\r\nline2\r\nappended\r\n",
            b"From: a\r\n\r\nprepended\r\nline1\r\ninserted\r\nline2\r\nappended\r\n",
        ]);
    }

    #[test]
    fn chain_body_deletions() {
        assert_chain(&[
            b"From: a\r\n\r\nl1\r\nl2\r\nl3\r\nl4\r\nl5\r\n",
            b"From: a\r\n\r\nl1\r\nl2\r\nl4\r\nl5\r\n",
            b"From: a\r\n\r\nl2\r\nl4\r\nl5\r\n",
            b"From: a\r\n\r\nl2\r\nl4\r\n",
        ]);
    }

    #[test]
    fn chain_body_and_headers_each_hop() {
        assert_chain(&[
            b"From: a\r\nSubject: s0\r\n\r\nintro\r\nmiddle\r\nclose\r\n",
            b"From: a\r\nSubject: s1\r\n\r\nintro\r\nMIDDLE\r\nclose\r\n",
            b"From: a\r\nSubject: s2\r\nX-Tag: keep\r\n\r\nintro\r\nMIDDLE\r\nadded\r\nclose\r\n",
            b"From: a\r\nSubject: s2\r\nX-Tag: keep\r\n\r\nMIDDLE\r\nadded\r\n",
        ]);
    }

    #[test]
    fn chain_with_noop_hop() {
        assert_chain(&[
            b"From: a\r\nSubject: keep\r\n\r\nbody line\r\n",
            b"From: a\r\nSubject: keep\r\n\r\nbody line\r\n",
            b"From: a\r\nSubject: changed\r\n\r\nbody line\r\n",
        ]);
    }

    #[test]
    fn chain_body_emptied_then_refilled() {
        assert_chain(&[
            b"From: a\r\n\r\nfirst\r\nsecond\r\n",
            b"From: a\r\n\r\n",
            b"From: a\r\n\r\nbrand new line\r\n",
        ]);
    }

    #[test]
    fn chain_empty_header_value() {
        assert_chain(&[
            b"From: a\r\nSubject: hello\r\n\r\nbody\r\n",
            b"From: a\r\nSubject:\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: world\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_non_utf8_body_copied_lines() {
        assert_chain(&[
            b"From: a\r\n\r\nhel\x80lo\r\nworld\r\n\xff\xfe binary\r\n",
            b"From: a\r\n\r\nhel\x80lo\r\nWORLD\r\n\xff\xfe binary\r\n",
            b"From: a\r\n\r\nhel\x80lo\r\nWORLD\r\ninserted\r\n\xff\xfe binary\r\n",
        ]);
    }

    #[test]
    fn chain_body_without_trailing_crlf() {
        assert_chain(&[
            b"From: a\r\n\r\nl1\r\nl2\r\nl3",
            b"From: a\r\n\r\nl1\r\nCHANGED\r\nl3",
            b"From: a\r\n\r\nl1\r\nCHANGED",
        ]);
    }

    #[test]
    fn chain_header_reinserted_after_deletion() {
        assert_chain(&[
            b"From: a\r\nSubject: present\r\n\r\nbody\r\n",
            b"From: a\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: back again\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn chain_internal_whitespace_changes_are_reconstructed() {
        assert_chain(&[
            b"From: a\r\nSubject: spaced   out   value\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: spaced out value\r\n\r\nbody\r\n",
        ]);
    }

    #[test]
    fn diff_numbers_duplicate_headers_bottom_up() {
        let recipe = diff_bytes(
            b"From: a\r\nComments: top\r\nComments: middle\r\nComments: bottom\r\n\r\nbody\r\n",
            b"From: a\r\nComments: top\r\nComments: bottom\r\n\r\nbody\r\n",
        );
        let header = recipe
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("comments"))
            .expect("comments recipe present");
        assert_eq!(
            header.steps,
            vec![
                Step::Copy { start: 1, end: 1 },
                Step::Data(vec!["middle".to_string()]),
                Step::Copy { start: 2, end: 2 },
            ],
        );
    }

    #[test]
    fn diff_numbers_body_lines_top_down() {
        let recipe = diff_bytes(
            b"From: a\r\n\r\nfirst\r\nsecond\r\nthird\r\n",
            b"From: a\r\n\r\nfirst\r\nCHANGED\r\nthird\r\n",
        );
        assert_eq!(
            recipe.body,
            BodyRecipe::Steps(vec![
                Step::Copy { start: 1, end: 1 },
                Step::Data(vec!["second".to_string()]),
                Step::Copy { start: 3, end: 3 },
            ]),
        );
    }

    #[test]
    fn diff_encodes_full_add_and_remove() {
        let added = diff_bytes(
            b"From: a\r\nSubject: was here\r\n\r\nbody\r\n",
            b"From: a\r\n\r\nbody\r\n",
        );
        let subject = added
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("subject"))
            .unwrap();
        assert_eq!(
            subject.steps,
            vec![Step::Data(vec!["was here".to_string()])]
        );

        let removed = diff_bytes(
            b"From: a\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: injected\r\n\r\nbody\r\n",
        );
        let subject = removed
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("subject"))
            .unwrap();
        assert!(
            subject.steps.is_empty(),
            "empty recipe removes all instances"
        );
    }

    #[test]
    fn diff_copy_ranges_are_strictly_ascending() {
        let recipe = diff_bytes(
            b"From: a\r\nComments: 1\r\nComments: 2\r\nComments: 3\r\nComments: 4\r\nComments: 5\r\n\r\nbody\r\n",
            b"From: a\r\nComments: 1\r\nComments: TWO\r\nComments: 3\r\nComments: FOUR\r\nComments: 5\r\n\r\nbody\r\n",
        );
        let header = recipe
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("comments"))
            .unwrap();
        assert_copy_ranges_ascending(&header.steps);

        let body = diff_bytes(
            b"From: a\r\n\r\na\r\nb\r\nc\r\nd\r\ne\r\nf\r\n",
            b"From: a\r\n\r\na\r\nB\r\nc\r\nd\r\nE\r\nf\r\n",
        )
        .body;
        if let BodyRecipe::Steps(steps) = body {
            assert_copy_ranges_ascending(&steps);
        } else {
            panic!("expected body steps");
        }
    }

    fn assert_no_crlf_in_data(recipe: &Recipe) {
        let check = |values: &[String], ctx: &str| {
            for value in values {
                assert!(
                    !value.contains('\r') && !value.contains('\n'),
                    "{ctx} data string contains CR/LF: {value:?}"
                );
            }
        };
        for header in &recipe.headers {
            for step in &header.steps {
                if let Step::Data(values) = step {
                    check(values, &format!("header {}", header.name));
                }
            }
        }
        if let BodyRecipe::Steps(steps) = &recipe.body {
            for step in steps {
                if let Step::Data(values) = step {
                    check(values, "body");
                }
            }
        }
    }

    #[test]
    fn data_strings_never_contain_crlf() {
        let recipes = [
            diff_bytes(
                b"From: a\r\nSubject: short value\r\n\r\nbody\r\n",
                b"From: a\r\nSubject: a much longer replacement subject value\r\n\r\nbody\r\n",
            ),
            diff_bytes(
                b"From: a\r\nSubject: one\r\n two\r\n three\r\n\r\nbody\r\n",
                b"From: a\r\nSubject: unrelated\r\n\r\nbody\r\n",
            ),
            diff_bytes(
                b"From: a\r\nSubject: line one;\r\n\tline two;\r\n\tline three\r\n\r\nbody\r\n",
                b"From: a\r\n\r\nbody\r\n",
            ),
            diff_bytes(
                b"From: a\r\n\r\nplain\r\nbody\r\n",
                b"From: a\r\n\r\nplain\r\ndifferent\r\n",
            ),
        ];
        for recipe in &recipes {
            assert_no_crlf_in_data(recipe);
        }
    }

    #[test]
    fn unfold_lossy_replaces_terminators_with_space() {
        assert_eq!(unfold_lossy(b"one\r\n two"), "one two");
        assert_eq!(unfold_lossy(b"alpha\r\nbeta"), "alpha beta");
        assert_eq!(unfold_lossy(b"lone\rcr"), "lone cr");
        assert_eq!(unfold_lossy(b"lone\nlf"), "lone lf");
        assert_eq!(unfold_lossy(b"no terminators"), "no terminators");
    }

    /// A folded header reconstructed from a "d" step must hash identically to the
    /// original folded header: the fold collapses to whitespace either way.
    #[test]
    fn folded_header_data_step_is_hash_equivalent() {
        let recipe = diff_bytes(
            b"From: a\r\nSubject: part one\r\n part two\r\n\r\nbody\r\n",
            b"From: a\r\n\r\nbody\r\n",
        );
        assert_no_crlf_in_data(&recipe);
        let reconstructed = apply_bytes(&recipe, b"From: a\r\n\r\nbody\r\n").unwrap();
        assert_eq!(
            signed_hashes(&reconstructed),
            signed_hashes(b"From: a\r\nSubject: part one part two\r\n\r\nbody\r\n"),
        );
    }

    #[test]
    fn chain_folded_header_round_trips() {
        assert_chain(&[
            b"From: a\r\nSubject: a folded header\r\n value spanning\r\n three lines\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: now unfolded and changed\r\n\r\nbody\r\n",
            b"From: a\r\nSubject: refolded value\r\n that wraps again\r\n\r\nbody\r\n",
        ]);
    }

    fn assert_copy_ranges_ascending(steps: &[Step]) {
        let mut prev_end = 0u32;
        for step in steps {
            if let Step::Copy { start, end } = step {
                assert!(
                    *start > prev_end,
                    "copy start {start} must exceed previous end {prev_end}: {steps:?}"
                );
                assert!(
                    start <= end,
                    "copy start {start} after end {end}: {steps:?}"
                );
                prev_end = *end;
            }
        }
    }
}
