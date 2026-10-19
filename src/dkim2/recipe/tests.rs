/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

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

    let r4 = r_headers("comments", vec![Step::Copy { start: 1, end: 3 }]);
    assert_eq!(json(&r4), b"{\"h\":{\"comments\":[{\"c\":[1,3]}]}}");
}

#[test]
fn from_json_round_trips() {
    let cases: [&[u8]; 4] = [
        b"{\"h\":{\"list-unsubscribe\":[]}}",
        b"{\"b\":[{\"c\":[1,1]}]}",
        b"{\"h\":{\"subject\":[{\"d\":[\" Simple test message\"]}]}}",
        b"{\"h\":{\"comments\":[{\"c\":[1,3]}]}}",
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
fn from_json_ignores_unknown_step() {
    assert_eq!(
        Recipe::from_json(b"{\"b\":[{\"c\":[1,2]},{\"z\":true}]}")
            .unwrap()
            .body,
        BodyRecipe::Steps(vec![Step::Copy { start: 1, end: 2 }])
    );
}

fn diff_bytes(original: &[u8], modified: &[u8]) -> Recipe {
    let o = crate::AuthenticatedMessage::parse(original).unwrap();
    let m = crate::AuthenticatedMessage::parse(modified).unwrap();
    Recipe::diff(&o, &m).unwrap()
}

fn apply_bytes(recipe: &Recipe, message: &[u8]) -> crate::Result<Vec<u8>> {
    let p = crate::AuthenticatedMessage::parse(message).unwrap();
    recipe.apply(&p.headers, p.raw_body())
}

fn signed_hashes(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use crate::crypto::HashAlgorithm;
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
            br#"{"h":{"keywords":[]}}"#,
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
            if via_json && (!recipe.headers.is_empty() || recipe.body != BodyRecipe::None) {
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
fn unfold_replaces_terminators_with_space() {
    assert_eq!(unfold(b"one\r\n two").as_ref(), b"one two");
    assert_eq!(unfold(b"alpha\r\nbeta").as_ref(), b"alpha beta");
    assert_eq!(unfold(b"lone\rcr").as_ref(), b"lone cr");
    assert_eq!(unfold(b"lone\nlf").as_ref(), b"lone lf");
    assert_eq!(unfold(b"no terminators").as_ref(), b"no terminators");
    assert_eq!(unfold(b"bin\xff\r\n ary").as_ref(), b"bin\xff ary");
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

#[test]
fn recipe_json_errors_are_recipe_syntax() {
    use crate::{Error, dkim2::MessageInstance};

    for invalid in [
        &b"not json"[..],
        b"{\"h\":null}",
        b"{\"h\":{\"subject\":null}}",
    ] {
        assert_eq!(
            Recipe::from_json(invalid).unwrap_err(),
            Error::Dkim2(Dkim2Error::RecipeSyntax)
        );
    }
    assert_eq!(
        MessageInstance::parse(b"m=2; h=sha256:QQ==:QQ==; r=bm90IGpzb24=;").unwrap_err(),
        Error::Dkim2(Dkim2Error::InvalidJson(2))
    );
}

// Rules whose breach could make a reconstruction ambiguous or inject header fields stay errors.
#[test]
fn from_json_strict_rules() {
    for invalid in [
        &br#"{"h":{"subject":[]},"h":{"to":[]}}"#[..],
        br#"{"b":[],"b":null}"#,
        br#"{"h":{"subject":[],"subject":[]}}"#,
        br#"{"h":{"From":[],"from":[]}}"#,
        br#"{"h":{"received":[],"Received":[]}}"#,
        br#"{"b":[{"c":[1,2],"d":["x"]}]}"#,
        br#"{"b":[{"u":["YQ=="],"d":["x"]}]}"#,
        br#"{"b":[{"d":["a\r\nb"]}]}"#,
        br#"{"b":[{"d":["a\nb"]}]}"#,
        br#"{"b":[{"u":["YQ0K"]}]}"#,
        br#"{"b":[{"u":["!!!"]}]}"#,
        br#"{"h":{"from ":[]}}"#,
        br#"{"h":{" from":[]}}"#,
        br#"{"h":{"subject\r\nbcc":[]}}"#,
        br#"{"h":{"sub:ject":[]}}"#,
        br#"{"h":{"":[]}}"#,
        br#"{"b":[{"c":[-1,2]}]}"#,
        br#"{"b":[{"c":[1]}]}"#,
    ] {
        assert!(
            Recipe::from_json(invalid).is_err(),
            "{}",
            String::from_utf8_lossy(invalid)
        );
    }
}

// Deviations that cannot change what is reconstructed are accepted when parsing.
#[test]
fn from_json_lenient_rules() {
    for (input, expected) in [
        (&b"{}"[..], Recipe::default()),
        (br#"{"h":{}}"#, Recipe::default()),
        (br#"{"H":{"subject":[]},"Z":1,"z":1,"z":2}"#, Recipe::default()),
        (
            br#"{"h":{"Subject":[{"c":[1,1]}]}}"#,
            r_headers("subject", vec![Step::Copy { start: 1, end: 1 }]),
        ),
        (
            br#"{"h":{"received":[],"Received-SPF":[{"d":["x"]}],"x-mailer":[],"to":[]}}"#,
            r_headers("to", vec![]),
        ),
        (
            br#"{"b":[{"c":[0,1]},{"c":[2,1]},{"c":[1,3]},{"c":[3,4]},{"c":[1,2,3]},{"c":[1,4294967296]}]}"#,
            Recipe {
                headers: vec![],
                body: BodyRecipe::Steps(vec![
                    Step::Copy { start: 0, end: 1 },
                    Step::Copy { start: 2, end: 1 },
                    Step::Copy { start: 1, end: 3 },
                    Step::Copy { start: 3, end: 4 },
                    Step::Copy { start: 1, end: 2 },
                    Step::Copy {
                        start: 1,
                        end: u32::MAX,
                    },
                ]),
            },
        ),
        (
            br#"{"b":[{"z":true},{"x":1,"c":[1,2]},{},1,"x",[9],null,{"d":[]},{"u":[]}]}"#,
            Recipe {
                headers: vec![],
                body: BodyRecipe::Steps(vec![
                    Step::Copy { start: 1, end: 2 },
                    Step::Data(vec![]),
                    Step::Bytes(vec![]),
                ]),
            },
        ),
        (
            br#"{"b":[{"u":["YQ","Y Q = =","YR=="]}]}"#,
            Recipe {
                headers: vec![],
                body: BodyRecipe::Steps(vec![Step::Bytes(vec![
                    b"a".to_vec(),
                    b"a".to_vec(),
                    b"a".to_vec(),
                ])]),
            },
        ),
    ] {
        assert_eq!(
            Recipe::from_json(input).unwrap(),
            expected,
            "{}",
            String::from_utf8_lossy(input)
        );
    }

    let recipe =
        Recipe::from_json(br#"{"z":1,"b":[{"c":[1,2]},{"u":["/w=="]},{"c":[4,4]}]}"#).unwrap();
    assert_eq!(
        json(&recipe),
        br#"{"b":[{"c":[1,2]},{"u":["/w=="]},{"c":[4,4]}]}"#
    );
}

// Copy ranges are clamped and never re-emit a line, so application stays linear.
#[test]
fn apply_bounds_copy_ranges() {
    let message = b"From: a\r\n\r\nl1\r\nl2\r\nl3\r\n";
    let body = |steps: Vec<Step>| {
        let recipe = Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(steps),
        };
        let out = apply_bytes(&recipe, message).unwrap();
        let text = String::from_utf8(out).unwrap();
        text.split_once("\r\n\r\n").unwrap().1.to_string()
    };
    assert_eq!(body(vec![Step::Copy { start: 0, end: 2 }]), "l1\r\nl2\r\n");
    assert_eq!(body(vec![Step::Copy { start: 3, end: 2 }]), "\r\n");
    assert_eq!(
        body(vec![
            Step::Copy { start: 1, end: 2 },
            Step::Copy {
                start: 1,
                end: u32::MAX
            },
            Step::Copy {
                start: 1,
                end: u32::MAX
            },
        ]),
        "l1\r\nl2\r\nl3\r\n"
    );

    let headers = b"Comments: 1\r\nComments: 2\r\nComments: 3\r\n\r\nbody\r\n";
    let recipe = Recipe {
        headers: vec![HeaderRecipe {
            name: "comments".to_string(),
            steps: vec![
                Step::Copy { start: 0, end: 1 },
                Step::Copy { start: 1, end: 9 },
                Step::Copy { start: 1, end: 9 },
            ],
        }],
        body: BodyRecipe::None,
    };
    let out = String::from_utf8(apply_bytes(&recipe, headers).unwrap()).unwrap();
    assert_eq!(
        out.to_ascii_lowercase().matches("comments:").count(),
        3,
        "{out}"
    );
}

// Changed lines that are not UTF-8 are recorded in u steps, the others in d steps.
#[test]
fn diff_uses_u_steps_for_binary_lines() {
    let original: &[u8] = b"From: a\r\nSubject: caf\xe9\r\n\r\none\r\nt\xffo\r\nthree\r\nfour\r\n";
    let modified: &[u8] = b"From: a\r\nSubject: new\r\n\r\none\r\nTWO\r\nTHREE\r\nfour\r\n";
    let recipe = diff_bytes(original, modified);
    assert_eq!(
        recipe.headers[0].steps,
        vec![Step::Bytes(vec![b"caf\xe9".to_vec()])]
    );
    assert_eq!(
        recipe.body,
        BodyRecipe::Steps(vec![
            Step::Copy { start: 1, end: 1 },
            Step::Bytes(vec![b"t\xffo".to_vec()]),
            Step::Data(vec!["three".to_string()]),
            Step::Copy { start: 4, end: 4 },
        ])
    );
    let reparsed = Recipe::from_json(&json(&recipe)).unwrap();
    assert_eq!(reparsed, recipe);
    let reconstructed = apply_bytes(&reparsed, modified).unwrap();
    assert_eq!(signed_hashes(&reconstructed), signed_hashes(original));
}

#[test]
fn validate_rejects_invalid_caller_recipes() {
    for recipe in [
        Recipe::default(),
        r_headers("received", vec![]),
        r_headers("subject", vec![Step::Data(vec![])]),
        r_headers("subject", vec![Step::Data(vec!["a\nb".to_string()])]),
        r_headers("subject", vec![Step::Bytes(vec![b"a\rb".to_vec()])]),
        r_headers("subject", vec![Step::Copy { start: 2, end: 1 }]),
        r_headers("from ", vec![]),
        r_headers("x y", vec![]),
        Recipe {
            headers: vec![
                HeaderRecipe {
                    name: "Subject".to_string(),
                    steps: vec![],
                },
                HeaderRecipe {
                    name: "subject".to_string(),
                    steps: vec![],
                },
            ],
            body: BodyRecipe::None,
        },
    ] {
        assert!(recipe.validate().is_err(), "{recipe:?}");
        assert!(recipe.to_json(&mut Vec::new()).is_err(), "{recipe:?}");
    }
    assert_eq!(
        json(&r_headers("List-Id", vec![])),
        b"{\"h\":{\"list-id\":[]}}"
    );
}

// Field names with whitespace before the colon group and sort like the trimmed name.
#[test]
fn chain_header_names_with_whitespace() {
    assert_chain(&[
        b"From: a\r\nTo: r\r\nSubject\t: A\r\nSubject: B\r\nComments: c\r\n\r\nbody\r\n",
        b"From: a\r\nTo: r\r\nSubject: A\r\nSubject\t: B\r\nComments: c\r\n\r\nbody\r\n",
        b"From: a\r\nTo: r\r\nSubject : A\r\nSubject: C\r\nComments: c\r\n\r\nbody\r\n",
    ]);
}

// A leniently parsed recipe is written back as parsed instead of being dropped.
#[test]
fn message_instance_keeps_lenient_recipe() {
    use crate::dkim2::MessageInstance;

    let mut header = b"m=2; h=sha256:QQ==:QQ==; r=".to_vec();
    encodify::base64::STANDARD.encode_append(br#"{"b":[{"c":[3,1]},{"d":[]}]}"#, &mut header);
    let instance = MessageInstance::parse(&header).unwrap();
    assert!(instance.recipe.as_ref().unwrap().validate().is_err());
    let written = instance.to_string();
    assert!(written.contains("r="), "{written}");
    assert_eq!(
        MessageInstance::parse(written.as_bytes()).unwrap(),
        instance
    );
}
