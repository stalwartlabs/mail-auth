/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainedHeaderIterator, HeaderIterator, HeaderStream};
use super::{HeaderFolder, MAX_HEADER_LINE_LEN};
use crate::headers::{AuthenticatedHeader, HeaderParser, Writer};

#[test]
fn header_iterator() {
    for (message, headers) in [
        (
            "From: a\nTo: b\nEmpty:\nMulti: 1\n 2\nSubject: c\n\nNot-header: ignore\n",
            vec![
                ("From", " a\n"),
                ("To", " b\n"),
                ("Empty", "\n"),
                ("Multi", " 1\n 2\n"),
                ("Subject", " c\n"),
            ],
        ),
        (
            ": a\nTo: b\n \n \nc\n:\nFrom : d\nSubject: e\n\nNot-header: ignore\n",
            vec![
                ("", " a\n"),
                ("To", " b\n \n \n"),
                ("c\n", ""),
                ("", "\n"),
                ("From ", " d\n"),
                ("Subject", " e\n"),
            ],
        ),
        (
            concat!(
                "A: X\r\n",
                "B : Y\t\r\n",
                "\tZ  \r\n",
                "\r\n",
                " C \r\n",
                "D \t E\r\n"
            ),
            vec![("A", " X\r\n"), ("B ", " Y\t\r\n\tZ  \r\n")],
        ),
    ] {
        assert_eq!(
            HeaderIterator::new(message.as_bytes())
                .map(|(h, v)| {
                    (
                        std::str::from_utf8(h).unwrap(),
                        std::str::from_utf8(v).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
            headers
        );

        assert_eq!(
            HeaderParser::new(message.as_bytes())
                .map(|(h, v)| {
                    (
                        std::str::from_utf8(match h {
                            #[cfg(feature = "arc")]
                            AuthenticatedHeader::Aar(v)
                            | AuthenticatedHeader::Ams(v)
                            | AuthenticatedHeader::As(v) => v,
                            AuthenticatedHeader::Ds(v)
                            | AuthenticatedHeader::D2s(v)
                            | AuthenticatedHeader::D2i(v)
                            | AuthenticatedHeader::From(v)
                            | AuthenticatedHeader::Other(v) => v,
                        })
                        .unwrap(),
                        std::str::from_utf8(v).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
            headers
        );
    }
}

#[cfg(feature = "arc")]
#[test]
fn header_parser() {
    let message = concat!(
        "ARC-Message-Signature: i=1; a=rsa-sha256;\n",
        "ARC-Authentication-Results: i=1;\n",
        "ARC-Seal: i=1; a=rsa-sha256;\n",
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple;\n",
        "From: jdoe@domain\n",
        "F r o m : jane@domain.com\n",
        "ARC-Authentication: i=1;\n",
        "Received: r1\n",
        "Received: r2\n",
        "Received: r3\n",
        "Received-From: test\n",
        "Date: date\n",
        "Message-Id: myid\n",
        "\nhey",
    );
    let mut parser = HeaderParser::new(message.as_bytes());
    assert_eq!(
        (&mut parser).map(|(h, _)| { h }).collect::<Vec<_>>(),
        vec![
            AuthenticatedHeader::Ams(b"ARC-Message-Signature"),
            AuthenticatedHeader::Aar(b"ARC-Authentication-Results"),
            AuthenticatedHeader::As(b"ARC-Seal"),
            AuthenticatedHeader::Ds(b"DKIM-Signature"),
            AuthenticatedHeader::From(b"From"),
            AuthenticatedHeader::From(b"F r o m "),
            AuthenticatedHeader::Other(b"ARC-Authentication"),
            AuthenticatedHeader::Other(b"Received"),
            AuthenticatedHeader::Other(b"Received"),
            AuthenticatedHeader::Other(b"Received"),
            AuthenticatedHeader::Other(b"Received-From"),
            AuthenticatedHeader::Other(b"Date"),
            AuthenticatedHeader::Other(b"Message-Id"),
        ]
    );
    assert!(parser.has_date);
    assert!(parser.has_message_id);
    assert_eq!(parser.num_received, 3);
}

#[test]
fn chained_header_iterator() {
    let parts = [
        &b"From: a\nTo: b\nEmpty:\nMulti: 1\n 2\n"[..],
        &b"Subject: c\nReceived: d\n\nhey"[..],
    ];
    let mut headers = vec![
        ("From", " a\n"),
        ("To", " b\n"),
        ("Empty", "\n"),
        ("Multi", " 1\n 2\n"),
        ("Subject", " c\n"),
        ("Received", " d\n"),
    ]
    .into_iter();
    let mut it = ChainedHeaderIterator::new(parts.iter().copied());

    while let Some((k, v)) = it.next_header() {
        assert_eq!(
            (
                std::str::from_utf8(k).unwrap(),
                std::str::from_utf8(v).unwrap()
            ),
            headers.next().unwrap()
        );
    }
    assert_eq!(it.body(), b"hey");
}

fn fold(header: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(header.len() + 16);
    let mut folder = HeaderFolder::new(&mut buf);
    folder.write(header);
    buf
}

fn unfold(folded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(folded.len());
    let mut i = 0;
    while i < folded.len() {
        if folded[i..].starts_with(b"\r\n\t") {
            i += 3;
        } else {
            out.push(folded[i]);
            i += 1;
        }
    }
    out
}

fn assert_folded(original: &[u8]) -> Vec<u8> {
    let folded = fold(original);

    assert_eq!(
        unfold(&folded),
        original,
        "folding must only insert CRLF+TAB fold points, never alter bytes: {:?}",
        String::from_utf8_lossy(original)
    );

    for (n, line) in folded.split(|&c| c == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let content = line.strip_prefix(b"\t").unwrap_or(line);
        assert!(
            content.len() <= MAX_HEADER_LINE_LEN,
            "line {n} of {content_len} bytes exceeds {MAX_HEADER_LINE_LEN}: {:?}",
            String::from_utf8_lossy(content),
            content_len = content.len(),
        );
    }

    for (i, &ch) in folded.iter().enumerate() {
        if ch == b'\n' {
            assert!(
                i >= 1 && folded[i - 1] == b'\r' && folded.get(i + 1) == Some(&b'\t'),
                "every LF must be part of a CRLF+TAB fold at offset {i}: {:?}",
                String::from_utf8_lossy(&folded)
            );
        }
    }

    assert!(
        !folded.starts_with(b"\r\n\t"),
        "output must never begin with a fold"
    );

    folded
}

fn extract_header<'a>(eml: &'a str, name: &str) -> &'a [u8] {
    eml.lines()
        .find(|l| {
            l.len() > name.len()
                && l.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes())
                && l.as_bytes()[name.len()] == b':'
        })
        .unwrap_or_else(|| panic!("header {name} not found"))
        .as_bytes()
}

#[test]
fn header_folder_passthrough() {
    for input in [
        &b""[..],
        &b";"[..],
        &b"a;;b;;;c"[..],
        &b"Subject: hello world"[..],
        &b"Dkim2-Signature: i=1; m=1; d=test.dkim2.eu"[..],
    ] {
        assert_eq!(
            fold(input),
            input,
            "should pass through unchanged: {:?}",
            String::from_utf8_lossy(input)
        );
    }

    let just_under = vec![b'a'; MAX_HEADER_LINE_LEN - 1];
    assert_eq!(fold(&just_under), just_under);
}

#[test]
fn header_folder_boundaries() {
    let exactly_max = vec![b'a'; MAX_HEADER_LINE_LEN];
    let folded = assert_folded(&exactly_max);
    assert_eq!(folded, exactly_max, "76 bytes fit on one line, no fold");

    let over_max = vec![b'a'; MAX_HEADER_LINE_LEN + 1];
    let folded = assert_folded(&over_max);
    let mut expected = vec![b'a'; MAX_HEADER_LINE_LEN];
    expected.extend_from_slice(b"\r\n\t");
    expected.push(b'a');
    assert_eq!(folded, expected, "77 bytes wrap into 76 + fold + 1");

    let two_pieces = vec![b'a'; MAX_HEADER_LINE_LEN * 2];
    let folded = assert_folded(&two_pieces);
    assert_eq!(
        folded.iter().filter(|&&c| c == b'\n').count(),
        1,
        "an exact multiple of the limit yields exactly one fold"
    );
}

#[test]
fn header_folder_large_chunk_followed_by_tags() {
    let big = vec![b'A'; MAX_HEADER_LINE_LEN * 2 - 3];
    let mut input = b"v=".to_vec();
    input.extend_from_slice(&big);
    input.extend_from_slice(b";a=1;b=2;c=3;d=4;e=5");
    assert_folded(&input);

    let big = vec![b'A'; MAX_HEADER_LINE_LEN + 20];
    let mut input = b"s=".to_vec();
    input.extend_from_slice(&big);
    input.extend_from_slice(b";f=feedback");
    assert_folded(&input);
}

#[test]
fn header_folder_consecutive_large_chunks() {
    let mf = vec![b'A'; 100];
    let rt = vec![b'B'; 90];
    let mut input = b"Dkim2-Signature:mf=".to_vec();
    input.extend_from_slice(&mf);
    input.extend_from_slice(b";rt=");
    input.extend_from_slice(&rt);
    input.extend_from_slice(b";f=feedback");
    assert_folded(&input);
}

#[test]
fn header_folder_many_small_tags() {
    let mut input = b"Dkim2-Signature:".to_vec();
    for i in 0..40 {
        input.extend_from_slice(format!(" tag{i}=value{i};").as_bytes());
    }
    assert_folded(&input);
}

#[test]
fn header_folder_large_leading_chunk_over_partial_line() {
    let mut input = b"Message-Instance: m=1; h=sha256:".to_vec();
    input.extend_from_slice(&[b'Z'; 120]);
    assert_folded(&input);
}

#[test]
fn header_folder_real_dkim2_headers() {
    const FILES: [&str; 2] = [
        include_str!("../../resources/dkim2/expected/d2_duplicate_rt_tag.eml"),
        include_str!("../../resources/dkim2/expected/pkix_rsa8192.eml"),
    ];

    for eml in FILES {
        for name in ["Message-Instance", "Dkim2-Signature"] {
            let header = extract_header(eml, name);
            assert!(
                header.len() > MAX_HEADER_LINE_LEN,
                "{name} should exceed the fold limit to exercise folding"
            );
            let folded = assert_folded(header);
            assert!(
                folded.windows(3).any(|w| w == b"\r\n\t"),
                "long real header {name} should have been folded"
            );
        }
    }
}
