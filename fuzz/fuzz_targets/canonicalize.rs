/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![no_main]
use libfuzzer_sys::fuzz_target;

use mail_auth::{
    AuthenticatedMessage,
    common::{
        crypto::{Ed25519Key, HashContext, HashImpl, Sha256},
        headers::{HeaderFolder, HeaderWriter, Writable, Writer},
    },
    dkim::{Canonicalization, DkimSigner, Done, canonicalize::BodyHasher},
};
use std::sync::LazyLock;

const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const ED25519_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

static SIGNER: LazyLock<DkimSigner<Ed25519Key, Done>> = LazyLock::new(|| {
    DkimSigner::from_key(
        Ed25519Key::from_seed_and_public_key(&ED25519_SEED, &ED25519_PUBLIC)
            .expect("test key is valid"),
    )
    .domain("example.com")
    .selector("ed")
    .headers(["From", "To", "Subject", "Date", "Message-ID"])
});

fn whole_body_digest(canonicalization: Canonicalization, body: &[u8], limit: u64) -> Vec<u8> {
    let mut hasher = Sha256::hasher();
    canonicalization
        .canonical_body(body, limit)
        .write(&mut hasher);
    hasher.complete().as_ref().to_vec()
}

fn chunked_body_digest(
    canonicalization: Canonicalization,
    body: &[u8],
    limit: u64,
    chunk: usize,
) -> (Vec<u8>, u64) {
    let mut hasher = BodyHasher::new(Sha256::hasher(), canonicalization, limit);
    for piece in body.chunks(chunk) {
        hasher.write(piece);
    }
    let (hasher, hashed) = hasher.finish();
    (hasher.complete().as_ref().to_vec(), hashed)
}

fn check_body(seed: u8, body: &[u8]) {
    let chunk = usize::from(seed % 13) + 1;
    let limits = [0, 1, 7, body.len() as u64, body.len() as u64 + 3];
    for canonicalization in [Canonicalization::Relaxed, Canonicalization::Simple] {
        for limit in limits {
            let whole = whole_body_digest(canonicalization, body, limit);
            let (chunked, hashed) = chunked_body_digest(canonicalization, body, limit, chunk);
            assert_eq!(whole, chunked, "chunk size {chunk}, limit {limit}");
            let expected = if limit == 0 {
                body.len() as u64
            } else {
                limit.min(body.len() as u64)
            };
            assert_eq!(hashed, expected);
        }
    }
}

fn check_headers(message: &[u8]) {
    let Some(parsed) = AuthenticatedMessage::parse(message) else {
        return;
    };
    for canonicalization in [Canonicalization::Relaxed, Canonicalization::Simple] {
        let mut out = Vec::new();
        canonicalization.canonicalize_headers(parsed.headers.iter().copied(), &mut out);
        if canonicalization == Canonicalization::Simple {
            let expected: usize = parsed
                .headers
                .iter()
                .map(|(name, value)| name.len() + 1 + value.len())
                .sum();
            assert_eq!(out.len(), expected);
        }
    }
}

fn signers_agree_on_boundary(message: &[u8]) -> bool {
    let bare_lf = message
        .iter()
        .enumerate()
        .any(|(pos, &ch)| ch == b'\n' && (pos == 0 || message[pos - 1] != b'\r'));
    if bare_lf {
        return false;
    }
    let Some(boundary) = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
    else {
        return false;
    };
    AuthenticatedMessage::parse(message).is_some_and(|parsed| parsed.body_offset() == boundary)
}

fn check_streaming(seed: u8, message: &[u8]) {
    if !signers_agree_on_boundary(message) {
        return;
    }
    let Ok(whole) = SIGNER.sign(message) else {
        return;
    };
    let chunk = usize::from(seed % 17) + 1;
    let mut stream = SIGNER.sign_streaming();
    for piece in message.chunks(chunk) {
        stream.write(piece);
    }
    let streamed = match stream.finish() {
        Ok(streamed) => streamed,
        Err(_) => {
            assert!(
                !has_signable_header(message),
                "streaming signer failed on a message with a signable header"
            );
            return;
        }
    };
    assert_eq!(whole.bh, streamed.bh, "chunk size {chunk}");
    assert_eq!(whole.h, streamed.h, "chunk size {chunk}");
    assert_eq!(whole.l, streamed.l, "chunk size {chunk}");

    let header = whole.to_header();
    let mut folded = Vec::new();
    HeaderFolder::new(&mut folded).write(header.as_bytes());
    assert_eq!(strip_folds(&folded), strip_folds(header.as_bytes()));
}

fn has_signable_header(message: &[u8]) -> bool {
    AuthenticatedMessage::parse(message).is_some_and(|parsed| {
        parsed.headers.iter().any(|(name, _)| {
            SIGNER
                .template
                .h
                .iter()
                .any(|signed| name.eq_ignore_ascii_case(signed.as_bytes()))
        })
    })
}

fn strip_folds(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|ch| !matches!(ch, b'\r' | b'\n' | b'\t'))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&seed, rest)) = data.split_first() else {
        return;
    };
    check_body(seed, rest);
    check_headers(rest);
    check_streaming(seed, rest);
});
