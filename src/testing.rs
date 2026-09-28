/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    crypto::{HashContext, HashImpl, Sha256},
    dkim::{Canonicalization, canonicalize::BodyHasher},
    headers::{Writable, Writer},
};

#[inline]
pub fn write_canonical_body(
    canonicalization: Canonicalization,
    body: &[u8],
    limit: u64,
    writer: &mut impl Writer,
) {
    canonicalization.canonical_body(body, limit).write(writer);
}

pub fn whole_body_digest(canonicalization: Canonicalization, body: &[u8], limit: u64) -> Vec<u8> {
    let mut hasher = Sha256::hasher();
    canonicalization
        .canonical_body(body, limit)
        .write(&mut hasher);
    hasher.complete().as_ref().to_vec()
}

pub fn chunked_body_digest(
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

#[inline]
pub fn canonicalize_headers<'x>(
    canonicalization: Canonicalization,
    headers: impl Iterator<Item = (&'x [u8], &'x [u8])>,
    out: &mut Vec<u8>,
) {
    canonicalization.canonicalize_headers(headers, out);
}
