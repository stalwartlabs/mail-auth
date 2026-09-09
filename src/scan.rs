/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
const fn zero_lanes(word: u64) -> u64 {
    word.wrapping_sub(ONES) & !word & HIGH
}

#[inline(always)]
const fn eq_lanes(word: u64, byte: u8) -> u64 {
    zero_lanes(word ^ ONES.wrapping_mul(byte as u64))
}

#[inline(always)]
const fn le_space_lanes(word: u64) -> u64 {
    word.wrapping_sub(ONES.wrapping_mul(b' ' as u64 + 1)) & !word & HIGH
}

#[inline(always)]
pub(crate) fn find_le_space_or2(bytes: &[u8], first: u8, second: u8) -> usize {
    let (chunks, tail) = bytes.as_chunks::<8>();
    for (index, chunk) in chunks.iter().enumerate() {
        let word = u64::from_le_bytes(*chunk);
        let hits = le_space_lanes(word) | eq_lanes(word, first) | eq_lanes(word, second);
        if hits != 0 {
            return index * 8 + (hits.trailing_zeros() / 8) as usize;
        }
    }

    let consumed = chunks.len() * 8;
    consumed
        + tail
            .iter()
            .position(|&ch| ch <= b' ' || ch == first || ch == second)
            .unwrap_or(tail.len())
}

#[inline(always)]
pub(crate) fn find_ascii_whitespace(bytes: &[u8]) -> usize {
    let mut pos = 0;
    while let Some(rest) = bytes.get(pos..) {
        pos += find_le_space_or2(rest, b' ', b' ');
        match bytes.get(pos) {
            None => break,
            Some(ch) if ch.is_ascii_whitespace() => return pos,
            _ => pos += 1,
        }
    }
    bytes.len()
}
