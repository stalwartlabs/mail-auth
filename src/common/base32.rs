/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::slice::Iter;

use super::headers::Writer;

pub(crate) static BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub static BASE32_INVERSE: [u8; 256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 30, 31, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

pub struct Base32Writer {
    last_byte: u8,
    pos: usize,
    result: String,
}

impl Base32Writer {
    pub fn encode(bytes: &[u8]) -> String {
        let mut w = Base32Writer::with_capacity(bytes.len());
        w.write(bytes);
        w.finalize()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Base32Writer {
            result: String::with_capacity(capacity.div_ceil(4) * 5),
            last_byte: 0,
            pos: 0,
        }
    }

    pub fn push_byte(&mut self, byte: u8, is_remainder: bool) {
        let (ch1, ch2) = match self.pos % 5 {
            0 => ((byte & 0xF8) >> 3, u8::MAX),
            1 => (
                (((self.last_byte & 0x07) << 2) | ((byte & 0xC0) >> 6)),
                ((byte & 0x3E) >> 1),
            ),
            2 => (
                (((self.last_byte & 0x01) << 4) | ((byte & 0xF0) >> 4)),
                u8::MAX,
            ),
            3 => (
                (((self.last_byte & 0x0F) << 1) | (byte >> 7)),
                ((byte & 0x7C) >> 2),
            ),
            4 => (
                (((self.last_byte & 0x03) << 3) | ((byte & 0xE0) >> 5)),
                (byte & 0x1F),
            ),
            _ => unreachable!(),
        };

        self.result.push(char::from(BASE32_ALPHABET[ch1 as usize]));
        if !is_remainder {
            if ch2 != u8::MAX {
                self.result.push(char::from(BASE32_ALPHABET[ch2 as usize]));
            }
            self.last_byte = byte;
            self.pos += 1;
        }
    }

    pub fn finalize(mut self) -> String {
        if self.pos % 5 != 0 {
            self.push_byte(0, true);
        }

        self.result
    }
}

impl Writer for Base32Writer {
    fn write(&mut self, buf: &[u8]) {
        for &byte in buf {
            self.push_byte(byte, false);
        }
    }
}

#[derive(Debug)]
pub struct Base32Reader<'x> {
    bytes: Iter<'x, u8>,
    last_byte: u8,
    pos: usize,
}

impl<'x> Base32Reader<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Base32Reader {
            bytes: bytes.iter(),
            pos: 0,
            last_byte: 0,
        }
    }

    #[inline(always)]
    fn map_byte(&mut self) -> Option<u8> {
        match self.bytes.next() {
            Some(&byte) => match BASE32_INVERSE[byte as usize] {
                byte if byte != u8::MAX => {
                    self.last_byte = byte;
                    Some(byte)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl Iterator for Base32Reader<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.pos % 5;
        let last_byte = self.last_byte;
        let byte = self.map_byte()?;
        self.pos += 1;

        match pos {
            0 => ((byte << 3) | (self.map_byte().unwrap_or(0) >> 2)).into(),
            1 => ((last_byte << 6) | (byte << 1) | (self.map_byte().unwrap_or(0) >> 4)).into(),
            2 => ((last_byte << 4) | (byte >> 1)).into(),
            3 => ((last_byte << 7) | (byte << 2) | (self.map_byte().unwrap_or(0) >> 3)).into(),
            4 => ((last_byte << 5) | byte).into(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{
        base32::{Base32Reader, Base32Writer},
        crypto::{HashContext, HashImpl, Sha1},
        headers::Writer,
    };

    #[test]
    fn base32_hash() {
        for (test, expected_result) in [
            ("one.example.net", "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6"),
            ("two.example.net", "ZTZGRRV3F45A4U6HLDKBF3ZCOW4V2AJX"),
        ] {
            // Encode
            let mut writer = Base32Writer::with_capacity(10);
            let mut hash = Sha1::hasher();
            hash.write(test.as_bytes());
            let hash = hash.complete();
            writer.write(hash.as_ref());
            assert_eq!(writer.finalize(), expected_result);

            // Decode
            let mut original = Vec::new();
            for byte in Base32Reader::new(expected_result.as_bytes()) {
                original.push(byte);
            }
            assert_eq!(original, hash.as_ref());
        }
    }
}
