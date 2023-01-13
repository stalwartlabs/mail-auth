/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use super::headers::Writer;

pub(crate) static BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
            result: String::with_capacity((capacity + 3) / 4 * 5),
            last_byte: 0,
            pos: 0,
        }
    }

    fn push_byte(&mut self, byte: u8, is_remainder: bool) {
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

#[cfg(test)]
mod tests {
    use crate::common::{
        base32::Base32Writer,
        crypto::{HashContext, HashImpl, Sha1},
        headers::Writer,
    };

    #[test]
    fn base32_hash() {
        for (test, expected_result) in [
            ("one.example.net", "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6"),
            ("two.example.net", "ZTZGRRV3F45A4U6HLDKBF3ZCOW4V2AJX"),
        ] {
            let mut writer = Base32Writer::with_capacity(10);
            let mut hash = Sha1::hasher();
            hash.write(test.as_bytes());
            writer.write(hash.complete().as_ref());
            assert_eq!(writer.finalize(), expected_result);
        }
    }
}
