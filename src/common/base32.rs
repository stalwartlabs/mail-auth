pub(crate) static BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(crate) struct Base32Writer {
    last_byte: u8,
    pos: usize,
    result: String,
}

impl Base32Writer {
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

impl std::io::Write for Base32Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let start_pos = self.pos;

        for &byte in bytes {
            self.push_byte(byte, false);
        }

        Ok(self.pos - start_pos)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sha1::{Digest, Sha1};

    use crate::common::base32::Base32Writer;

    #[test]
    fn base32_hash() {
        for (test, expected_result) in [
            ("one.example.net", "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6"),
            ("two.example.net", "ZTZGRRV3F45A4U6HLDKBF3ZCOW4V2AJX"),
        ] {
            let mut writer = Base32Writer::with_capacity(10);
            let mut hash = Sha1::new();
            hash.update(test.as_bytes());
            writer.write_all(&hash.finalize()[..]).ok();
            assert_eq!(writer.finalize(), expected_result);
        }
    }
}
