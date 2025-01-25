/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::fmt::{Display, Formatter};

use crate::common::headers::{HeaderWriter, Writer};

use super::{Algorithm, Canonicalization, HashAlgorithm, Signature};

impl Signature {
    pub fn write(&self, writer: &mut impl Writer, as_header: bool) {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"dkim-signature:"[..], &b" "[..]),
            _ => (&b"DKIM-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write(header);
        writer.write(b"v=1; a=");
        writer.write(match self.a {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::RsaSha1 => b"rsa-sha1",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        });
        for (tag, value) in [(&b"; s="[..], &self.s), (&b"; d="[..], &self.d)] {
            writer.write(tag);
            writer.write(value.as_bytes());
        }
        writer.write(b"; c=");
        self.ch.serialize_name(writer);
        writer.write(b"/");
        self.cb.serialize_name(writer);

        if let Some(atps) = &self.atps {
            writer.write(b"; atps=");
            writer.write(atps.as_bytes());
            writer.write(b"; atpsh=");
            writer.write(match self.atpsh {
                Some(HashAlgorithm::Sha256) => b"sha256",
                Some(HashAlgorithm::Sha1) => b"sha1",
                _ => b"none",
            });
        }
        if self.r {
            writer.write(b"; r=y");
        }

        writer.write(b";");
        writer.write(new_line);

        let mut bw = 1;
        for (num, h) in self.h.iter().enumerate() {
            if bw + h.len() + 1 >= 76 {
                writer.write(new_line);
                bw = 1;
            }
            if num > 0 {
                writer.write_len(b":", &mut bw);
            } else {
                writer.write_len(b"h=", &mut bw);
            }
            writer.write_len(h.as_bytes(), &mut bw);
        }

        if !self.i.is_empty() {
            if bw + self.i.len() + 3 >= 76 {
                writer.write(b";");
                writer.write(new_line);
                bw = 1;
            } else {
                writer.write_len(b"; ", &mut bw);
            }
            writer.write_len(b"i=", &mut bw);

            for &ch in self.i.as_bytes().iter() {
                match ch {
                    0..=0x20 | b';' | 0x7f..=u8::MAX => {
                        writer.write_len(format!("={ch:02X}").as_bytes(), &mut bw);
                    }
                    _ => {
                        writer.write_len(&[ch], &mut bw);
                    }
                }
                if bw >= 76 {
                    writer.write(new_line);
                    bw = 1;
                }
            }
        }

        for (tag, value) in [
            (&b"t="[..], self.t),
            (&b"x="[..], self.x),
            (&b"l="[..], self.l),
        ] {
            if value > 0 {
                let value = value.to_string();
                writer.write_len(b";", &mut bw);
                if bw + tag.len() + value.len() >= 76 {
                    writer.write(new_line);
                    bw = 1;
                } else {
                    writer.write_len(b" ", &mut bw);
                }

                writer.write_len(tag, &mut bw);
                writer.write_len(value.as_bytes(), &mut bw);
            }
        }

        for (tag, value) in [(&b"; bh="[..], &self.bh), (&b"; b="[..], &self.b)] {
            writer.write_len(tag, &mut bw);
            for &byte in value {
                writer.write_len(&[byte], &mut bw);
                if bw >= 76 {
                    writer.write(new_line);
                    bw = 1;
                }
            }
        }

        writer.write(b";");
        if as_header {
            writer.write(b"\r\n");
        }
    }
}

impl HeaderWriter for Signature {
    fn write_header(&self, writer: &mut impl Writer) {
        self.write(writer, true);
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write(&mut buf, false);
        f.write_str(&String::from_utf8_lossy(&buf))
    }
}
