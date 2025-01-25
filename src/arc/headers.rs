/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    common::{
        crypto::Algorithm,
        headers::{HeaderWriter, Writer},
    },
    dkim::Canonicalization,
    AuthenticationResults,
};

use super::{ArcSet, ChainValidation, Seal, Signature};

impl Signature {
    pub(crate) fn write(&self, writer: &mut impl Writer, as_header: bool) {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"arc-message-signature:"[..], &b" "[..]),
            _ => (&b"ARC-Message-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write(header);
        writer.write(b"i=");
        writer.write(self.i.to_string().as_bytes());
        writer.write(b"; a=");
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

impl Seal {
    pub(crate) fn write(&self, writer: &mut impl Writer, as_header: bool) {
        let (header, new_line) = if !as_header {
            (&b"arc-seal:"[..], &b" "[..])
        } else {
            (&b"ARC-Seal: "[..], &b"\r\n\t"[..])
        };

        writer.write(header);
        writer.write(b"i=");
        writer.write(self.i.to_string().as_bytes());
        writer.write(b"; a=");
        writer.write(match self.a {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::RsaSha1 => b"rsa-sha1",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        });
        for (tag, value) in [(&b"; s="[..], &self.s), (&b"; d="[..], &self.d)] {
            writer.write(tag);
            writer.write(value.as_bytes());
        }
        writer.write(b"; cv=");
        writer.write(match self.cv {
            ChainValidation::None => b"none",
            ChainValidation::Fail => b"fail",
            ChainValidation::Pass => b"pass",
        });

        writer.write(b";");
        writer.write(new_line);

        let mut bw = 1;
        if self.t > 0 {
            writer.write_len(b"t=", &mut bw);
            writer.write_len(self.t.to_string().as_bytes(), &mut bw);
            writer.write_len(b"; ", &mut bw);
        }

        writer.write_len(b"b=", &mut bw);
        for &byte in &self.b {
            writer.write_len(&[byte], &mut bw);
            if bw >= 76 {
                writer.write(new_line);
                bw = 1;
            }
        }

        writer.write(b";");
        if as_header {
            writer.write(b"\r\n");
        }
    }
}

impl AuthenticationResults<'_> {
    pub(crate) fn write(&self, writer: &mut impl Writer, i: u32, as_header: bool) {
        writer.write(if !as_header {
            b"arc-authentication-results:"
        } else {
            b"ARC-Authentication-Results: "
        });
        writer.write(b"i=");
        writer.write(i.to_string().as_bytes());
        writer.write(b"; ");
        writer.write(self.hostname.as_bytes());
        if !as_header {
            let mut last_is_space = false;
            for &ch in self.auth_results.as_bytes() {
                if !ch.is_ascii_whitespace() {
                    if last_is_space {
                        writer.write(b" ");
                        last_is_space = false;
                    }
                    writer.write(&[ch]);
                } else {
                    last_is_space = true;
                }
            }
        } else {
            writer.write(self.auth_results.as_bytes());
        }
        writer.write(b"\r\n");
    }
}

impl HeaderWriter for ArcSet<'_> {
    fn write_header(&self, writer: &mut impl Writer) {
        self.seal.write(writer, true);
        self.signature.write(writer, true);
        self.results.write(writer, self.seal.i, true);
    }
}
