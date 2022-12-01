/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    fmt::{Display, Formatter},
    io::Write,
};

use crate::common::headers::HeaderWriter;

use super::{Algorithm, Canonicalization, HashAlgorithm, Signature};

impl<'x> Signature<'x> {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"dkim-signature:"[..], &b" "[..]),
            _ => (&b"DKIM-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write_all(header)?;
        writer.write_all(b"v=1; a=")?;
        writer.write_all(match self.a {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::RsaSha1 => b"rsa-sha1",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        })?;
        for (tag, value) in [(&b"; s="[..], &self.s), (&b"; d="[..], &self.d)] {
            writer.write_all(tag)?;
            writer.write_all(value.as_bytes())?;
        }
        writer.write_all(b"; c=")?;
        self.ch.serialize_name(&mut writer)?;
        writer.write_all(b"/")?;
        self.cb.serialize_name(&mut writer)?;

        if let Some(atps) = &self.atps {
            writer.write_all(b"; atps=")?;
            writer.write_all(atps.as_bytes())?;
            writer.write_all(b"; atpsh=")?;
            writer.write_all(match self.atpsh {
                Some(HashAlgorithm::Sha256) => b"sha256",
                Some(HashAlgorithm::Sha1) => b"sha1",
                _ => b"none",
            })?;
        }
        if self.r {
            writer.write_all(b"; r=y")?;
        }

        writer.write_all(b";")?;
        writer.write_all(new_line)?;

        let mut bw = 1;
        for (num, h) in self.h.iter().enumerate() {
            if bw + h.len() + 1 >= 76 {
                writer.write_all(new_line)?;
                bw = 1;
            }
            if num > 0 {
                bw += writer.write(b":")?;
            } else {
                bw += writer.write(b"h=")?;
            }
            bw += writer.write(h.as_bytes())?;
        }

        if !self.i.is_empty() {
            if bw + self.i.len() + 3 >= 76 {
                writer.write_all(b";")?;
                writer.write_all(new_line)?;
                bw = 1;
            } else {
                bw += writer.write(b"; ")?;
            }
            bw += writer.write(b"i=")?;

            for &ch in self.i.as_bytes().iter() {
                match ch {
                    0..=0x20 | b';' | 0x7f..=u8::MAX => {
                        bw += writer.write(format!("={:02X}", ch).as_bytes())?;
                    }
                    _ => {
                        bw += writer.write(&[ch])?;
                    }
                }
                if bw >= 76 {
                    writer.write_all(new_line)?;
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
                bw += writer.write(b";")?;
                if bw + tag.len() + value.len() >= 76 {
                    writer.write_all(new_line)?;
                    bw = 1;
                } else {
                    bw += writer.write(b" ")?;
                }

                bw += writer.write(tag)?;
                bw += writer.write(value.as_bytes())?;
            }
        }

        for (tag, value) in [(&b"; bh="[..], &self.bh), (&b"; b="[..], &self.b)] {
            bw += writer.write(tag)?;
            for &byte in value {
                bw += writer.write(&[byte])?;
                if bw >= 76 {
                    writer.write_all(new_line)?;
                    bw = 1;
                }
            }
        }

        writer.write_all(b";")?;
        if as_header {
            writer.write_all(b"\r\n")?;
        }
        Ok(())
    }
}

impl<'x> HeaderWriter for Signature<'x> {
    fn write_header(&self, writer: impl Write) -> std::io::Result<()> {
        self.write(writer, true)
    }
}

impl<'x> Display for Signature<'x> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write(&mut buf, false).map_err(|_| std::fmt::Error)?;
        f.write_str(&String::from_utf8(buf).map_err(|_| std::fmt::Error)?)
    }
}
