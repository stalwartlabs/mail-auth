use std::io::Write;

use crate::{
    dkim::{Algorithm, Canonicalization},
    AuthenticationResults,
};

use super::{ChainValidation, Seal, Signature};

impl<'x> Signature<'x> {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"arc-message-signature:"[..], &b" "[..]),
            _ => (&b"ARC-Message-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write_all(header)?;
        writer.write_all(b"i=")?;
        writer.write_all(self.i.to_string().as_bytes())?;
        writer.write_all(b"; a=")?;
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

impl<'x> Seal<'x> {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        let (header, new_line) = if !as_header {
            (&b"arc-seal:"[..], &b" "[..])
        } else {
            (&b"ARC-Seal: "[..], &b"\r\n\t"[..])
        };

        writer.write_all(header)?;
        writer.write_all(b"i=")?;
        writer.write_all(self.i.to_string().as_bytes())?;
        writer.write_all(b"; a=")?;
        writer.write_all(match self.a {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::RsaSha1 => b"rsa-sha1",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        })?;
        for (tag, value) in [(&b"; s="[..], &self.s), (&b"; d="[..], &self.d)] {
            writer.write_all(tag)?;
            writer.write_all(value.as_bytes())?;
        }
        writer.write_all(b"; cv=")?;
        writer.write_all(match self.cv {
            ChainValidation::None => b"none",
            ChainValidation::Fail => b"fail",
            ChainValidation::Pass => b"pass",
        })?;

        writer.write_all(b";")?;
        writer.write_all(new_line)?;

        let mut bw = 1;
        if self.t > 0 {
            bw += writer.write(b"t=")?;
            bw += writer.write(self.t.to_string().as_bytes())?;
        }

        bw += writer.write(b"; b=")?;
        for &byte in &self.b {
            bw += writer.write(&[byte])?;
            if bw >= 76 {
                writer.write_all(new_line)?;
                bw = 1;
            }
        }

        writer.write_all(b";")?;
        if as_header {
            writer.write_all(b"\r\n")?;
        }
        Ok(())
    }
}

impl<'x> AuthenticationResults<'x> {
    pub(crate) fn write(
        &self,
        mut writer: impl Write,
        i: u32,
        as_header: bool,
    ) -> std::io::Result<()> {
        writer.write_all(if !as_header {
            b"arc-authentication-results:"
        } else {
            b"ARC-Authentication-Results: "
        })?;
        writer.write_all(b"i=")?;
        writer.write_all(i.to_string().as_bytes())?;
        writer.write_all(b"; ")?;
        writer.write_all(self.hostname.as_bytes())?;
        if !as_header {
            let mut last_is_space = false;
            for &ch in self.auth_results.as_bytes() {
                if !ch.is_ascii_whitespace() {
                    if last_is_space {
                        writer.write_all(&[b' '])?;
                        last_is_space = false;
                    }
                    writer.write_all(&[ch])?;
                } else {
                    last_is_space = true;
                }
            }
            Ok(())
        } else {
            writer.write_all(self.auth_results.as_bytes())?;
            writer.write_all(b"\r\n")
        }
    }
}
