/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcSet, ChainValidation, Seal, Signature};
use crate::{
    AuthenticationResults,
    common::{
        crypto::Algorithm,
        headers::{HeaderWriter, IntegerBuffer, Writer, write_integer, write_wrapped_base64},
    },
    dkim::Canonicalization,
};

impl Signature {
    pub(crate) fn write(&self, writer: &mut impl Writer, as_header: bool) {
        let (header, new_line) = match self.ch {
            Canonicalization::Relaxed if !as_header => (&b"arc-message-signature:"[..], &b" "[..]),
            _ => (&b"ARC-Message-Signature: "[..], &b"\r\n\t"[..]),
        };
        writer.write(header);
        writer.write(b"i=");
        write_integer(writer, self.i as u64);
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

        let mut integer = IntegerBuffer::new();
        for (tag, value) in [
            (&b"t="[..], self.t),
            (&b"x="[..], self.x),
            (&b"l="[..], self.l),
        ] {
            if value > 0 {
                let value = integer.digits(value);
                writer.write_len(b";", &mut bw);
                if bw + tag.len() + value.len() >= 76 {
                    writer.write(new_line);
                    bw = 1;
                } else {
                    writer.write_len(b" ", &mut bw);
                }

                writer.write_len(tag, &mut bw);
                writer.write_len(value, &mut bw);
            }
        }

        for (tag, value) in [(&b"; bh="[..], &self.bh), (&b"; b="[..], &self.b)] {
            writer.write_len(tag, &mut bw);
            write_wrapped_base64(writer, value, &mut bw, new_line);
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
        write_integer(writer, self.i as u64);
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
            let mut integer = IntegerBuffer::new();
            writer.write_len(b"t=", &mut bw);
            writer.write_len(integer.digits(self.t), &mut bw);
            writer.write_len(b"; ", &mut bw);
        }

        writer.write_len(b"b=", &mut bw);
        write_wrapped_base64(writer, &self.b, &mut bw, new_line);

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
        write_integer(writer, i as u64);
        writer.write(b"; ");
        writer.write(self.hostname.as_bytes());
        if !as_header {
            let mut rest = self.auth_results.as_bytes();
            let mut last_is_space = false;
            while !rest.is_empty() {
                let run = rest
                    .iter()
                    .position(u8::is_ascii_whitespace)
                    .unwrap_or(rest.len());
                if run > 0 {
                    if last_is_space {
                        writer.write(b" ");
                        last_is_space = false;
                    }
                    let (head, tail) = rest.split_at(run);
                    writer.write(head);
                    rest = tail;
                } else {
                    last_is_space = true;
                    let spaces = rest
                        .iter()
                        .position(|ch| !ch.is_ascii_whitespace())
                        .unwrap_or(rest.len());
                    rest = rest.get(spaces..).unwrap_or_default();
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

#[cfg(test)]
mod test {
    use crate::arc::{Seal, Signature};

    #[test]
    fn arc_headers_round_trip() {
        let signature = Signature::parse(
            concat!(
                "i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;\r\n",
                "        h=sender:errors-to:content-transfer-encoding:mime-version\r\n",
                "         :list-subscribe:list-help:list-post:list-archive:list-unsubscribe\r\n",
                "         :list-id:precedence:subject:archived-at:date:message-id:user-agent\r\n",
                "         :to:from:autocrypt:dkim-signature:delivered-to:dkim-signature\r\n",
                "         :dkim-signature;\r\n",
                "        bh=wA8UHicgWC9Xhbg+MPaDDXiNuk7OpeLzC4PgU7LJ3mQ=;\r\n",
                "        b=0nKy4Nn+8nEVYv5YYtFjBFSi3BwcNSeqcf1t9IOA7le6cQG7QI/M33po0jAXzgOs76\r\n",
                "         UaQ3Pg9K/ORHImUIOqWTHwXBK2ROYEVKoW/Z4Gezci76/LAy6gZCpourr+wVN5S5owWy\r\n",
                "         W2obi6q+wIaemywp1Ky+WZKlQjF8ruuviyPWUwZCk414fk8n1RChWWDW/6X1nZWNHXjj\r\n",
                "         o2qXzlcYIIoptcsfQrbKZiTwzvad/c+dHZdd8NTTCdEkw0DwAWcjIMflDllv5Fyd2pL5\r\n",
                "         7DVuyNqgrNIJPR13Gd0iYjR5bUujKcPDNz/xxMHmoj65LRWMtAkwEv8047PL/4nL7F3z\r\n",
                "         2QYg==\r\n",
            )
            .as_bytes(),
        )
        .unwrap();
        let mut buf = Vec::new();
        signature.write(&mut buf, true);
        let header = String::from_utf8(buf).unwrap();
        let value = header.strip_prefix("ARC-Message-Signature: ").unwrap();
        assert_eq!(
            Signature::parse(value.as_bytes()).unwrap(),
            signature,
            "{header:?}"
        );

        let seal = Seal::parse(
            concat!(
                "i=1; a=rsa-sha256; t=1667893878; cv=none;\r\n",
                "        d=google.com; s=arc-20160816;\r\n",
                "        b=kna37LD/XkkyCuF2pr6yqCft1v3+68UKvkcTDqgwys4t5BG8Nf/Wy8Yds2g3K3QizJ\r\n",
                "         t142Y3gHsRkWPrjrcNUkx7udVx90nb71uOVNkkcqLxwlWNSSp1ob5GsdyijKBqvC1+sW\r\n",
                "         MJaenWq8fymomRGMpH8FxoeJCnp+Kl3N6gFJ5Js7d5X11JqGSxUrU9fC0NmPx6Wn+IOx\r\n",
                "         f/mxC87fM6RTYeTyMiDeNiBve8S/RBj4mkr1MMo9xhA795Wa3SVVA2Ry3RSrg3BmOOUL\r\n",
                "         fX6mY0XAahlLvALABgOdCGXupQ6oT8wZWE1y77zSpC+NAGXeAFHF6MczR2ImHV8i2Crg\r\n",
                "         SObA==\r\n",
            )
            .as_bytes(),
        )
        .unwrap();
        let mut buf = Vec::new();
        seal.write(&mut buf, true);
        let header = String::from_utf8(buf).unwrap();
        let value = header.strip_prefix("ARC-Seal: ").unwrap();
        assert_eq!(Seal::parse(value.as_bytes()).unwrap(), seal, "{header:?}");
    }
}
