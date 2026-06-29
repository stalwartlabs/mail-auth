/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainBinding, MessageInstance, Signature, SignatureValue};
use crate::common::headers::Writer;
use mail_builder::encoders::base64::base64_encode_mime;
use std::{
    fmt::{Display, Formatter},
    io::Write,
};

struct Base64Writer<'x, W: Writer> {
    inner: &'x mut W,
}

impl<'x, W: Writer> Write for Base64Writer<'x, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_base64(writer: &mut impl Writer, bytes: &[u8]) {
    let _ = base64_encode_mime(bytes, Base64Writer { inner: writer }, true);
}

impl SignatureValue {
    fn write(&self, writer: &mut impl Writer, empty: bool) {
        writer.write(self.selector.as_bytes());
        writer.write(b":");
        writer.write(self.a.name().as_bytes());
        writer.write(b":");
        if !empty {
            write_base64(writer, &self.b);
        }
    }
}

impl Signature {
    pub(super) fn write_value(&self, writer: &mut impl Writer, empty_signature: bool) {
        writer.write(b"i=");
        writer.write(self.i.to_string().as_bytes());
        writer.write(b"; m=");
        writer.write(self.m.to_string().as_bytes());
        writer.write(b"; t=");
        writer.write(self.t.to_string().as_bytes());
        writer.write(b"; d=");
        writer.write(self.d.as_bytes());
        writer.write(b"; ");

        match &self.chain {
            ChainBinding::Envelope { mail_from, rcpt_to } => {
                writer.write(b"mf=");
                write_base64(writer, mail_from.as_bytes());
                writer.write(b"; rt=");
                for (pos, rcpt) in rcpt_to.iter().enumerate() {
                    if pos > 0 {
                        writer.write(b",");
                    }
                    write_base64(writer, rcpt.as_bytes());
                }
            }
            ChainBinding::NextDomain(domain) => {
                writer.write(b"nd=");
                writer.write(domain.as_bytes());
            }
        }

        writer.write(b"; s=");
        for (pos, value) in self.s.iter().enumerate() {
            if pos > 0 {
                writer.write(b",");
            }
            value.write(writer, empty_signature);
        }
        writer.write(b";");

        if let Some(nonce) = &self.n {
            writer.write(b" n=");
            writer.write(nonce.as_bytes());
            writer.write(b";");
        }

        if !self.flags.is_empty() {
            writer.write(b" f=");
            for (pos, flag) in self.flags.iter().enumerate() {
                if pos > 0 {
                    writer.write(b",");
                }
                writer.write(flag.as_bytes());
            }
            writer.write(b";");
        }
    }

    pub fn write(&self, writer: &mut impl Writer) {
        writer.write(b"DKIM2-Signature: ");
        self.write_value(writer, false);
        writer.write(b"\r\n");
    }
}

impl MessageInstance {
    pub(super) fn write_value(&self, writer: &mut impl Writer) {
        writer.write(b"m=");
        writer.write(self.m.to_string().as_bytes());
        writer.write(b"; h=");
        for (pos, hash) in self.hashes.iter().enumerate() {
            if pos > 0 {
                writer.write(b",");
            }
            writer.write(hash.name.map(|n| n.name().as_bytes()).unwrap_or(b""));
            writer.write(b":");
            write_base64(writer, &hash.header_hash);
            writer.write(b":");
            write_base64(writer, &hash.body_hash);
        }

        if let Some(recipe) = &self.recipe {
            let mut json = Vec::new();
            if recipe.to_json(&mut json).is_ok() {
                writer.write(b"; r=");
                write_base64(writer, &json);
            }
        }
        writer.write(b";");
    }

    pub fn write(&self, writer: &mut impl Writer) {
        writer.write(b"Message-Instance: ");
        self.write_value(writer);
        writer.write(b"\r\n");
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write_value(&mut buf, false);
        f.write_str(&String::from_utf8_lossy(&buf))
    }
}

impl Display for MessageInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write_value(&mut buf);
        f.write_str(&String::from_utf8_lossy(&buf))
    }
}

#[cfg(test)]
mod test {
    use crate::common::crypto::Algorithm;
    use crate::dkim2::{ChainBinding, Flag, Signature, SignatureValue};

    fn sample() -> Signature {
        Signature {
            i: 2,
            m: 1,
            t: 1700000000,
            d: "example.com".to_string(),
            s: vec![SignatureValue {
                selector: "sel".to_string(),
                a: Algorithm::Ed25519Sha256,
                b: vec![1, 2, 3, 4],
            }],
            chain: ChainBinding::Envelope {
                mail_from: "<a@example.com>".to_string(),
                rcpt_to: vec!["<b@example.org>".to_string()],
            },
            n: None,
            flags: Vec::new(),
        }
    }

    #[test]
    fn flags_emitted_in_order() {
        let mut buf = Vec::new();
        Signature {
            flags: vec![Flag::DoNotModify, Flag::FeedHere],
            ..sample()
        }
        .write_value(&mut buf, false);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("f=donotmodify,feedhere;"), "{out}");
    }

    #[test]
    fn next_domain_emits_nd_and_omits_envelope() {
        let mut buf = Vec::new();
        Signature {
            chain: ChainBinding::NextDomain("relay.example".to_string()),
            ..sample()
        }
        .write_value(&mut buf, false);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("nd=relay.example"), "{out}");
        assert!(!out.contains("mf="), "{out}");
        assert!(!out.contains("rt="), "{out}");
    }

    #[test]
    fn write_then_parse_round_trips() {
        let sig = sample();
        let mut buf = Vec::new();
        sig.write_value(&mut buf, false);
        assert_eq!(Signature::parse(&buf).unwrap(), sig);
    }
}
