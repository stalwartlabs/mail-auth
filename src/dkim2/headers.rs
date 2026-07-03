/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ChainBinding, MessageInstance, Signature, SignatureValue};
use crate::common::headers::{HeaderFolder, HeaderWriter, Writer};
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

impl HeaderWriter for Signature {
    fn write_header(&self, writer: &mut impl Writer) {
        self.write(&mut HeaderFolder::new(writer));
    }
}

impl HeaderWriter for MessageInstance {
    fn write_header(&self, writer: &mut impl Writer) {
        self.write(&mut HeaderFolder::new(writer));
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
    use crate::common::crypto::{Algorithm, HashAlgorithm};
    use crate::common::headers::HeaderWriter;
    use crate::dkim2::{ChainBinding, Flag, MessageHash, MessageInstance, Signature, SignatureValue};

    const MAX_HEADER_LINE_LEN: usize = 76;

    fn strip_all_ws(bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .copied()
            .filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
            .collect()
    }

    // draft-ietf-dkim-dkim2-spec-03 §9.6: the signature canonicalization unfolds
    // and then deletes ALL whitespace, so a folded header field and its unfolded
    // form MUST reduce to identical bytes. Also assert no physical line exceeds the
    // fold limit (excluding the single leading fold tab).
    fn assert_fold_is_transparent(field_name: &[u8], folded: &[u8], unfolded: &[u8]) {
        assert!(
            folded.ends_with(b"\r\n"),
            "a folded header field must end with CRLF: {:?}",
            String::from_utf8_lossy(folded)
        );

        for (n, line) in folded.strip_suffix(b"\r\n").unwrap().split(|&c| c == b'\n').enumerate() {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let content = line.strip_prefix(b"\t").unwrap_or(line);
            assert!(
                content.len() <= MAX_HEADER_LINE_LEN,
                "{}: line {n} is {} bytes, exceeds {MAX_HEADER_LINE_LEN}: {:?}",
                String::from_utf8_lossy(field_name),
                content.len(),
                String::from_utf8_lossy(content),
            );
        }

        for (i, &ch) in folded.iter().enumerate() {
            if ch == b'\n' && i + 1 < folded.len() {
                assert!(
                    i >= 1 && folded[i - 1] == b'\r' && folded.get(i + 1) == Some(&b'\t'),
                    "every interior LF must be part of a CRLF+TAB fold: {:?}",
                    String::from_utf8_lossy(folded)
                );
            }
        }

        let mut expected = field_name.to_vec();
        expected.extend_from_slice(unfolded);
        assert_eq!(
            strip_all_ws(folded),
            strip_all_ws(&expected),
            "folding changed the whitespace-stripped (signed) bytes of {}",
            String::from_utf8_lossy(field_name)
        );
    }

    fn dump_folded(title: &str, folded: &[u8]) {
        println!("\n===== {title} ({} bytes) =====", folded.len());
        for (n, line) in folded.split(|&c| c == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let content = line.strip_prefix(b"\t").unwrap_or(line);
            let leader = if line.len() != content.len() { "\\t" } else { "  " };
            println!(
                "  line {n:>2} | {:>3} | {leader}{}",
                content.len(),
                String::from_utf8_lossy(content)
            );
        }
        println!("----- raw (escaped) -----");
        println!("  {}", String::from_utf8_lossy(folded).escape_debug());
    }

    fn value_of<'a>(folded: &'a [u8], field_name: &[u8]) -> &'a [u8] {
        folded
            .strip_prefix(field_name)
            .expect("folded header must start with the field name")
    }

    fn big_signature() -> Signature {
        Signature {
            i: 3,
            m: 2,
            t: 1782394336,
            d: "test.dkim2.eu".to_string(),
            s: vec![
                SignatureValue {
                    selector: "rsa2048".to_string(),
                    a: Algorithm::RsaSha256,
                    b: (0u8..=255).cycle().take(256).collect(),
                },
                SignatureValue {
                    selector: "ed25519".to_string(),
                    a: Algorithm::Ed25519Sha256,
                    b: (0u8..64).collect(),
                },
            ],
            chain: ChainBinding::Envelope {
                mail_from: "<sender@test.dkim2.eu>".to_string(),
                rcpt_to: vec![
                    "<recipient@example.com>".to_string(),
                    "<second-recipient@another-example.org>".to_string(),
                ],
            },
            n: Some("banana".to_string()),
            flags: vec![Flag::Feedback, Flag::DoNotModify],
        }
    }

    fn big_instance() -> MessageInstance {
        MessageInstance {
            m: 1,
            hashes: vec![
                MessageHash {
                    name: Some(HashAlgorithm::Sha256),
                    header_hash: (0u8..32).collect(),
                    body_hash: (32u8..64).collect(),
                },
                MessageHash {
                    name: Some(HashAlgorithm::Sha256),
                    header_hash: (64u8..96).collect(),
                    body_hash: (96u8..128).collect(),
                },
            ],
            recipe: None,
        }
    }

    #[test]
    fn signature_write_header_folds_and_round_trips() {
        let sig = big_signature();

        let mut folded = Vec::new();
        sig.write_header(&mut folded);

        let mut unfolded = Vec::new();
        sig.write_value(&mut unfolded, false);
        unfolded.extend_from_slice(b"\r\n");

        assert!(
            folded.windows(3).any(|w| w == b"\r\n\t"),
            "a large signature should have been folded: {:?}",
            String::from_utf8_lossy(&folded)
        );
        dump_folded("DKIM2-Signature (large: rsa2048 + ed25519, 2 recipients)", &folded);
        assert_fold_is_transparent(b"DKIM2-Signature: ", &folded, &unfolded);

        let value = value_of(&folded, b"DKIM2-Signature: ");
        assert_eq!(
            Signature::parse(value).unwrap(),
            sig,
            "folded signature must parse back to the original"
        );
    }

    #[test]
    fn message_instance_write_header_folds_and_round_trips() {
        let instance = big_instance();

        let mut folded = Vec::new();
        instance.write_header(&mut folded);

        assert!(
            folded.windows(3).any(|w| w == b"\r\n\t"),
            "a large message-instance should have been folded: {:?}",
            String::from_utf8_lossy(&folded)
        );
        let mut unfolded = Vec::new();
        instance.write_value(&mut unfolded);
        unfolded.extend_from_slice(b"\r\n");
        dump_folded("Message-Instance (large: 2 sha256 hash sets)", &folded);
        assert_fold_is_transparent(b"Message-Instance: ", &folded, &unfolded);

        let value = value_of(&folded, b"Message-Instance: ");
        assert_eq!(
            MessageInstance::parse(value).unwrap(),
            instance,
            "folded message-instance must parse back to the original"
        );
    }

    #[test]
    fn signature_folds_at_every_realistic_size() {
        for extra_recipients in 0..6 {
            let mut sig = big_signature();
            if let ChainBinding::Envelope { rcpt_to, .. } = &mut sig.chain {
                for n in 0..extra_recipients {
                    rcpt_to.push(format!("<rcpt-{n}@padding-domain-for-length.example>"));
                }
            }

            let mut folded = Vec::new();
            sig.write_header(&mut folded);

            let mut unfolded = Vec::new();
            sig.write_value(&mut unfolded, false);
            unfolded.extend_from_slice(b"\r\n");

            dump_folded(
                &format!("DKIM2-Signature ({} recipients)", extra_recipients + 2),
                &folded,
            );
            assert_fold_is_transparent(b"DKIM2-Signature: ", &folded, &unfolded);
            assert_eq!(Signature::parse(value_of(&folded, b"DKIM2-Signature: ")).unwrap(), sig);
        }
    }

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
