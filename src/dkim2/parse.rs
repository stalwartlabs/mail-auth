/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    ChainBinding, Dkim2Error, Flag, MessageHash, MessageInstance, Signature, SignatureValue,
};
use crate::{
    Error,
    common::{
        crypto::{Algorithm, HashAlgorithm},
        parse::TagParser,
    },
};
use mail_parser::decoders::base64::base64_decode;

const I: u64 = b'i' as u64;
const M: u64 = b'm' as u64;
const T: u64 = b't' as u64;
const D: u64 = b'd' as u64;
const S: u64 = b's' as u64;
const H: u64 = b'h' as u64;
const R: u64 = b'r' as u64;
const N: u64 = b'n' as u64;
const F: u64 = b'f' as u64;
const MF: u64 = (b'm' as u64) | ((b'f' as u64) << 8);
const RT: u64 = (b'r' as u64) | ((b't' as u64) << 8);
const ND: u64 = (b'n' as u64) | ((b'd' as u64) << 8);

impl Signature {
    /// Parses a single DKIM2-Signature header value (without the field name).
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &[u8]) -> crate::Result<Signature> {
        let mut signature = Signature::default();
        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut next_domain: Option<String> = None;
        let mut has_envelope = false;
        let mut seen: Vec<u64> = Vec::with_capacity(16);
        let mut header = header.iter();

        while let Some(key) = header.key() {
            if key != u64::MAX {
                if seen.contains(&key) {
                    return Err(Error::Dkim2(Dkim2Error::SignatureSyntax(signature.i)));
                }
                seen.push(key);
            }
            match key {
                I => signature.i = header.number().unwrap_or(0) as u32,
                M => signature.m = header.number().unwrap_or(0) as u32,
                T => signature.t = header.number().unwrap_or(0),
                D => signature.d = header.text(true),
                S => {
                    signature.s = parse_signature_values(&header.text(false))
                        .ok_or(Error::Dkim2(Dkim2Error::SignatureSyntax(signature.i)))?;
                }
                MF => {
                    mail_from = Some(
                        decode_b64_string(&header.text(false))
                            .ok_or(Error::Dkim2(Dkim2Error::SignatureSyntax(signature.i)))?,
                    );
                    has_envelope = true;
                }
                RT => {
                    let value = header.text(false);
                    rcpt_to = value
                        .split(',')
                        .map(|v| {
                            decode_b64_string(v)
                                .ok_or(Error::Dkim2(Dkim2Error::SignatureSyntax(signature.i)))
                        })
                        .collect::<Result<_, _>>()?;
                    has_envelope = true;
                }
                ND => next_domain = Some(header.text(true)),
                N => {
                    let nonce = header.text(false);
                    if nonce.len() > 64 {
                        return Err(Error::Dkim2(Dkim2Error::SignatureSyntax(signature.i)));
                    }
                    signature.n = Some(nonce);
                }
                F => {
                    signature.flags = header
                        .text(false)
                        .split(',')
                        .filter(|f| !f.is_empty())
                        .map(Flag::parse)
                        .collect();
                }
                _ => header.ignore(),
            }
        }

        for (key, tag) in [(I, "i"), (M, "m"), (T, "t"), (D, "d"), (S, "s")] {
            if !seen.contains(&key) {
                return Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                    i: signature.i,
                    tag,
                }));
            }
        }

        signature.chain = match (next_domain, has_envelope) {
            (Some(_), true) => {
                return Err(Error::Dkim2(Dkim2Error::SignatureTagUnexpected {
                    i: signature.i,
                    tag: "nd",
                }));
            }
            (Some(domain), false) => ChainBinding::NextDomain(domain),
            (None, _) => {
                for (key, tag) in [(MF, "mf"), (RT, "rt")] {
                    if !seen.contains(&key) {
                        return Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                            i: signature.i,
                            tag,
                        }));
                    }
                }
                ChainBinding::Envelope {
                    mail_from: mail_from.unwrap_or_default(),
                    rcpt_to,
                }
            }
        };

        Ok(signature)
    }
}

impl MessageInstance {
    /// Parses a single Message-Instance header value (without the field name).
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &[u8]) -> crate::Result<MessageInstance> {
        let mut instance = MessageInstance::default();
        let mut seen: Vec<u64> = Vec::with_capacity(4);
        let mut header = header.iter();

        while let Some(key) = header.key() {
            if key != u64::MAX {
                if seen.contains(&key) {
                    return Err(Error::Dkim2(Dkim2Error::InstanceSyntax(instance.m)));
                }
                seen.push(key);
            }
            match key {
                M => instance.m = header.number().unwrap_or(0) as u32,
                H => {
                    instance.hashes = parse_hashes(&header.text(false))
                        .ok_or(Error::Dkim2(Dkim2Error::InstanceSyntax(instance.m)))?;
                }
                R => {
                    let encoded = header.text(false);
                    let json = base64_decode(encoded.as_bytes()).ok_or(Error::Base64)?;
                    instance.recipe = Some(super::recipe::Recipe::from_json(&json)?);
                }
                _ => header.ignore(),
            }
        }

        Ok(instance)
    }
}

fn decode_b64_string(value: &str) -> Option<String> {
    base64_decode(value.as_bytes()).and_then(|bytes| String::from_utf8(bytes).ok())
}

fn parse_signature_values(value: &str) -> Option<Vec<SignatureValue>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let mut values = Vec::new();
    for set in value.split(',') {
        let mut parts = set.splitn(3, ':');
        let selector = parts.next()?.trim();
        let algorithm = parts.next()?.trim();
        let signature = parts.next()?.trim();
        let Some(algorithm) = Algorithm::parse(algorithm.as_bytes()) else {
            continue;
        };
        if matches!(algorithm, Algorithm::RsaSha1) {
            continue;
        }
        let b = if signature.is_empty() {
            Vec::new()
        } else {
            base64_decode(signature.as_bytes())?
        };
        values.push(SignatureValue {
            selector: selector.to_string(),
            a: algorithm,
            b,
        });
    }
    Some(values)
}

fn parse_hashes(value: &str) -> Option<Vec<MessageHash>> {
    let mut hashes = Vec::new();
    for set in value.split(',') {
        let mut parts = set.splitn(3, ':');
        let name = parts.next()?.trim();
        let header_hash = base64_decode(parts.next()?.trim().as_bytes())?;
        let body_hash = base64_decode(parts.next()?.trim().as_bytes())?;
        hashes.push(MessageHash {
            name: HashAlgorithm::parse(name),
            header_hash,
            body_hash,
        });
    }
    Some(hashes)
}

impl Flag {
    pub fn parse(value: &str) -> Flag {
        hashify::tiny_map!(value.as_bytes(),
            b"donotmodify" => Flag::DoNotModify,
            b"donotexplode" => Flag::DoNotExplode,
            b"feedback" => Flag::Feedback,
            b"feedhere" => Flag::FeedHere,
            b"exploded" => Flag::Exploded,
        )
        .unwrap_or_else(|| Flag::Unknown(value.to_string()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::AuthenticatedMessage;
    use mail_parser::MessageParser;

    #[test]
    fn from_parsed_classifies_dkim2_headers() {
        let raw = concat!(
            "DKIM2-Signature: i=1; m=1; t=1740000000; d=test4.dkim2.com; mf=PHNlbmRlckB0ZXN0NC5ka2ltMi5jb20+; rt=PHJlY2lwaWVudEBleGFtcGxlLmNvbT4=; s=ed25519:ed25519-sha256:651OFNp+DdgjeVHm1EaEmnpcP6L9PWJczuJ5Oo9dzWPf0xnVgDLcVu4IMmNgW8stVVocIt7MBd8aL0Gc/lCsAA==;\r\n",
            "Message-Instance: m=1; h=sha256:WT8nqIyG8W1R78H1QT4oZdo1SKdQrY9JHQ4fMC+IXHU=:frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=;\r\n",
            "From: sender@test4.dkim2.com\r\n",
            "To: recipient@example.com\r\n",
            "\r\n",
            "body\r\n",
        )
        .as_bytes();

        let from_parsed =
            AuthenticatedMessage::from_parsed(&MessageParser::new().parse(raw).unwrap(), raw, true);
        assert_eq!(from_parsed.dkim2_signatures.len(), 1);
        assert_eq!(from_parsed.dkim2_instances.len(), 1);

        assert_eq!(from_parsed, AuthenticatedMessage::parse(raw).unwrap());
    }

    #[test]
    fn signature_parse_malformed_does_not_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"garbage no equals",
            b"i=; m=; t=; d=;",
            b"i=1; m=1; t=0; d=example.com; mf=; s=sel",
            b"i=1; m=1; t=0; d=example.com; mf=; s=",
            b"i=1; m=1; t=0; d=example.com; mf=; s=,,",
            b"i=1; m=1; t=0; d=example.com; mf=; s=sel:rsa-sha256:",
        ];
        for c in cases {
            let _ = Signature::parse(c);
        }
    }

    #[test]
    fn signature_parse_nd_with_envelope_is_rejected() {
        assert!(Signature::parse(b"nd=next.example; mf=a@b.com").is_err());
    }

    #[test]
    fn header_classification_no_false_positive() {
        let msg = b"DKIM2-Silly: foo\r\nMessage-Idle: bar\r\nFrom: a@b\r\n\r\nbody\r\n";
        let parsed = AuthenticatedMessage::parse(msg).unwrap();
        assert_eq!(parsed.dkim2_signatures.len(), 0);
        assert_eq!(parsed.dkim2_instances.len(), 0);
    }

    #[test]
    fn header_with_digit_parses() {
        let msg = b"X-Test1-Header: v\r\nFrom: a@b\r\n\r\nbody\r\n";
        let parsed = AuthenticatedMessage::parse(msg).unwrap();
        assert_eq!(parsed.raw_parsed_headers().len(), 2);
    }

    #[test]
    fn signature_parse_reordered_tags_and_multi_sset() {
        let v = b"f=donotmodify; m=2; s=sel:rsa-sha256:AAAA,sel2:ed25519-sha256:BBBB; i=3; d=ex.com; mf=; rt=Yg==; t=5; xunknown=zz";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.i, 3);
        assert_eq!(sig.m, 2);
        assert_eq!(sig.s.len(), 2);
    }

    #[test]
    fn message_instance_parse_huge_recipe_does_not_panic_on_parse() {
        let json = br#"{"b":[{"c":[1,4294967295]}]}"#;
        let b64 = mail_builder::encoders::base64::base64_encode(json).unwrap();
        let mut hdr = b"m=2; h=sha256:QQ==:Qg==; r=".to_vec();
        hdr.extend_from_slice(&b64);
        let mi = MessageInstance::parse(&hdr).unwrap();
        assert!(mi.recipe.is_some());
    }

    #[test]
    fn signature_m_can_reach_u32_max() {
        let v: &[u8] =
            b"i=1; m=4294967295; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==; f=donotmodify;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.m, u32::MAX);
    }

    #[test]
    fn signature_parse_decodes_null_reverse_path() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=PD4=; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        if let ChainBinding::Envelope { mail_from, .. } = &sig.chain {
            assert_eq!(mail_from, "<>");
        } else {
            panic!("expected envelope chain");
        }
    }

    #[test]
    fn nonce_over_64_chars_is_rejected() {
        let long = "a".repeat(65);
        let v = format!("i=1; m=1; t=0; d=ex.com; mf=YQ==; n={long}; s=sel:rsa-sha256:QQ==;");
        assert!(matches!(
            Signature::parse(v.as_bytes()),
            Err(Error::Dkim2(Dkim2Error::SignatureSyntax(_)))
        ));
    }

    #[test]
    fn nonce_exactly_64_chars_is_accepted() {
        let n = "a".repeat(64);
        let v = format!("i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; n={n}; s=sel:rsa-sha256:QQ==;");
        let sig = Signature::parse(v.as_bytes()).unwrap();
        assert_eq!(sig.n.as_deref(), Some(n.as_str()));
    }

    #[test]
    fn duplicate_signature_tag_is_rejected() {
        let v: &[u8] = b"i=1; i=2; m=1; t=0; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureSyntax(_)))
        ));
    }

    #[test]
    fn duplicate_signature_tag_case_insensitive_is_rejected() {
        let v: &[u8] = b"i=1; m=1; M=1; t=0; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(Signature::parse(v).is_err());
    }

    #[test]
    fn duplicate_message_instance_tag_is_rejected() {
        let v: &[u8] = b"m=1; m=2; h=sha256:QQ==:Qg==;";
        assert!(matches!(
            MessageInstance::parse(v),
            Err(Error::Dkim2(Dkim2Error::InstanceSyntax(_)))
        ));
    }

    #[test]
    fn missing_t_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "t",
                ..
            }))
        ));
    }

    #[test]
    fn missing_s_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "s",
                ..
            }))
        ));
    }

    #[test]
    fn nd_with_envelope_is_rejected_as_unexpected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; nd=next.example; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagUnexpected {
                tag: "nd",
                ..
            }))
        ));
    }

    #[test]
    fn unknown_algorithm_in_s_is_ignored() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=banana:banana:,sel:ed25519-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.s.len(), 1);
        assert_eq!(sig.s[0].selector, "sel");
    }

    #[test]
    fn only_unknown_algorithms_yields_empty_s() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=banana:banana:;";
        let sig = Signature::parse(v).unwrap();
        assert!(sig.s.is_empty());
    }

    #[test]
    fn mf_without_rt_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "rt",
                ..
            }))
        ));
    }

    #[test]
    fn rt_without_mf_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "mf",
                ..
            }))
        ));
    }

    #[test]
    fn missing_d_tag_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "d",
                ..
            }))
        ));
    }

    #[test]
    fn neither_nd_nor_envelope_is_rejected() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; s=sel:rsa-sha256:QQ==;";
        assert!(matches!(
            Signature::parse(v),
            Err(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                tag: "mf",
                ..
            }))
        ));
    }

    #[test]
    fn rsa_sha1_set_is_dropped() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha1:QQ==,sel2:ed25519-sha256:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.s.len(), 1);
        assert_eq!(sig.s[0].selector, "sel2");
    }

    #[test]
    fn only_rsa_sha1_yields_empty_s() {
        let v: &[u8] = b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha1:QQ==;";
        let sig = Signature::parse(v).unwrap();
        assert!(sig.s.is_empty());
    }

    #[test]
    fn feedhere_flag_is_parsed() {
        let v: &[u8] =
            b"i=1; m=1; t=0; d=ex.com; mf=YQ==; rt=Yg==; s=sel:rsa-sha256:QQ==; f=feedback,feedhere;";
        let sig = Signature::parse(v).unwrap();
        assert_eq!(sig.flags, vec![Flag::Feedback, Flag::FeedHere]);
    }
}
