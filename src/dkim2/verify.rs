/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    ChainBinding, ChainLink, Dkim2Error, Dkim2Output, Flag, MessageInstance, Signature,
    sign::Envelope,
};
use crate::{
    AuthenticatedMessage, Dkim2Result, DnsError, Error, MX, MessageAuthenticator, Parameters,
    RecordSet, ResolverCache, Txt,
    common::{
        crypto::{Algorithm, CryptoError, HashAlgorithm},
        headers::{Header, HeaderIterator, HeaderStream, Writer},
        verify::DomainKey,
    },
    dkim::DkimError,
    dkim2::{canonicalize::CanonicalizedHeaderWriter, sign::now},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_AGE: u64 = 14 * 86400;

impl MessageAuthenticator {
    /// Verifies the DKIM2 signature chain of an RFC5322 message.
    pub async fn verify_dkim2<'x, TXT, MXX, IPV4, IPV6, PTR, A, R>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, TXT, MXX, IPV4, IPV6, PTR>>,
        envelope: Envelope<A, R>,
    ) -> Dkim2Output<'x>
    where
        TXT: ResolverCache<Box<str>, Txt> + 'x,
        MXX: ResolverCache<Box<str>, RecordSet<MX>> + 'x,
        IPV4: ResolverCache<Box<str>, RecordSet<Ipv4Addr>> + 'x,
        IPV6: ResolverCache<Box<str>, RecordSet<Ipv6Addr>> + 'x,
        PTR: ResolverCache<IpAddr, RecordSet<Box<str>>> + 'x,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
    {
        let params = params.into();
        self.verify_dkim2_(params.params, envelope, params.cache_txt, now(), true)
            .await
    }

    pub(crate) async fn verify_dkim2_<'x, TXT, A, R>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        envelope: Envelope<A, R>,
        cache_txt: Option<&TXT>,
        now: u64,
        body_present: bool,
    ) -> Dkim2Output<'x>
    where
        TXT: ResolverCache<Box<str>, Txt>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
    {
        if message.has_dkim2_errors {
            for header in &message.errors {
                let name = header.name.trim_ascii();

                if name.eq_ignore_ascii_case(b"dkim2-signature")
                    || name.eq_ignore_ascii_case(b"message-instance")
                {
                    return Dkim2Result::from(header.header.clone()).into();
                }
            }
        }

        if message.dkim2_signatures.is_empty() {
            return Dkim2Result::None.into();
        }

        let signatures = message.dkim2_signatures.as_slice();
        let instances = message.dkim2_instances.as_slice();

        for (index, header) in signatures.iter().enumerate() {
            let signature = &header.header;
            let expected = index as u32 + 1;
            if signature.i != expected {
                return Dkim2Result::None.into();
            }
            for (present, tag) in [(signature.m != 0, "m"), (!signature.d.is_empty(), "d")] {
                if !present {
                    return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                        i: signature.i,
                        tag,
                    }))
                    .into();
                }
            }
            if let ChainBinding::Envelope { mail_from, rcpt_to } = &signature.chain {
                if mail_from.is_empty() && rcpt_to.is_empty() {
                    return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                        i: signature.i,
                        tag: "mf",
                    }))
                    .into();
                }
                if require_reverse_path()
                    && !(is_reverse_path(mail_from) && rcpt_to.iter().all(|r| is_reverse_path(r)))
                {
                    return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureSyntax(
                        signature.i,
                    )))
                    .into();
                }
            }
            if now > signature.t && now - signature.t > MAX_AGE {
                return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureExpired(
                    signature.i,
                )))
                .into();
            }
        }

        for (index, header) in instances.iter().enumerate() {
            let instance = &header.header;
            if instance.m != index as u32 + 1 {
                return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::InstanceMissing(
                    index as u32 + 1,
                )))
                .into();
            }
        }

        let highest_sig_m = signatures.last().map(|h| h.header.m).unwrap_or(0);
        let highest_mi_m = instances.last().map(|h| h.header.m).unwrap_or(0);
        if highest_mi_m == 0 {
            return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::InstanceMissing(1))).into();
        }
        if highest_mi_m != highest_sig_m {
            return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::InstanceAboveSignature(
                highest_mi_m,
            )))
            .into();
        }

        let top_signature = &signatures.last().unwrap().header;
        match &top_signature.chain {
            ChainBinding::Envelope { mail_from, rcpt_to } => {
                if !address_matches(envelope.mail_from.as_ref(), mail_from) {
                    return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::MailFromMismatch(
                        top_signature.i,
                    )))
                    .into();
                }
                for rcpt in envelope.rcpt_to {
                    if !rcpt_to.iter().any(|r| address_matches(rcpt.as_ref(), r)) {
                        return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::RcptToMismatch(
                            top_signature.i,
                        )))
                        .into();
                    }
                }
                if mail_from != "<>" {
                    let (_, domain) = local_and_domain(mail_from);
                    if !relaxed_domain_match(domain, &top_signature.d) {
                        return Dkim2Result::PermError(Error::Dkim2(
                            Dkim2Error::MailFromDomainMismatch(top_signature.i),
                        ))
                        .into();
                    }
                }
            }
            ChainBinding::NextDomain(_) => {
                return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureTagMissing {
                    i: top_signature.i,
                    tag: "mf",
                }))
                .into();
            }
        }

        for window in signatures.windows(2) {
            let previous = &window[0].header;
            let current = &window[1].header;
            match &previous.chain {
                ChainBinding::NextDomain(next_domain) => {
                    if !next_domain.eq_ignore_ascii_case(&current.d) {
                        return Dkim2Result::PermError(Error::Dkim2(
                            Dkim2Error::NextDomainMismatch(current.i),
                        ))
                        .into();
                    }
                }
                ChainBinding::Envelope { rcpt_to, .. } => {
                    let custody_ok =
                        if let ChainBinding::Envelope { mail_from, .. } = &current.chain {
                            let (_, current_domain) = local_and_domain(mail_from);
                            rcpt_to.iter().any(|rcpt| {
                                let (_, rcpt_domain) = local_and_domain(rcpt);
                                relaxed_domain_match(current_domain, rcpt_domain)
                            })
                        } else {
                            false
                        };
                    if !custody_ok {
                        return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::MailFromMismatch(
                            current.i,
                        )))
                        .into();
                    }
                }
            }
        }

        for sig_header in signatures {
            let signature = &sig_header.header;
            if signature.s.is_empty() {
                return Dkim2Result::Fail(Error::Dkim2(Dkim2Error::NoValidAlgorithm(signature.i)))
                    .into();
            }

            let mut input = Vec::with_capacity(256);
            for (name, value) in instances
                .iter()
                .filter(|h| h.header.m <= signature.m)
                .map(|h| (h.name, h.value))
                .chain(
                    signatures
                        .iter()
                        .filter(|h| h.header.i < signature.i)
                        .map(|h| (h.name, h.value)),
                )
            {
                let mut w = CanonicalizedHeaderWriter::new(&mut input, name);
                w.write(value);
                w.finalize();
            }
            strip_and_canonicalize_signature(sig_header.value, &mut input);

            for value in &signature.s {
                let key = match self
                    .txt_lookup::<DomainKey>(
                        format!("{}._domainkey.{}.", value.selector, signature.d),
                        cache_txt,
                    )
                    .await
                {
                    Ok(key) => key,
                    Err(Error::Dns(DnsError::Resolver(_))) => {
                        return Dkim2Result::TempError(Error::Dkim2(Dkim2Error::PublicKeyFetch(
                            signature.i,
                        )))
                        .into();
                    }
                    Err(Error::Dkim(DkimError::RevokedPublicKey)) => {
                        return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::PublicKeyRevoked(
                            signature.i,
                        )))
                        .into();
                    }
                    Err(_) => {
                        return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::PublicKeyMissing(
                            signature.i,
                        )))
                        .into();
                    }
                };

                if matches!(value.a, Algorithm::RsaSha256 | Algorithm::RsaSha1)
                    && key.p.public_key_bits() < 1024
                {
                    return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::PublicKeySyntax(
                        signature.i,
                    )))
                    .into();
                }

                match key.p.verify_bytes(&input, &value.b, value.a) {
                    Ok(()) => {}
                    Err(Error::Crypto(CryptoError::IncompatibleAlgorithms)) => {
                        return Dkim2Result::PermError(Error::Dkim2(
                            Dkim2Error::PublicKeyAlgorithmMismatch(signature.i),
                        ))
                        .into();
                    }
                    Err(_) => {
                        return Dkim2Result::Fail(Error::Dkim2(Dkim2Error::IncorrectSignature(
                            signature.i,
                        )))
                        .into();
                    }
                }
            }
        }

        let algorithm = HashAlgorithm::Sha256;
        let mut new_body = vec![];
        let mut new_haders = vec![];
        let mut last_body = message.raw_body();
        let mut last_headers = message.headers.as_slice();

        for header in instances.iter().rev() {
            let instance = &header.header;
            let Some(recorded) = instance.hashes.iter().find(|h| h.name == Some(algorithm)) else {
                continue;
            };

            let header_hash = algorithm.headers_hash(last_headers.iter().copied());

            if header_hash.as_ref() != recorded.header_hash {
                return Dkim2Result::Fail(Error::Dkim2(Dkim2Error::HeaderHashMismatch(instance.m)))
                    .into();
            }
            if !body_present {
                break;
            }
            let body_hash = algorithm.body_hash(last_body);
            if body_hash.as_ref() != recorded.body_hash {
                return Dkim2Result::Fail(Error::Dkim2(Dkim2Error::BodyHashMismatch(instance.m)))
                    .into();
            }
            if instance.m > 1
                && let Some(recipe) = &instance.recipe
            {
                match recipe.apply(last_headers, last_body) {
                    Ok(previous) => {
                        new_body = previous;
                        let mut iter = HeaderIterator::new(&new_body);
                        new_haders = iter.by_ref().collect();
                        last_body = iter.body();
                        last_headers = new_haders.as_slice();
                    }
                    Err(_) => {
                        return Dkim2Result::Fail(Error::Dkim2(Dkim2Error::HeaderHashMismatch(
                            instance.m,
                        )))
                        .into();
                    }
                }
            }
        }

        if let Some(error) = flag_violation(signatures, instances, algorithm) {
            return Dkim2Result::Fail(Error::Dkim2(error)).into();
        }

        Dkim2Output {
            result: Dkim2Result::Pass,
            chain: signatures
                .iter()
                .map(|sig_header| ChainLink {
                    signature: &sig_header.header,
                    instance: instances
                        .iter()
                        .find(|h| h.header.m == sig_header.header.m)
                        .map(|h| &h.header),
                    result: Dkim2Result::Pass,
                    custody_ok: true,
                })
                .collect(),
        }
    }
}

fn flag_violation(
    signatures: &[Header<'_, Signature>],
    instances: &[Header<'_, MessageInstance>],
    algorithm: HashAlgorithm,
) -> Option<Dkim2Error> {
    let mut protected_m: Option<u32> = None;
    let mut protected_i: Option<u32> = None;
    for header in signatures {
        let signature = &header.header;
        if signature.flags.contains(&Flag::DoNotModify) {
            protected_m = Some(protected_m.map_or(signature.m, |m| m.min(signature.m)));
        }
        if signature.flags.contains(&Flag::DoNotExplode) {
            protected_i = Some(protected_i.map_or(signature.i, |i| i.min(signature.i)));
        }
    }

    if let Some(protected_m) = protected_m
        && let Some(reference) = instances
            .iter()
            .find(|h| h.header.m == protected_m)
            .and_then(|h| h.header.hashes.iter().find(|h| h.name == Some(algorithm)))
            .map(|h| (h.header_hash.as_slice(), h.body_hash.as_slice()))
    {
        for header in instances {
            let instance = &header.header;
            if instance.m > protected_m
                && let Some(hashes) = instance.hashes.iter().find(|h| h.name == Some(algorithm))
                && (hashes.header_hash.as_slice(), hashes.body_hash.as_slice()) != reference
            {
                return Some(Dkim2Error::Modified);
            }
        }
    }

    if let Some(protected_i) = protected_i
        && signatures
            .iter()
            .any(|h| h.header.i > protected_i && h.header.flags.contains(&Flag::Exploded))
    {
        return Some(Dkim2Error::Exploded);
    }

    None
}

fn local_and_domain(address: &str) -> (&str, &str) {
    let address = address.strip_prefix('<').unwrap_or(address);
    let address = address.strip_suffix('>').unwrap_or(address);
    match address.rsplit_once('@') {
        Some((local, domain)) => (local, domain),
        None => (address, ""),
    }
}

/// Exact reverse-path / forward-path comparison for the chain-of-custody check
fn address_matches(envelope: &str, signed: &str) -> bool {
    let (el, ed) = local_and_domain(envelope);
    let (sl, sd) = local_and_domain(signed);
    el == sl && ed.eq_ignore_ascii_case(sd)
}

/// Whether a signed mf=/rt= value is a well-formed RFC5321 reverse-path
#[inline(always)]
fn is_reverse_path(value: &str) -> bool {
    value.starts_with('<') && value.ends_with('>')
}

/// Whether the verifier requires signed mf=/rt= values to carry angle brackets.
#[inline(always)]
fn require_reverse_path() -> bool {
    #[cfg(test)]
    {
        test_reverse_path::required()
    }
    #[cfg(not(test))]
    {
        true
    }
}

pub(crate) fn relaxed_domain_match(mail_from_domain: &str, signing_domain: &str) -> bool {
    let mut current = mail_from_domain;
    loop {
        if current.eq_ignore_ascii_case(signing_domain) {
            return true;
        }
        match current.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => current = rest,
            _ => return false,
        }
    }
}

/// Blanks the base64 signature value(s) in the `s=`
fn strip_and_canonicalize_signature(signature: &[u8], out: &mut Vec<u8>) {
    out.extend(b"dkim2-signature:".as_slice());
    let mut iter = signature.iter().peekable();
    let mut last_ch = b' ';
    while let Some(&ch) = iter.next() {
        if !ch.is_ascii_whitespace() {
            if matches!(ch, b's' | b'S') && matches!(last_ch, b' ' | b';') {
                let mut found_eq = false;
                while let Some(next_ch) = iter.peek() {
                    match next_ch {
                        b'\t' | b'\n' | b'\x0C' | b'\r' | b' ' => {
                            iter.next();
                        }
                        b'=' => {
                            found_eq = true;
                            iter.next();
                            break;
                        }
                        _ => break,
                    }
                }

                if found_eq {
                    out.push(ch);
                    out.push(b'=');
                    'next_signature: loop {
                        // Write up to second colon
                        let mut found_colon = false;
                        for &ch in iter.by_ref() {
                            match ch {
                                b'\t' | b'\n' | b'\x0C' | b'\r' | b' ' => {}
                                b':' => {
                                    out.push(ch);
                                    if !found_colon {
                                        found_colon = true;
                                    } else {
                                        break;
                                    }
                                }
                                b';' => {
                                    out.push(ch);
                                    break 'next_signature;
                                }
                                b',' => {
                                    out.push(ch);
                                    continue 'next_signature;
                                }
                                _ => {
                                    out.push(ch);
                                }
                            }
                        }

                        // Skip until next comma or EOF
                        for &ch in iter.by_ref() {
                            match ch {
                                b';' => {
                                    out.push(ch);
                                    break 'next_signature;
                                }
                                b',' => {
                                    out.push(ch);
                                    continue 'next_signature;
                                }
                                _ => {}
                            }
                        }

                        break;
                    }
                    last_ch = b' ';
                    continue;
                }
            }

            out.push(ch);
            last_ch = ch;
        } else {
            last_ch = b' ';
        }
    }

    out.extend(b"\r\n");
}

#[cfg(test)]
mod canonicalize_test {
    #[test]
    fn strip_and_canonicalize_signature() {
        for (value, expected) in [
            // Baseline: WSP deleted, name lowercased, s= signature blanked.
            (
                "i=1; m=1; t=5; d=ex.com; mf=YQ==; rt=Yg==; s=sel:alg:U0lH;",
                "dkim2-signature:i=1;m=1;t=5;d=ex.com;mf=YQ==;rt=Yg==;s=sel:alg:;\r\n",
            ),
            // s= is the last tag, no trailing semicolon.
            ("i=1; s=sel:alg:U0lH", "dkim2-signature:i=1;s=sel:alg:\r\n"),
            // Multiple algorithm sets in s=.
            ("s=a:b:U0lH,c:d:WkZa;", "dkim2-signature:s=a:b:,c:d:;\r\n"),
            // f= after s=.
            (
                "s=sel:alg:U0lH; f=donotmodify;",
                "dkim2-signature:s=sel:alg:;f=donotmodify;\r\n",
            ),
            // Folding: CRLF + WSP everywhere, including inside the signature.
            (
                "i=1;\r\n m=1;\r\n\ts=sel:alg:U0\r\n lH;",
                "dkim2-signature:i=1;m=1;s=sel:alg:;\r\n",
            ),
            // Leading and trailing whitespace.
            ("  i=1; s=a:b:CC;  ", "dkim2-signature:i=1;s=a:b:;\r\n"),
            // s= as the first tag.
            ("s=a:b:CC; i=1;", "dkim2-signature:s=a:b:;i=1;\r\n"),
            // No whitespace at all.
            (
                "i=1;s=a:b:CC;f=exploded;",
                "dkim2-signature:i=1;s=a:b:;f=exploded;\r\n",
            ),
            // A nonce (no colons) preceding s=.
            ("n=foo; s=a:b:CC;", "dkim2-signature:n=foo;s=a:b:;\r\n"),
            // Realistic ed25519 signature.
            (
                "d=sub.ex.com; s=ed25519:ed25519-sha256:F//Dt+leS4H;",
                "dkim2-signature:d=sub.ex.com;s=ed25519:ed25519-sha256:;\r\n",
            ),
            // Empty value.
            ("", "dkim2-signature:\r\n"),
            // A value byte 's' that is not a tag (preceded by a non-boundary char).
            ("d=as; s=a:b:CC;", "dkim2-signature:d=as;s=a:b:;\r\n"),
            // Adversarial: uppercase S= tag (tag names are case-insensitive, §8).
            ("S=sel:alg:CC;", "dkim2-signature:S=sel:alg:;\r\n"),
            // Adversarial: malformed s= (no colons) followed by a colon-bearing nonce.
            (
                "s=badset; n=a:b:c;",
                "dkim2-signature:s=badset;n=a:b:c;\r\n",
            ),
            // Adversarial: empty s= followed by a colon-bearing nonce.
            ("s=; n=a:b:c;", "dkim2-signature:s=;n=a:b:c;\r\n"),
            // Adversarial: single set with only one colon.
            ("s=sel:alg; i=1;", "dkim2-signature:s=sel:alg;i=1;\r\n"),
            // FWS inside a base64 value that ends in an "s=" (padding) before a real s=.
            (
                "i=1; mf=QQ s=; s=a:b:CC;",
                "dkim2-signature:i=1;mf=QQs=;s=a:b:;\r\n",
            ),
            // FWS base64 ending in "s=" followed by a colon-bearing nonce, no real s=.
            ("mf=QQ s=; n=a:b:c;", "dkim2-signature:mf=QQs=;n=a:b:c;\r\n"),
            // FWS base64 ending in "s=" inside a comma-separated rt= list.
            (
                "rt=QQ s=,WWW; s=a:b:CC;",
                "dkim2-signature:rt=QQs=,WWW;s=a:b:;\r\n",
            ),
            // WSP inside the selector and algorithm tokens is deleted.
            ("s=se l:al g:CC;", "dkim2-signature:s=sel:alg:;\r\n"),
        ] {
            let mut out = Vec::new();
            super::strip_and_canonicalize_signature(value.as_bytes(), &mut out);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                expected,
                "input: {value:?}"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test_reverse_path {
    use std::cell::Cell;

    thread_local! {
        static REQUIRED: Cell<bool> = const { Cell::new(true) };
    }

    pub(super) fn required() -> bool {
        REQUIRED.with(Cell::get)
    }

    /// Scope guard that relaxes the reverse-path requirement on the current
    /// thread, restoring it on drop.
    pub(crate) struct LenientReversePath;

    impl LenientReversePath {
        pub(crate) fn new() -> Self {
            REQUIRED.with(|r| r.set(false));
            LenientReversePath
        }
    }

    impl Drop for LenientReversePath {
        fn drop(&mut self) {
            REQUIRED.with(|r| r.set(true));
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Envelope, flag_violation};
    use crate::dkim2::{ChainBinding, Dkim2Signed};
    use crate::{
        AuthenticatedMessage, Dkim2Result, Error, MessageAuthenticator,
        common::{
            cache::test::DummyCaches, crypto::HashAlgorithm, headers::Header,
            parse::TxtRecordParser, verify::DomainKey,
        },
        dkim2::{Dkim2Error, Flag, MessageHash, MessageInstance, Signature},
    };

    fn wrap_sigs(s: &[Signature]) -> Vec<Header<'static, Signature>> {
        s.iter()
            .map(|x| Header::new(b"".as_slice(), b"".as_slice(), x.clone()))
            .collect()
    }

    fn wrap_mis(m: &[MessageInstance]) -> Vec<Header<'static, MessageInstance>> {
        m.iter()
            .map(|x| Header::new(b"".as_slice(), b"".as_slice(), x.clone()))
            .collect()
    }

    #[test]
    fn flag_violation_single_pass() {
        let alg = HashAlgorithm::Sha256;
        let mi = |m: u32, h: &[u8]| MessageInstance {
            m,
            hashes: vec![MessageHash {
                name: Some(alg),
                header_hash: h.to_vec(),
                body_hash: h.to_vec(),
            }],
            recipe: None,
        };
        let sig = |i: u32, m: u32, flags: Vec<Flag>| Signature {
            i,
            m,
            flags,
            ..Default::default()
        };

        let changed = [mi(1, b"a"), mi(2, b"b")];
        let unchanged = [mi(1, b"a")];

        let donotmodify = [sig(1, 1, vec![Flag::DoNotModify]), sig(2, 2, vec![])];
        assert_eq!(
            flag_violation(&wrap_sigs(&donotmodify), &wrap_mis(&changed), alg),
            Some(Dkim2Error::Modified)
        );
        assert_eq!(
            flag_violation(&wrap_sigs(&donotmodify[..1]), &wrap_mis(&unchanged), alg),
            None
        );

        let explode = [
            sig(1, 1, vec![Flag::DoNotExplode]),
            sig(2, 1, vec![Flag::Exploded]),
        ];
        assert_eq!(
            flag_violation(&wrap_sigs(&explode), &wrap_mis(&unchanged), alg),
            Some(Dkim2Error::Exploded)
        );
        let explode_before = [
            sig(1, 1, vec![Flag::Exploded]),
            sig(2, 1, vec![Flag::DoNotExplode]),
        ];
        assert_eq!(
            flag_violation(&wrap_sigs(&explode_before), &wrap_mis(&unchanged), alg),
            None
        );
    }
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };

    const NOW: u64 = 1740002100;

    fn resource(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources/dkim2");
        for part in parts {
            path.push(part);
        }
        path
    }

    fn load_caches() -> DummyCaches {
        let caches = DummyCaches::new();
        let dns = std::fs::read(resource(&["dns.json"])).unwrap();
        let dns: serde_json::Value = serde_json::from_slice(&dns).unwrap();
        let valid_until = Instant::now() + Duration::new(3600, 0);
        for (domain, selectors) in dns.as_object().unwrap() {
            for (selector, records) in selectors.as_object().unwrap() {
                let record = records[0][1].as_str().unwrap();
                let name = format!("{selector}.{domain}.");
                caches.txt_add(
                    name,
                    DomainKey::parse(record.as_bytes()).unwrap(),
                    valid_until,
                );
            }
        }
        caches
    }

    async fn verify_file<A, R>(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        name: &str,
        envelope: Envelope<A, R>,
    ) -> Dkim2Result
    where
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
    {
        let raw = std::fs::read(resource(&["expected", name])).unwrap();
        let message = AuthenticatedMessage::parse(&raw).unwrap();
        let params = caches.parameters(&message);
        resolver
            .verify_dkim2_(&message, envelope, params.cache_txt, NOW, true)
            .await
            .result()
            .clone()
    }

    fn top_envelope(name: &str) -> (String, Vec<String>) {
        let raw = std::fs::read(resource(&["expected", name])).unwrap();
        let message = AuthenticatedMessage::parse(&raw).unwrap();
        let top = message
            .dkim2_signatures
            .iter()
            .map(|h| &h.header)
            .max_by_key(|s| s.i)
            .unwrap();
        match &top.chain {
            ChainBinding::Envelope { mail_from, rcpt_to } => (mail_from.clone(), rcpt_to.clone()),
            ChainBinding::NextDomain(_) => panic!("top signature has nd="),
        }
    }

    #[tokio::test]
    async fn verify_golden_vectors() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();

        verify_pass_list(
            &resolver,
            &caches,
            &[
                "simple-ed25519.eml",
                "simple-rsa2048.eml",
                "simple-sel2.eml",
                "simple-sel3.eml",
                "multiheader-ed25519.eml",
                "trailingblank-ed25519.eml",
                "emptybody-ed25519.eml",
                "multirecipient-ed25519.eml",
                "dsn-ed25519.eml",
                "dupheaders-ed25519.eml",
            ],
        )
        .await;

        let _lenient = super::test_reverse_path::LenientReversePath::new();
        verify_pass_list(
            &resolver,
            &caches,
            &[
                "simple-rsa1024.eml",
                "multihop-header-add.eml",
                "multihop-body-footer.eml",
                "multihop-header-replace.eml",
                "multihop-dup-headers.eml",
                "multihop-3hop-dup-headers.eml",
            ],
        )
        .await;
    }

    async fn verify_pass_list(
        resolver: &MessageAuthenticator,
        caches: &DummyCaches,
        names: &[&str],
    ) {
        for &name in names {
            let (mail_from, rcpt_to) = top_envelope(name);
            let result =
                verify_file(resolver, caches, name, Envelope::new(&mail_from, &rcpt_to)).await;
            assert_eq!(result, Dkim2Result::Pass, "vector {name}");
        }
    }

    fn prepend(signed: &Dkim2Signed, message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(message.len() + 512);
        signed.write(&mut out);
        out.extend_from_slice(message);
        out
    }

    #[tokio::test]
    async fn sign_then_verify_multi_hop() {
        use crate::{
            common::crypto::Ed25519Key,
            dkim2::{Dkim2Signer, Envelope, Hop},
        };
        use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

        let load = |domain: &str, selector: &str| {
            let pem = std::fs::read(resource(&[
                "keys",
                &format!("{selector}._domainkey.{domain}.pem"),
            ]))
            .unwrap();
            let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
                panic!("expected PKCS8 key");
            };
            Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
        };

        let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();

        let hop1 = Dkim2Signer::from_key(load("test1.dkim2.com", "ed25519"))
            .domain("test1.dkim2.com")
            .selector("ed25519");
        let sign1 = hop1
            .sign(
                &original,
                Hop::real("sender@test1.dkim2.com", ["list@test2.dkim2.com"]),
            )
            .unwrap();
        let message1 = prepend(&sign1, &original);

        let hop2 = Dkim2Signer::from_key(load("test2.dkim2.com", "ed25519"))
            .domain("test2.dkim2.com")
            .selector("ed25519");
        let sign2 = hop2
            .sign(
                &message1,
                Hop::real("relay@test2.dkim2.com", ["recipient@example.com"]),
            )
            .unwrap();
        let message2 = prepend(&sign2, &message1);

        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let message = AuthenticatedMessage::parse(&message2).unwrap();
        let params = caches.parameters(&message);
        let envelope = Envelope::new("relay@test2.dkim2.com", ["recipient@example.com"]);
        let output = resolver
            .verify_dkim2_(&message, envelope, params.cache_txt, NOW, true)
            .await;
        assert_eq!(
            output.result(),
            &Dkim2Result::Pass,
            "{:?}",
            output.failure_reason()
        );
        assert_eq!(output.chain().len(), 2);
    }

    #[tokio::test]
    async fn sign_multi_algorithm_then_verify() {
        use crate::{
            common::crypto::{Algorithm, Ed25519Key, RsaKey, Sha256},
            dkim2::{Dkim2Signer, Envelope, Hop},
        };
        use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

        let load_ed = |domain: &str, selector: &str| {
            let pem = std::fs::read(resource(&[
                "keys",
                &format!("{selector}._domainkey.{domain}.pem"),
            ]))
            .unwrap();
            let PrivateKeyDer::Pkcs8(der) = PrivateKeyDer::from_pem_slice(&pem).unwrap() else {
                panic!("expected PKCS8 key");
            };
            Ed25519Key::from_pkcs8_maybe_unchecked_der(der.secret_pkcs8_der()).unwrap()
        };
        let load_rsa = |domain: &str, selector: &str| {
            let pem = std::fs::read(resource(&[
                "keys",
                &format!("{selector}._domainkey.{domain}.pem"),
            ]))
            .unwrap();
            RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(&pem).unwrap()).unwrap()
        };

        let original = std::fs::read(resource(&["emails", "simple.eml"])).unwrap();

        let signed = Dkim2Signer::from_key(load_ed("test1.dkim2.com", "ed25519"))
            .domain("test1.dkim2.com")
            .selector("ed25519")
            .additional_key(load_rsa("test1.dkim2.com", "sel1"), "sel1")
            .sign(
                &original,
                Hop::real("sender@test1.dkim2.com", ["recipient@example.com"]),
            )
            .unwrap();

        assert_eq!(signed.signature.s.len(), 2);
        assert_eq!(signed.signature.s[0].selector, "ed25519");
        assert_eq!(signed.signature.s[0].a, Algorithm::Ed25519Sha256);
        assert_eq!(signed.signature.s[1].selector, "sel1");
        assert_eq!(signed.signature.s[1].a, Algorithm::RsaSha256);

        let message = prepend(&signed, &original);
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let parsed = AuthenticatedMessage::parse(&message).unwrap();
        let params = caches.parameters(&parsed);
        let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
        let output = resolver
            .verify_dkim2_(&parsed, envelope, params.cache_txt, NOW, true)
            .await;
        assert_eq!(
            output.result(),
            &Dkim2Result::Pass,
            "{:?}",
            output.failure_reason()
        );
    }

    #[tokio::test]
    async fn verify_rejects_wrong_envelope() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let envelope = Envelope::new("attacker@evil.example", ["recipient@example.com"]);
        let result = verify_file(&resolver, &caches, "simple-ed25519.eml", envelope).await;
        assert!(
            matches!(result, Dkim2Result::PermError(_)),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_tampered_body() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let raw = std::fs::read(resource(&["expected", "simple-ed25519.eml"])).unwrap();
        let mut tampered = raw.clone();
        let pos = tampered.windows(5).position(|w| w == b"Hello").unwrap();
        tampered[pos] = b'J';
        let message = AuthenticatedMessage::parse(&tampered).unwrap();
        let params = caches.parameters(&message);
        let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
        let result = resolver
            .verify_dkim2_(&message, envelope, params.cache_txt, NOW, true)
            .await;
        assert!(
            matches!(result.result(), Dkim2Result::Fail(_)),
            "got {:?}",
            result.result()
        );
    }

    #[tokio::test]
    async fn verify_rejects_tampered_header() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let raw = std::fs::read(resource(&["expected", "simple-ed25519.eml"])).unwrap();
        let mut tampered = raw.clone();
        let pos = tampered.windows(6).position(|w| w == b"Simple").unwrap();
        tampered[pos] = b'X';
        let message = AuthenticatedMessage::parse(&tampered).unwrap();
        let params = caches.parameters(&message);
        let envelope = Envelope::new("sender@test1.dkim2.com", ["recipient@example.com"]);
        let result = resolver
            .verify_dkim2_(&message, envelope, params.cache_txt, NOW, true)
            .await;
        assert!(
            matches!(
                result.result(),
                Dkim2Result::Fail(Error::Dkim2(Dkim2Error::HeaderHashMismatch(_)))
            ),
            "got {:?}",
            result.result()
        );
    }

    #[tokio::test]
    async fn verify_rejects_rcpt_not_in_rt() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();
        let envelope = Envelope::new("sender@test1.dkim2.com", ["someone-else@example.com"]);
        let result = verify_file(&resolver, &caches, "simple-ed25519.eml", envelope).await;
        assert!(
            matches!(
                result,
                Dkim2Result::PermError(Error::Dkim2(Dkim2Error::RcptToMismatch(_)))
            ),
            "got {result:?}"
        );
    }

    fn state_matches(expected: &str, result: &Dkim2Result) -> bool {
        match expected {
            "pass" => matches!(result, Dkim2Result::Pass),
            "fail" => matches!(result, Dkim2Result::Fail(_)),
            "permerror" => matches!(result, Dkim2Result::PermError(_)),
            "temperror" => matches!(result, Dkim2Result::TempError(_)),
            other => panic!("unknown expected state {other}"),
        }
    }

    #[tokio::test]
    async fn test_vectors() {
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = load_caches();

        let cases = std::fs::read(resource(&["cases.json"])).unwrap();
        let cases: serde_json::Value = serde_json::from_slice(&cases).unwrap();
        let cases = cases.as_array().unwrap();
        assert!(!cases.is_empty(), "no imported vectors found");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let expected = case["expected"].as_str().unwrap();
            let file = case["file"].as_str().unwrap();
            let mail_from = case["mail_from"].as_str().unwrap().to_string();
            let rcpt_to: Vec<String> = case["rcpt_to"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_string())
                .collect();

            let now = case["now"]
                .as_u64()
                .expect("vector manifest must carry now");
            let strict = case["strict"].as_bool().unwrap_or(true);

            let raw = std::fs::read(resource(&["expected", file])).unwrap();
            let Some(message) = AuthenticatedMessage::parse(&raw) else {
                failures.push(format!("{name}: message failed to parse"));
                continue;
            };
            let params = caches.parameters(&message);
            let envelope = Envelope::new(&mail_from, &rcpt_to);
            let lenient = (!strict).then(super::test_reverse_path::LenientReversePath::new);
            let output = resolver
                .verify_dkim2_(&message, envelope, params.cache_txt, now, true)
                .await;
            drop(lenient);
            if !state_matches(expected, output.result()) {
                failures.push(format!(
                    "{name}: expected {expected}, got {:?} ({:?})",
                    output.result(),
                    output.failure_reason()
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "{} of {} vectors diverged:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }
}
