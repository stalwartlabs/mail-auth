/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM2 chain verification (§10 and §11) through
//! [`MessageAuthenticator::verify_dkim2`].

use super::{
    ChainBinding, ChainLink, Dkim2Error, Dkim2Output, Flag, MessageInstance, Signature,
    sign::Envelope,
};
use crate::dns::DnsCache;
use crate::{
    AuthenticatedMessage, Dkim2Result, DnsError, Error, MessageAuthenticator, Parameters,
    ResolverCache, TxtRecord,
    crypto::{Algorithm, CryptoError, HashAlgorithm},
    dkim::DkimError,
    dkim::DomainKey,
    dkim2::{canonicalize::CanonicalizedHeaderWriter, sign::now},
    headers::{Header, HeaderIterator, HeaderStream, Writer},
};

const MAX_AGE: u64 = 14 * 86400;
const MAX_CHAIN_LENGTH: usize = 50;

impl MessageAuthenticator {
    /// Verifies the DKIM2 signature chain of an RFC 5322 message.
    ///
    /// `params` wraps the parsed message, optionally with a DNS cache (see
    /// [`Parameters`]); a plain `&AuthenticatedMessage` also works.
    /// `envelope` is the SMTP envelope the message was received with. It
    /// must match the most recent signature: `MAIL FROM` equals its `mf=`
    /// and every `RCPT TO` appears in its `rt=`.
    ///
    /// The verifier checks, in order, the syntax and numbering of every
    /// `DKIM2-Signature` and `Message-Instance`, the signature timestamps
    /// (at most 14 days old), the envelope binding and chain of custody,
    /// every signature value, the header and body hashes of every instance
    /// (applying recipes to recreate earlier revisions) and finally the
    /// `donotmodify` and `donotexplode` requests. It stops at the first
    /// failure.
    ///
    /// For each `s=` entry of each signature it performs one DNS TXT lookup
    /// for the public key at `<selector>._domainkey.<d>`, served from the
    /// cache when one is given.
    ///
    /// The returned [`Dkim2Output`] holds one of:
    ///
    /// - [`Dkim2Result::Pass`]: the whole chain verified. The output lists
    ///   every hop in [`Dkim2Output::chain`].
    /// - [`Dkim2Result::Fail`]: a signature value, header hash or body hash
    ///   did not match, a signature has no supported algorithm, or a
    ///   `donotmodify`/`donotexplode` request was not honored.
    /// - [`Dkim2Result::PermError`]: a DKIM2 header field is malformed or
    ///   incomplete, the chain is longer than 50 hops, a signature expired,
    ///   the envelope or chain of custody does not match, or a public key is
    ///   missing, invalid, revoked or of the wrong type.
    /// - [`Dkim2Result::TempError`]: a public key lookup failed with a
    ///   temporary DNS error.
    /// - [`Dkim2Result::None`]: the message has no `DKIM2-Signature`, or the
    ///   signature numbering does not run from 1 without gaps.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::{AuthenticatedMessage, Dkim2Result, MessageAuthenticator, dkim2::Envelope};
    ///
    /// # async fn run(raw_message: &[u8]) {
    /// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
    /// let message = AuthenticatedMessage::parse(raw_message).unwrap();
    ///
    /// let envelope = Envelope::new("sender@example.com", ["recipient@example.org"]);
    /// let output = authenticator.verify_dkim2(&message, envelope).await;
    ///
    /// match output.result() {
    ///     Dkim2Result::Pass => {
    ///         for link in output.chain() {
    ///             println!("hop {} signed by {}", link.signature.i, link.signature.d);
    ///         }
    ///     }
    ///     Dkim2Result::None => println!("not DKIM2 signed"),
    ///     _ => println!("DKIM2 failed: {:?}", output.error()),
    /// }
    /// # }
    /// ```
    pub async fn verify_dkim2<'x, C, A, R>(
        &self,
        params: impl Into<Parameters<'x, &'x AuthenticatedMessage<'x>, C>>,
        envelope: Envelope<A, R>,
    ) -> Dkim2Output<'x>
    where
        C: DnsCache + 'x,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
    {
        let params = params.into();
        self.verify_dkim2_(params.input, envelope, params.txt_cache(), now(), true)
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
        TXT: ResolverCache<Box<str>, TxtRecord>,
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
        } else if message.dkim2_signatures.len() > MAX_CHAIN_LENGTH
            || message.dkim2_instances.len() > MAX_CHAIN_LENGTH
        {
            return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::ChainTooLong)).into();
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
                return Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureTagUnexpected {
                    i: top_signature.i,
                    tag: "nd",
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
                    let current_domain = match &current.chain {
                        ChainBinding::Envelope { mail_from, .. } => local_and_domain(mail_from).1,
                        ChainBinding::NextDomain(_) => current.d.as_str(),
                    };
                    let custody_ok = rcpt_to.iter().any(|rcpt| {
                        let (_, rcpt_domain) = local_and_domain(rcpt);
                        relaxed_domain_match(current_domain, rcpt_domain)
                    });
                    if !custody_ok {
                        let error = match &current.chain {
                            ChainBinding::Envelope { .. } => {
                                Dkim2Error::MailFromMismatch(current.i)
                            }
                            ChainBinding::NextDomain(_) => Dkim2Error::CustodyBreak(current.i),
                        };
                        return Dkim2Result::PermError(Error::Dkim2(error)).into();
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
                    Err(Error::Dkim(DkimError::PublicKeyRevoked)) => {
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

/// Exact reverse-path or forward-path comparison for the chain-of-custody
/// check.
fn address_matches(envelope: &str, signed: &str) -> bool {
    let (el, ed) = local_and_domain(envelope);
    let (sl, sd) = local_and_domain(signed);
    el == sl && ed.eq_ignore_ascii_case(sd)
}

/// Whether a signed `mf=` or `rt=` value is a well-formed RFC 5321 path.
#[inline(always)]
fn is_reverse_path(value: &str) -> bool {
    value.starts_with('<') && value.ends_with('>')
}

/// Whether the verifier requires signed `mf=` and `rt=` values to carry
/// angle brackets.
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

/// Writes the canonicalized `DKIM2-Signature` value with the base64
/// signature values of the `s=` tag removed (§9.6).
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
            (
                "i=1; m=1; t=5; d=ex.com; mf=YQ==; rt=Yg==; s=sel:alg:U0lH;",
                "dkim2-signature:i=1;m=1;t=5;d=ex.com;mf=YQ==;rt=Yg==;s=sel:alg:;\r\n",
            ),
            ("i=1; s=sel:alg:U0lH", "dkim2-signature:i=1;s=sel:alg:\r\n"),
            ("s=a:b:U0lH,c:d:WkZa;", "dkim2-signature:s=a:b:,c:d:;\r\n"),
            (
                "s=sel:alg:U0lH; f=donotmodify;",
                "dkim2-signature:s=sel:alg:;f=donotmodify;\r\n",
            ),
            (
                "i=1;\r\n m=1;\r\n\ts=sel:alg:U0\r\n lH;",
                "dkim2-signature:i=1;m=1;s=sel:alg:;\r\n",
            ),
            ("  i=1; s=a:b:CC;  ", "dkim2-signature:i=1;s=a:b:;\r\n"),
            ("s=a:b:CC; i=1;", "dkim2-signature:s=a:b:;i=1;\r\n"),
            (
                "i=1;s=a:b:CC;f=exploded;",
                "dkim2-signature:i=1;s=a:b:;f=exploded;\r\n",
            ),
            ("n=foo; s=a:b:CC;", "dkim2-signature:n=foo;s=a:b:;\r\n"),
            (
                "d=sub.ex.com; s=ed25519:ed25519-sha256:F//Dt+leS4H;",
                "dkim2-signature:d=sub.ex.com;s=ed25519:ed25519-sha256:;\r\n",
            ),
            ("", "dkim2-signature:\r\n"),
            ("d=as; s=a:b:CC;", "dkim2-signature:d=as;s=a:b:;\r\n"),
            ("S=sel:alg:CC;", "dkim2-signature:S=sel:alg:;\r\n"),
            (
                "s=badset; n=a:b:c;",
                "dkim2-signature:s=badset;n=a:b:c;\r\n",
            ),
            ("s=; n=a:b:c;", "dkim2-signature:s=;n=a:b:c;\r\n"),
            ("s=sel:alg; i=1;", "dkim2-signature:s=sel:alg;i=1;\r\n"),
            (
                "i=1; mf=QQ s=; s=a:b:CC;",
                "dkim2-signature:i=1;mf=QQs=;s=a:b:;\r\n",
            ),
            ("mf=QQ s=; n=a:b:c;", "dkim2-signature:mf=QQs=;n=a:b:c;\r\n"),
            (
                "rt=QQ s=,WWW; s=a:b:CC;",
                "dkim2-signature:rt=QQs=,WWW;s=a:b:;\r\n",
            ),
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
mod tests;
