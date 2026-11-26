/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM2 chain verification (§13 and §14) through
//! [`MessageAuthenticator::verify_dkim2`] and
//! [`MessageAuthenticator::verify_dkim2_provisionally`].

use super::{
    ChainBinding, ChainLink, Dkim2Error, Dkim2Hash, Dkim2Output, Dkim2Signed, MessageHash,
    MessageInstance, Signature, SignatureValue, Verification,
    recipe::{BodyRecipe, apply_body_recipe, headers_len},
    sign::Envelope,
};
use crate::dns::DnsCache;
use crate::{
    AuthenticatedMessage, Dkim2Result, DnsError, Error, MessageAuthenticator, Parameters,
    ResolverCache, TxtRecord,
    crypto::{Algorithm, CryptoError},
    dkim::{DkimError, DomainKey},
    dkim2::{DomainPolicy, Flag, parse::is_domain},
    dkim2::{
        canonicalize::{CanonicalizedHeaderWriter, Digests, body_digests, header_digests},
        sign::now,
    },
    dns::to_a_label,
    headers::{Header, HeaderIterator, Writer},
};
use mail_parser::{Address, HeaderForm};
use outcome::{Failure, Tally};
use std::borrow::Cow;

pub(crate) mod outcome;

const MAX_AGE: u64 = 14 * 86400;
const MAX_FUTURE: u64 = 86400;
const MAX_CHAIN_LENGTH: usize = 50;
const MIN_RSA_BITS: usize = 1024;

impl MessageAuthenticator {
    /// Verifies the DKIM2 signature chain of an RFC 5322 message: whether it
    /// is a Fully Verified DKIM2 Message (§13 and §14).
    ///
    /// `params` wraps the parsed message, optionally with a DNS cache (see
    /// [`Parameters`]); a plain `&AuthenticatedMessage` also works.
    /// `envelope` is the SMTP envelope the message was received with. It
    /// must match the most recent signature: `MAIL FROM` equals its `mf=`
    /// and every `RCPT TO` appears in its `rt=`.
    ///
    /// The verifier checks, in order, the syntax and numbering of every
    /// `DKIM2-Signature` and `Message-Instance` (§14.2), the signature
    /// timestamps (at most 14 days old and at most one day in the future,
    /// §14.3), the envelope binding, the `mf=`/`d=` match of every signature
    /// and the chain of custody (§14.4), the signatures of every
    /// `DKIM2-Signature` (§14.5 and §14.6), the hashes of every instance,
    /// applying recipes to recreate earlier revisions (§14.7), and that every
    /// `From` header field, current or recreated, is Authentic (§11 and
    /// §14.8). Signatures and hashes are combined over their `,` and `|`
    /// groups: a group passes when all its entries pass, and the tag passes
    /// when any group does. It stops once the result is known. Domains are
    /// compared as A-labels (§18).
    ///
    /// For each `s=` entry it evaluates it performs one DNS TXT lookup for
    /// the public key at `<selector>._domainkey.<d>`, served from the cache
    /// when one is given. Entries of a group that already failed and groups
    /// after one that passed are not looked up. A `From` domain that is only
    /// Authentic because `d=` is one of its subdomains also costs one lookup
    /// of its Domain Policy Record at `_domainkey.<from domain>` (§3.8,
    /// §11.1), made after the signatures verified.
    ///
    /// The returned [`Dkim2Output`] holds one of:
    ///
    /// - [`Dkim2Result::Pass`]: the whole chain verified. The output lists
    ///   every hop in [`Dkim2Output::chain`].
    /// - [`Dkim2Result::Fail`]: verification completed but the message is not
    ///   a Fully Verified DKIM2 Message: a signature, header hash or body hash
    ///   did not match, a timestamp is out of range, the envelope or chain of
    ///   custody does not match, or a `From` header field is not Authentic
    ///   (including a subdomain signature that the `From` domain forbids
    ///   with `f=strict`).
    /// - [`Dkim2Result::PermError`]: a DKIM2 header field is malformed,
    ///   incomplete, missing or duplicated, the numbering has a gap, the first
    ///   signature has the `exploded` flag, the chain is longer than 50 hops,
    ///   a null body recipe prevents checking earlier body hashes, a signature
    ///   or hash algorithm is not implemented, a public key is missing,
    ///   malformed, too short, duplicated, revoked or of the wrong type and no
    ///   group passed, or the `From` domain has more than one Domain Policy
    ///   Record.
    /// - [`Dkim2Result::TempError`]: a public key lookup failed with a
    ///   temporary DNS error and no group passed, or a Domain Policy Record
    ///   lookup failed with a temporary DNS error.
    /// - [`Dkim2Result::None`]: the message has no `DKIM2-Signature` and no
    ///   `Message-Instance` header field.
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
        self.verify_dkim2_(
            params.input,
            envelope,
            params.txt_cache(),
            now(),
            true,
            Verification::Full,
        )
        .await
    }

    /// Checks whether a message is Provisionally Verified (§13.2): the
    /// initial assessment a receiver may make before accepting delivery,
    /// and the precondition for later sending a DSN about the message.
    ///
    /// Performs the header field validity, timestamp and envelope checks of
    /// [`verify_dkim2`](Self::verify_dkim2), then verifies only the most
    /// recent signature and the hashes of the most recent `Message-Instance`.
    /// It does not check the chain of custody of earlier hops, earlier
    /// signatures or hashes, or whether `From` header fields are Authentic.
    /// A most recent signature with `nd=` is a [`Dkim2Result::Fail`] (§14.4).
    ///
    /// A passing result is reported with [`Verification::Provisional`], its
    /// [`Dkim2Output::chain`] holds only the most recent signature, and it is
    /// neither a proof of validity for [`Dkim2Signer`](super::Dkim2Signer)
    /// nor an authenticated identity for DMARC or Authentication-Results.
    pub async fn verify_dkim2_provisionally<'x, C, A, R>(
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
        self.verify_dkim2_(
            params.input,
            envelope,
            params.txt_cache(),
            now(),
            true,
            Verification::Provisional,
        )
        .await
    }

    /// Fetches the DKIM2 Domain Policy Record of `domain` from
    /// `_domainkey.<domain>` (§3.8), served from the cache when one is
    /// given. `domain` is mapped to an A-label and a trailing dot is ignored.
    /// A domain without a record gets the default policy, which authorizes
    /// subdomains.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::MultipleRecords`] when the name
    /// has more than one Domain Policy Record, or the lookup error otherwise
    /// (such as [`DnsError::Resolver`] for a temporary failure).
    pub async fn dkim2_domain_policy(
        &self,
        domain: &str,
        cache_txt: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
    ) -> crate::Result<DomainPolicy> {
        let domain = to_a_label(domain.strip_suffix('.').unwrap_or(domain));
        match self
            .txt_lookup::<DomainPolicy>(format!("_domainkey.{domain}."), cache_txt)
            .await
        {
            Ok(policy) => Ok(*policy),
            Err(Error::Dns(DnsError::RecordNotFound(_))) => Ok(DomainPolicy::default()),
            Err(err) => Err(err),
        }
    }

    /// Checks that the Domain Policy Record of the `From` domain permits a
    /// signature made with [`Dkim2Signer::allow_from_subdomain`](super::Dkim2Signer::allow_from_subdomain)
    /// (§12.4). Returns `Ok(())` without a lookup when
    /// [`Dkim2Signed::policy_domain`](super::Dkim2Signed::policy_domain) is
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns the errors the verifier reports for the same record:
    /// [`Dkim2Error::FromSubdomainForbidden`] when the record has `f=strict`,
    /// [`Dkim2Error::PolicyMultiple`] when the domain has more than one
    /// record, and [`Dkim2Error::PolicyFetch`] when it cannot be fetched. The
    /// signature must not be used in any of these cases.
    pub async fn dkim2_check_policy(
        &self,
        signed: &Dkim2Signed,
        cache_txt: Option<&impl ResolverCache<Box<str>, TxtRecord>>,
    ) -> Result<(), Dkim2Error> {
        let Some(domain) = signed.policy_domain() else {
            return Ok(());
        };
        self.check_domain_policy(
            &PolicyCheck {
                i: signed.signature.i,
                domain: domain.into(),
            },
            cache_txt,
        )
        .await
        .map_err(Failure::into_error)
    }

    pub(crate) async fn verify_dkim2_<'x, TXT, A, R>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        envelope: Envelope<A, R>,
        cache_txt: Option<&TXT>,
        now: u64,
        body_present: bool,
        verification: Verification,
    ) -> Dkim2Output<'x>
    where
        TXT: ResolverCache<Box<str>, TxtRecord>,
        A: AsRef<str>,
        R: IntoIterator<Item: AsRef<str>>,
    {
        let result = self
            .verify_chain(
                message,
                envelope,
                cache_txt,
                now,
                body_present,
                verification,
            )
            .await;
        let signatures = message.dkim2_signatures.as_slice();
        let instances = message.dkim2_instances.as_slice();
        let verified = match verification {
            Verification::Full => signatures,
            Verification::Provisional => signatures
                .len()
                .checked_sub(1)
                .and_then(|top| signatures.get(top..))
                .unwrap_or_default(),
        };
        let chain = match result {
            Ok(()) => verified
                .iter()
                .map(|sig_header| ChainLink {
                    signature: &sig_header.header,
                    instance: sig_header
                        .header
                        .m
                        .checked_sub(1)
                        .and_then(|index| instances.get(index as usize))
                        .map(|h| &h.header),
                    result: Dkim2Result::Pass,
                    custody_ok: true,
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        Dkim2Output {
            result: match result {
                Ok(()) => Dkim2Result::Pass,
                Err(result) => result,
            },
            chain,
            verification,
            raw_message: message.raw_message,
            headers: &message.headers,
            signature_fields: signatures,
            instance_fields: instances,
        }
    }

    async fn verify_chain<TXT, A, R>(
        &self,
        message: &AuthenticatedMessage<'_>,
        envelope: Envelope<A, R>,
        cache_txt: Option<&TXT>,
        now: u64,
        body_present: bool,
        verification: Verification,
    ) -> Result<(), Dkim2Result>
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
                    return Err(Dkim2Result::from(header.header.clone()));
                }
            }
        }

        let signatures = message.dkim2_signatures.as_slice();
        let instances = message.dkim2_instances.as_slice();
        if signatures.is_empty() {
            return Err(if instances.is_empty() {
                Dkim2Result::None
            } else {
                perm_error(Dkim2Error::SignatureMissing(1))
            });
        } else if signatures.len() > MAX_CHAIN_LENGTH || instances.len() > MAX_CHAIN_LENGTH {
            return Err(perm_error(Dkim2Error::ChainTooLong));
        }

        check_numbering(signatures, instances).map_err(perm_error)?;
        check_timestamps(signatures, now).map_err(fail)?;

        let Some((top, previous)) = signatures.split_last() else {
            return Err(perm_error(Dkim2Error::SignatureMissing(1)));
        };
        let top = &top.header;
        check_envelope(top, envelope).map_err(fail)?;

        match verification {
            Verification::Full => {
                for header in signatures {
                    check_mail_from_domain(&header.header).map_err(fail)?;
                }
                for pair in signatures.windows(2) {
                    if let [previous, current] = pair {
                        check_custody(&previous.header, &current.header).map_err(fail)?;
                    }
                }
            }
            Verification::Provisional => check_mail_from_domain(top).map_err(fail)?,
        }

        let checked = match verification {
            Verification::Full => signatures,
            Verification::Provisional => signatures.get(previous.len()..).unwrap_or_default(),
        };
        let mut policies = Vec::new();
        match verification {
            Verification::Full => {
                check_instances(message, signatures, instances, body_present, &mut policies)
            }
            Verification::Provisional => instances.last().map_or(Ok(()), |header| {
                StateHashes::for_message(message).check(
                    &header.header,
                    &message.headers,
                    body_present.then(|| message.raw_body()),
                )
            }),
        }
        .map_err(Dkim2Result::from)?;

        let mut input = Vec::with_capacity(256 * (instances.len() + signatures.len()));
        let mut temp_error = None;
        for sig_header in checked {
            match self
                .check_signature(sig_header, signatures, instances, cache_txt, &mut input)
                .await
            {
                Ok(()) => {}
                Err(Failure::TempError(error)) => {
                    temp_error.get_or_insert(error);
                }
                Err(failure) => return Err(failure.into()),
            }
        }
        for check in &policies {
            match self.check_domain_policy(check, cache_txt).await {
                Ok(()) => {}
                Err(Failure::TempError(error)) => {
                    temp_error.get_or_insert(error);
                }
                Err(failure) => return Err(failure.into()),
            }
        }
        temp_error.map_or(Ok(()), |error| Err(Failure::TempError(error).into()))
    }

    async fn check_domain_policy<TXT>(
        &self,
        check: &PolicyCheck,
        cache_txt: Option<&TXT>,
    ) -> Result<(), Failure>
    where
        TXT: ResolverCache<Box<str>, TxtRecord>,
    {
        let policy_error =
            |error: fn(u32, Box<str>) -> Dkim2Error| error(check.i, check.domain.clone());
        match self.dkim2_domain_policy(&check.domain, cache_txt).await {
            Ok(policy) if policy.is_strict() => Err(Failure::Fail(policy_error(|i, domain| {
                Dkim2Error::FromSubdomainForbidden { i, domain }
            }))),
            Ok(_) => Ok(()),
            Err(Error::Dns(DnsError::MultipleRecords)) => {
                Err(Failure::PermError(policy_error(|i, domain| {
                    Dkim2Error::PolicyMultiple { i, domain }
                })))
            }
            Err(_) => Err(Failure::TempError(policy_error(|i, domain| {
                Dkim2Error::PolicyFetch { i, domain }
            }))),
        }
    }

    async fn check_signature<TXT>(
        &self,
        sig_header: &Header<'_, Signature>,
        signatures: &[Header<'_, Signature>],
        instances: &[Header<'_, MessageInstance>],
        cache_txt: Option<&TXT>,
        input: &mut Vec<u8>,
    ) -> Result<(), Failure>
    where
        TXT: ResolverCache<Box<str>, TxtRecord>,
    {
        let signature = &sig_header.header;

        input.clear();
        for (name, value) in instances
            .iter()
            .filter(|h| h.header.m <= signature.m)
            .map(|h| (h.name, h.value))
            .chain(
                signatures
                    .iter()
                    .take_while(|h| h.header.i < signature.i)
                    .map(|h| (h.name, h.value)),
            )
        {
            let mut w = CanonicalizedHeaderWriter::new(input, name);
            w.write(value);
            w.finalize();
        }
        strip_and_canonicalize_signature(sig_header.value, input);

        let mut groups = Tally::default();
        for group in signature.s.chunk_by(|a, b| a.group == b.group) {
            let mut entries = Tally::default();
            for value in group {
                entries.record(
                    self.check_signature_value(signature, value, input, cache_txt)
                        .await,
                );
                if entries.failed() {
                    break;
                }
            }
            groups.record(entries.all());
            if groups.passed() {
                return Ok(());
            }
        }
        groups.any(Dkim2Error::NoSignatureGroupPassed(signature.i))
    }

    async fn check_signature_value<TXT>(
        &self,
        signature: &Signature,
        value: &SignatureValue,
        input: &[u8],
        cache_txt: Option<&TXT>,
    ) -> Result<(), Failure>
    where
        TXT: ResolverCache<Box<str>, TxtRecord>,
    {
        let key_error = |error: fn(u32, Box<str>) -> Dkim2Error| {
            error(signature.i, value.selector.as_str().into())
        };
        let Some(algorithm) = value.a.known() else {
            return Err(Failure::PermError(key_error(|i, selector| {
                Dkim2Error::UnknownAlgorithm { i, selector }
            })));
        };
        let key = match self
            .txt_lookup::<DomainKey>(
                format!("{}._domainkey.{}.", value.selector, signature.d),
                cache_txt,
            )
            .await
        {
            Ok(key) => key,
            Err(Error::Dns(DnsError::Resolver(_))) => {
                return Err(Failure::TempError(key_error(|i, selector| {
                    Dkim2Error::PublicKeyFetch { i, selector }
                })));
            }
            Err(err) => {
                return Err(Failure::PermError(key_error(match err {
                    Error::Dkim(DkimError::PublicKeyRevoked) => {
                        |i, selector| Dkim2Error::PublicKeyRevoked { i, selector }
                    }
                    Error::Dns(DnsError::RecordNotFound(_)) => {
                        |i, selector| Dkim2Error::PublicKeyMissing { i, selector }
                    }
                    Error::Dkim(DkimError::UnsupportedKeyType) => {
                        |i, selector| Dkim2Error::PublicKeyAlgorithmMismatch { i, selector }
                    }
                    Error::Crypto(CryptoError::MalformedPublicKey) => {
                        |i, selector| Dkim2Error::PublicKeyMalformed { i, selector }
                    }
                    _ => |i, selector| Dkim2Error::PublicKeySyntax { i, selector },
                })));
            }
        };

        if key.has_multiple_records() {
            return Err(Failure::PermError(key_error(|i, selector| {
                Dkim2Error::PublicKeyMultiple { i, selector }
            })));
        } else if matches!(algorithm, Algorithm::RsaSha256)
            && key.p.public_key_bits() < MIN_RSA_BITS
        {
            return Err(Failure::PermError(key_error(|i, selector| {
                Dkim2Error::PublicKeyTooShort { i, selector }
            })));
        }

        match key.p.verify_bytes(input, &value.b, algorithm) {
            Ok(()) => Ok(()),
            Err(Error::Crypto(CryptoError::IncompatibleAlgorithms)) => {
                Err(Failure::PermError(key_error(|i, selector| {
                    Dkim2Error::PublicKeyAlgorithmMismatch { i, selector }
                })))
            }
            Err(_) => Err(Failure::Fail(key_error(|i, selector| {
                Dkim2Error::IncorrectSignature { i, selector }
            }))),
        }
    }
}

#[cold]
fn perm_error(error: Dkim2Error) -> Dkim2Result {
    Dkim2Result::PermError(Error::Dkim2(error))
}

#[cold]
fn fail(error: Dkim2Error) -> Dkim2Result {
    Dkim2Result::Fail(Error::Dkim2(error))
}

fn check_timestamps(signatures: &[Header<'_, Signature>], now: u64) -> Result<(), Dkim2Error> {
    for header in signatures {
        let signature = &header.header;
        if now > signature.t && now - signature.t > MAX_AGE {
            return Err(Dkim2Error::SignatureExpired(signature.i));
        } else if signature.t > now.saturating_add(MAX_FUTURE) {
            return Err(Dkim2Error::SignatureFromFuture(signature.i));
        }
    }
    Ok(())
}

fn check_numbering(
    signatures: &[Header<'_, Signature>],
    instances: &[Header<'_, MessageInstance>],
) -> Result<(), Dkim2Error> {
    for (expected, header) in (1u32..).zip(signatures) {
        let signature = &header.header;
        if expected > 1 && signature.i == expected - 1 {
            return Err(Dkim2Error::SignatureDuplicated(signature.i));
        } else if signature.i != expected {
            return Err(Dkim2Error::SequenceGap(expected));
        } else if expected == 1 && signature.flags.contains(&Flag::Exploded) {
            return Err(Dkim2Error::ExplodedFirstSignature);
        }
        if let ChainBinding::Envelope { mail_from, rcpt_to } = &signature.chain
            && require_reverse_path()
            && !(is_reverse_path(mail_from) && rcpt_to.iter().all(|r| is_reverse_path(r)))
        {
            return Err(Dkim2Error::SignatureSyntax(signature.i));
        }
    }

    for (expected, header) in (1u32..).zip(instances) {
        let m = header.header.m;
        if expected > 1 && m == expected - 1 {
            return Err(Dkim2Error::InstanceDuplicated(m));
        } else if m != expected {
            return Err(Dkim2Error::InstanceMissing(expected));
        }
    }

    let highest_m = instances.last().map_or(0, |h| h.header.m);
    let mut previous_m = 0;
    for header in signatures {
        let signature = &header.header;
        if signature.m == 0 || signature.m > highest_m {
            return Err(Dkim2Error::InstanceMissing(signature.m));
        } else if signature.m < previous_m {
            return Err(Dkim2Error::SignatureSyntax(signature.i));
        }
        previous_m = signature.m;
    }
    if highest_m > previous_m {
        return Err(Dkim2Error::InstanceNotSigned(highest_m));
    }

    Ok(())
}

fn check_envelope<A, R>(top: &Signature, envelope: Envelope<A, R>) -> Result<(), Dkim2Error>
where
    A: AsRef<str>,
    R: IntoIterator<Item: AsRef<str>>,
{
    match &top.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => {
            let envelope_from = envelope.mail_from.as_ref();
            if !address_matches(envelope_from, mail_from) {
                return Err(Dkim2Error::MailFromMismatch {
                    i: top.i,
                    value: envelope_from.into(),
                });
            }
            for rcpt in envelope.rcpt_to {
                let rcpt = rcpt.as_ref();
                if !rcpt_to.iter().any(|r| address_matches(rcpt, r)) {
                    return Err(Dkim2Error::RcptToMismatch {
                        i: top.i,
                        value: rcpt.into(),
                    });
                }
            }
            Ok(())
        }
        ChainBinding::NextDomain(_) => Err(Dkim2Error::UnexpectedNextDomain(top.i)),
    }
}

pub(crate) fn check_mail_from_domain(signature: &Signature) -> Result<(), Dkim2Error> {
    match &signature.chain {
        ChainBinding::Envelope { mail_from, .. }
            if !is_null_path(mail_from)
                && !relaxed_domain_match(local_and_domain(mail_from).1, &signature.d) =>
        {
            Err(Dkim2Error::MailFromDomainMismatch(signature.i))
        }
        _ => Ok(()),
    }
}

pub(crate) fn check_custody(previous: &Signature, current: &Signature) -> Result<(), Dkim2Error> {
    match (&previous.chain, &current.chain) {
        (ChainBinding::NextDomain(next_domain), _) => {
            if domain_eq(next_domain, &current.d) {
                Ok(())
            } else {
                Err(Dkim2Error::NextDomainMismatch(current.i))
            }
        }
        (ChainBinding::Envelope { rcpt_to, .. }, ChainBinding::Envelope { mail_from, .. })
            if !is_null_path(mail_from) =>
        {
            let mail_from_domain = local_and_domain(mail_from).1;
            if rcpt_to
                .iter()
                .any(|rcpt| relaxed_domain_match(mail_from_domain, local_and_domain(rcpt).1))
            {
                Ok(())
            } else {
                Err(Dkim2Error::CustodyMailFromMismatch {
                    i: current.i,
                    previous: previous.i,
                })
            }
        }
        (ChainBinding::Envelope { rcpt_to, .. }, _) => {
            if rcpt_to
                .iter()
                .any(|rcpt| relaxed_domain_match(local_and_domain(rcpt).1, &current.d))
            {
                Ok(())
            } else {
                Err(Dkim2Error::CustodyDomainMismatch {
                    i: current.i,
                    previous: previous.i,
                })
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct StateHashes {
    header: Digests,
    body: Digests,
}

impl StateHashes {
    /// The starting hashes for `message`: empty, or the body digests of a
    /// streamed message.
    pub(crate) fn for_message(message: &AuthenticatedMessage<'_>) -> Self {
        match message.streamed_body.as_deref() {
            Some(body) => Self::with_body(body.dkim2.clone()),
            None => Self::default(),
        }
    }

    pub(crate) fn with_body(body: Digests) -> Self {
        StateHashes {
            header: Default::default(),
            body,
        }
    }

    pub(crate) fn check(
        &mut self,
        instance: &MessageInstance,
        headers: &[(&[u8], &[u8])],
        body: Option<&[u8]>,
    ) -> Result<(), Failure> {
        let mut header_wanted = [false; Dkim2Hash::COUNT];
        let mut body_wanted = [false; Dkim2Hash::COUNT];
        for algorithm in instance.hashes.iter().filter_map(|hash| hash.name.known()) {
            let index = algorithm.index();
            for (wanted, cached) in [
                (&mut header_wanted, &self.header),
                (&mut body_wanted, &self.body),
            ] {
                if let (Some(wanted), Some(None)) = (wanted.get_mut(index), cached.get(index)) {
                    *wanted = true;
                }
            }
        }
        if body.is_none() {
            body_wanted = [false; Dkim2Hash::COUNT];
        }
        fill(
            &mut self.header,
            header_digests(headers.iter().copied(), header_wanted),
        );
        if let Some(body) = body.filter(|_| body_wanted.contains(&true)) {
            fill(&mut self.body, body_digests(body, body_wanted));
        }

        let mut groups = Tally::default();
        for group in instance.hashes.chunk_by(|a, b| a.group == b.group) {
            let mut entries = Tally::default();
            for hash in group {
                entries.record(self.check_hash(instance.m, hash, body.is_some()));
                if entries.failed() {
                    break;
                }
            }
            groups.record(entries.all());
            if groups.passed() {
                return Ok(());
            }
        }
        groups.any(Dkim2Error::NoHashGroupPassed(instance.m))
    }

    fn check_hash(&self, m: u32, hash: &MessageHash, body_present: bool) -> Result<(), Failure> {
        let Some(algorithm) = hash.name.known() else {
            return Err(Failure::PermError(Dkim2Error::UnknownHash {
                m,
                name: hash.name.as_str().into(),
            }));
        };
        let index = algorithm.index();
        let matches = |digests: &Digests, expected: &[u8]| {
            digests
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|computed| computed.as_ref() == expected)
        };
        if !matches(&self.header, &hash.header_hash) {
            Err(Failure::Fail(Dkim2Error::HeaderHashMismatch {
                m,
                hash: algorithm,
            }))
        } else if body_present && !matches(&self.body, &hash.body_hash) {
            Err(Failure::Fail(Dkim2Error::BodyHashMismatch {
                m,
                hash: algorithm,
            }))
        } else {
            Ok(())
        }
    }
}

fn fill(cache: &mut Digests, computed: Digests) {
    for (slot, digest) in cache.iter_mut().zip(computed) {
        if digest.is_some() {
            *slot = digest;
        }
    }
}

fn check_instances(
    message: &AuthenticatedMessage<'_>,
    signatures: &[Header<'_, Signature>],
    instances: &[Header<'_, MessageInstance>],
    body_present: bool,
    policies: &mut Vec<PolicyCheck>,
) -> Result<(), Failure> {
    let mut hashes = StateHashes::for_message(message);
    let mut header_buffer;
    let mut body_buffer;
    let mut headers: Cow<'_, [(&[u8], &[u8])]> = Cow::Borrowed(&message.headers);
    let mut body = body_present.then(|| message.raw_body());
    let mut from = FromDomain::parse(&message.headers);
    let mut null_body_recipe = None;

    for header in instances.iter().rev() {
        let instance = &header.header;
        if let Some(m) = null_body_recipe {
            return Err(Failure::PermError(Dkim2Error::NullBodyRecipe(m)));
        }
        hashes.check(instance, &headers, body)?;

        let Some(recipe) = instance.recipe.as_ref().filter(|_| instance.m > 1) else {
            continue;
        };
        let replaces_from = recipe
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("from"));
        if replaces_from {
            let signature = signatures
                .iter()
                .map(|h| &h.header)
                .find(|signature| signature.m >= instance.m)
                .ok_or(Failure::PermError(Dkim2Error::InstanceNotSigned(
                    instance.m,
                )))?;
            from.check(signature, policies).map_err(Failure::Fail)?;
        }

        match (&recipe.body, body) {
            (BodyRecipe::Steps(_), Some(_)) if message.is_streamed() => {
                return Err(Failure::TempError(Dkim2Error::BodyNotAvailable(instance.m)));
            }
            (BodyRecipe::Steps(steps), Some(current)) => {
                let mut previous = Vec::with_capacity(current.len());
                apply_body_recipe(current, steps, &mut previous);
                body_buffer = previous;
                body = Some(&body_buffer);
                hashes.body = Default::default();
            }
            (BodyRecipe::Unreconstructable, Some(_)) => {
                null_body_recipe = Some(instance.m);
                body = None;
            }
            (BodyRecipe::Unreconstructable, None) => {}
            (BodyRecipe::None, _) | (BodyRecipe::Steps(_), None) => {}
        }

        if !recipe.headers.is_empty() {
            let mut previous = Vec::with_capacity(headers_len(&headers));
            recipe.apply_headers(&headers, &mut previous);
            header_buffer = previous;
            headers = Cow::Owned(HeaderIterator::new(&header_buffer).collect());
            hashes.header = Default::default();
            if replaces_from {
                from = FromDomain::parse(&headers);
            }
        }
    }

    signatures.first().map_or(Ok(()), |first| {
        from.check(&first.header, policies).map_err(Failure::Fail)
    })
}

pub(crate) struct PolicyCheck {
    i: u32,
    domain: Box<str>,
}

pub(crate) enum FromDomain {
    Domain(String),
    MultipleAddresses,
    DomainLiteral,
    Invalid,
}

pub(crate) enum FromMatch<'x> {
    Authentic,
    Subdomain(&'x str),
}

impl FromDomain {
    pub(crate) fn parse(headers: &[(&[u8], &[u8])]) -> Self {
        let mut from = headers
            .iter()
            .filter(|(name, _)| name.trim_ascii().eq_ignore_ascii_case(b"from"));
        let (Some((_, value)), None) = (from.next(), from.next()) else {
            return FromDomain::Invalid;
        };
        let parsed = HeaderForm::Addresses.parse(value);
        let Some(list) = parsed.value().as_address() else {
            return FromDomain::Invalid;
        };
        let mut addresses = list.iter();
        let mailbox = match (addresses.next(), addresses.next()) {
            (Some(Address::Mailbox(mailbox)), None) => mailbox,
            (Some(_), Some(_)) => return FromDomain::MultipleAddresses,
            (Some(Address::Group(group)), None) if group.len() > 1 => {
                return FromDomain::MultipleAddresses;
            }
            _ => return FromDomain::Invalid,
        };
        let Some((local, domain)) = mailbox
            .address()
            .and_then(|address| address.split_once('@'))
        else {
            return FromDomain::Invalid;
        };
        if domain.starts_with('[') {
            return FromDomain::DomainLiteral;
        }
        let valid = !local.is_empty()
            && local.bytes().chain(domain.bytes()).all(|ch| {
                !ch.is_ascii_whitespace()
                    && !ch.is_ascii_control()
                    && !b"@<>()[],;:\"".contains(&ch)
            });
        let domain = to_a_label(domain);
        if valid && is_domain(domain.as_bytes()) {
            FromDomain::Domain(domain.into_owned())
        } else {
            FromDomain::Invalid
        }
    }

    pub(crate) fn authenticate(
        &self,
        i: u32,
        signing_domain: &str,
    ) -> Result<FromMatch<'_>, Dkim2Error> {
        match self {
            FromDomain::Domain(domain) if relaxed_domain_match(domain, signing_domain) => {
                Ok(FromMatch::Authentic)
            }
            FromDomain::Domain(domain) if relaxed_domain_match(signing_domain, domain) => {
                Ok(FromMatch::Subdomain(domain))
            }
            FromDomain::Domain(_) | FromDomain::Invalid => Err(Dkim2Error::FromNotAuthentic(i)),
            FromDomain::MultipleAddresses => Err(Dkim2Error::FromMultipleAddresses(i)),
            FromDomain::DomainLiteral => Err(Dkim2Error::FromDomainLiteral(i)),
        }
    }

    fn check(
        &self,
        signature: &Signature,
        policies: &mut Vec<PolicyCheck>,
    ) -> Result<(), Dkim2Error> {
        if let FromMatch::Subdomain(domain) = self.authenticate(signature.i, &signature.d)?
            && !policies.iter().any(|check| check.domain.as_ref() == domain)
        {
            policies.push(PolicyCheck {
                i: signature.i,
                domain: domain.into(),
            });
        }
        Ok(())
    }
}

fn local_and_domain(address: &str) -> (&str, &str) {
    let address = address.strip_prefix('<').unwrap_or(address);
    let address = address.strip_suffix('>').unwrap_or(address);
    match address.rsplit_once('@') {
        Some((local, domain)) => (local, domain),
        None => (address, ""),
    }
}

fn is_null_path(path: &str) -> bool {
    matches!(path.trim(), "<>" | "")
}

fn domain_eq(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        a.eq_ignore_ascii_case(b)
    } else {
        to_a_label(a) == to_a_label(b)
    }
}

/// Exact reverse-path or forward-path comparison for the envelope check.
fn address_matches(envelope: &str, signed: &str) -> bool {
    let (el, ed) = local_and_domain(envelope);
    let (sl, sd) = local_and_domain(signed);
    el == sl && domain_eq(ed, sd)
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

pub(crate) fn relaxed_domain_match(parameter1: &str, parameter2: &str) -> bool {
    if parameter1.starts_with('[') || parameter2.starts_with('[') {
        return false;
    }
    let (parameter1, parameter2) = if parameter1.is_ascii() && parameter2.is_ascii() {
        (Cow::Borrowed(parameter1), Cow::Borrowed(parameter2))
    } else {
        (to_a_label(parameter1), to_a_label(parameter2))
    };
    let mut current = parameter1.as_ref();
    loop {
        if current.eq_ignore_ascii_case(&parameter2) {
            return true;
        }
        match current.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => current = rest,
            _ => return false,
        }
    }
}

/// Writes the canonicalized `DKIM2-Signature` value with the base64
/// signature values of the `s=` tag removed (§12.8).
fn strip_and_canonicalize_signature(signature: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(b"dkim2-signature:");
    for (pos, spec) in signature.split(|&ch| ch == b';').enumerate() {
        if pos > 0 {
            out.push(b';');
        }
        let is_signature_tag = spec
            .split(|&ch| ch == b'=')
            .next()
            .is_some_and(|name| name.trim_ascii() == b"s")
            && spec.contains(&b'=');
        if !is_signature_tag {
            out.extend(spec.iter().filter(|ch| !ch.is_ascii_whitespace()));
            continue;
        }
        let mut colons = 0;
        for &ch in spec.iter().filter(|ch| !ch.is_ascii_whitespace()) {
            if matches!(ch, b',' | b'|') {
                colons = 0;
                out.push(ch);
            } else if colons < 2 {
                out.push(ch);
                colons += usize::from(ch == b':');
            }
        }
    }
    out.extend_from_slice(b"\r\n");
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
                "s=a:b:U0lH|c:d:WkZa, e:f:QUJD;",
                "dkim2-signature:s=a:b:|c:d:,e:f:;\r\n",
            ),
            (
                "s=sel:alg:U0lH; f=feedback;",
                "dkim2-signature:s=sel:alg:;f=feedback;\r\n",
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
            ("n= s=a:b:c;", "dkim2-signature:n=s=a:b:c;\r\n"),
            (
                "x=1 s=a:b:c; s=a:b:c;",
                "dkim2-signature:x=1s=a:b:c;s=a:b:;\r\n",
            ),
            ("\r\n\ts\r\n =a:b:c", "dkim2-signature:s=a:b:\r\n"),
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
