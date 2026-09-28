/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Parsed view of an RFC 5322 message for authentication.
//!
//! [`AuthenticatedMessage`] splits a raw message into headers and body,
//! parses the authentication headers it contains (`DKIM-Signature` from
//! RFC 6376, `ARC-Seal`, `ARC-Message-Signature` and
//! `ARC-Authentication-Results` from RFC 8617, `DKIM2-Signature` and
//! `Message-Instance` from draft-ietf-dkim-dkim2-spec) and precomputes the
//! body hashes the DKIM and ARC verifiers need. The verifiers on
//! [`MessageAuthenticator`](crate::MessageAuthenticator) take it as input.

#[cfg(feature = "arc")]
use crate::arc;
use crate::{
    Error,
    crypto::HashAlgorithm,
    dkim::{self, Canonicalization},
    dkim2,
    headers::{AuthenticatedHeader, Header, HeaderParser},
};
use mail_parser::{AddressList, HeaderForm, HeaderName, Message};

const EXPECTED_HEADER_COUNT: usize = 32;

/// An RFC 5322 message prepared for DKIM, DKIM2, ARC and DMARC verification.
///
/// The message borrows the raw bytes it was parsed from. Parsing records the
/// position of every header, the `From` addresses (used for DMARC, RFC 9989),
/// the number of `Received` headers and the presence of `Date` and
/// `Message-ID`. Authentication headers that fail to parse do not abort
/// parsing: they are recorded in [`errors`](Self::errors) and flagged by
/// [`has_dkim_errors`](Self::has_dkim_errors),
/// [`has_dkim2_errors`](Self::has_dkim2_errors) and `has_arc_errors`.
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::AuthenticatedMessage;
///
/// let raw = b"From: jdoe@example.org\r\nSubject: Hi\r\n\r\nHello\r\n";
/// let message = AuthenticatedMessage::parse(raw).unwrap();
/// assert_eq!(message.first_from_address(), "jdoe@example.org");
/// assert_eq!(message.raw_body(), b"Hello\r\n");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<String>,
    pub(crate) raw_message: &'x [u8],
    pub(crate) body_offset: u32,
    pub(crate) body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub(crate) dkim_headers: Vec<Header<'x, dkim::Signature>>,
    pub(crate) dkim2_signatures: Vec<Header<'x, dkim2::Signature>>,
    pub(crate) dkim2_instances: Vec<Header<'x, dkim2::MessageInstance>>,
    #[cfg(feature = "arc")]
    pub(crate) ams_headers: Vec<Header<'x, arc::Signature>>,
    #[cfg(feature = "arc")]
    pub(crate) as_headers: Vec<Header<'x, arc::Seal>>,
    #[cfg(feature = "arc")]
    pub(crate) aar_headers: Vec<Header<'x, arc::ArcAuthResults>>,
    pub(crate) received_headers_count: usize,
    pub(crate) date_header_present: bool,
    pub(crate) message_id_header_present: bool,
    pub(crate) errors: Vec<Header<'x, Error>>,
    pub(crate) has_dkim_errors: bool,
    #[cfg(feature = "arc")]
    pub(crate) has_arc_errors: bool,
    pub(crate) has_dkim2_errors: bool,
}

impl<'x> AsRef<AuthenticatedMessage<'x>> for AuthenticatedMessage<'x> {
    fn as_ref(&self) -> &AuthenticatedMessage<'x> {
        self
    }
}

impl<'x> TryFrom<&'x [u8]> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x [u8]) -> Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::Parse)
    }
}

impl<'x> TryFrom<&'x Vec<u8>> for AuthenticatedMessage<'x> {
    type Error = Error;

    fn try_from(value: &'x Vec<u8>) -> Result<Self, Self::Error> {
        AuthenticatedMessage::parse(value).ok_or(Error::Parse)
    }
}

impl<'x> AuthenticatedMessage<'x> {
    /// Parses a raw RFC 5322 message in strict mode.
    ///
    /// Equivalent to [`parse_with_opts(raw_message, None, true)`](Self::parse_with_opts).
    /// Returns `None` when no header could be parsed.
    pub fn parse(raw_message: &'x [u8]) -> Option<Self> {
        Self::parse_with_opts(raw_message, None, true)
    }

    /// Builds an `AuthenticatedMessage` from a message already parsed by
    /// [`mail_parser`], reusing its header offsets instead of parsing again.
    ///
    /// `raw_message` must be the exact bytes `parsed` was parsed from. Only the
    /// headers of the root part are read. `strict` has the same meaning as in
    /// [`parse_with_opts`](Self::parse_with_opts).
    pub fn from_parsed<'y>(parsed: &'y Message<'x>, raw_message: &'x [u8], strict: bool) -> Self {
        let root = parsed.root_part();
        let headers = root.headers();
        let mut message = AuthenticatedMessage {
            raw_message,
            body_offset: root.offset_body(),
            headers: Vec::with_capacity(headers.len()),
            ..Default::default()
        };
        let raw_range = |from: u32, to: u32| {
            raw_message
                .get(from as usize..to as usize)
                .unwrap_or_default()
        };

        for header in headers {
            let name = raw_range(
                header.offset_field(),
                header.offset_start().saturating_sub(1),
            );
            let value = raw_range(header.offset_start(), header.offset_end());

            match header.name() {
                HeaderName::From => {
                    message.parse_from(header.value().as_address());
                }
                HeaderName::Date => {
                    message.date_header_present = true;
                }
                HeaderName::Received => {
                    message.received_headers_count += 1;
                }
                HeaderName::MessageId => {
                    message.message_id_header_present = true;
                }
                HeaderName::DkimSignature => {
                    message.parse_dkim(name, value, strict);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcAuthenticationResults => {
                    message.parse_aar(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcSeal => {
                    message.parse_as(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcMessageSignature => {
                    message.parse_ams(name, value, strict);
                }
                HeaderName::Dkim2Signature => {
                    message.parse_dkim2_signature(name, value);
                }
                HeaderName::MessageInstance => {
                    message.parse_dkim2_instance(name, value);
                }
                _ => (),
            }

            message.headers.push((name, value))
        }

        message.finalize()
    }

    /// Parses a raw RFC 5322 message.
    ///
    /// `prepend_headers`, when set, holds header lines that are parsed as if
    /// they appeared before the headers of `raw_message` (for example,
    /// headers added by the receiving MTA but not yet written to the message).
    ///
    /// When `strict` is `true`, `DKIM-Signature` and `ARC-Message-Signature`
    /// headers that carry a body length tag (`l=`) are rejected and recorded
    /// as errors ([`DkimError::BodyLengthTag`](crate::dkim::DkimError::BodyLengthTag)
    /// for DKIM, `ArcError::BodyLengthTag` for ARC),
    /// because a length limit lets an attacker append content to a signed
    /// body (RFC 6376 Section 8.2). When `false`, such signatures are kept.
    ///
    /// Returns `None` when no header could be parsed.
    pub fn parse_with_opts(
        raw_message: &'x [u8],
        prepend_headers: Option<&'x [u8]>,
        strict: bool,
    ) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            raw_message,
            headers: Vec::with_capacity(EXPECTED_HEADER_COUNT),
            ..Default::default()
        };

        if let Some(headers) = prepend_headers {
            message.parse_headers(headers, strict);
        }

        let body_offset = message.parse_headers(raw_message, strict);

        if !message.headers.is_empty() {
            if let Some(offset) = body_offset {
                message.body_offset = offset as u32;
            } else {
                message.body_offset = raw_message.len() as u32;
            }
            Some(message.finalize())
        } else {
            None
        }
    }

    fn parse_headers(&mut self, headers: &'x [u8], strict: bool) -> Option<usize> {
        let mut headers = HeaderParser::new(headers);

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    self.parse_dkim(name, value, strict);
                    name
                }
                AuthenticatedHeader::D2s(name) => {
                    self.parse_dkim2_signature(name, value);
                    name
                }
                AuthenticatedHeader::D2i(name) => {
                    self.parse_dkim2_instance(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Aar(name) => {
                    self.parse_aar(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Ams(name) => {
                    self.parse_ams(name, value, strict);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::As(name) => {
                    self.parse_as(name, value);
                    name
                }
                AuthenticatedHeader::From(name) => {
                    self.parse_from(HeaderForm::Addresses.parse(value).value().as_address());
                    name
                }
                AuthenticatedHeader::Other(name) => name,
            };

            self.headers.push((name, value));
        }

        self.received_headers_count += headers.num_received;
        self.message_id_header_present |= headers.has_message_id;
        self.date_header_present |= headers.has_date;

        headers.body_offset()
    }

    fn parse_dkim(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        match dkim::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                self.dkim_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_dkim_error(name, value, Error::Dkim(dkim::DkimError::BodyLengthTag));
            }
            Err(err) => self.push_dkim_error(name, value, err),
        }
    }

    fn parse_dkim2_signature(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::Signature::parse(value) {
            Ok(signature) => self
                .dkim2_signatures
                .push(Header::new(name, value, signature)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    fn parse_dkim2_instance(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::MessageInstance::parse(value) {
            Ok(instance) => self
                .dkim2_instances
                .push(Header::new(name, value, instance)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_aar(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::ArcAuthResults::parse(value) {
            Ok(results) => self.aar_headers.push(Header::new(name, value, results)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_ams(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        match arc::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                self.ams_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_arc_error(name, value, Error::Arc(arc::ArcError::BodyLengthTag));
            }
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_as(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::Seal::parse(value) {
            Ok(seal) => self.as_headers.push(Header::new(name, value, seal)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    fn push_dkim_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    fn push_dkim2_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim2_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    #[cfg(feature = "arc")]
    fn push_arc_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_arc_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    fn parse_from(&mut self, addresses: Option<AddressList<'_>>) {
        if let Some(addresses) = addresses {
            self.from.extend(
                addresses
                    .mailboxes()
                    .filter_map(|mailbox| mailbox.address().map(str::to_lowercase)),
            );
        }
    }

    fn finalize(mut self) -> Self {
        let body = self
            .raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default();

        for (cb, ha, l, bh) in &mut self.body_hashes {
            *bh = ha.hash(cb.canonical_body(body, *l)).as_ref().to_vec();
        }

        #[cfg(feature = "arc")]
        if !self.as_headers.is_empty() && !self.has_arc_errors {
            self.as_headers.sort_unstable_by_key(|h| h.header.i);
            self.ams_headers.sort_unstable_by_key(|h| h.header.i);
            self.aar_headers.sort_unstable_by_key(|h| h.header.i);
        }

        if !self.has_dkim2_errors {
            self.dkim2_signatures.sort_unstable_by_key(|h| h.header.i);
            self.dkim2_instances.sort_unstable_by_key(|h| h.header.m);
        }

        self
    }

    /// Returns the number of `Received` headers in the message.
    pub fn received_headers_count(&self) -> usize {
        self.received_headers_count
    }

    /// Returns `true` if the message has a `Message-ID` header.
    pub fn has_message_id_header(&self) -> bool {
        self.message_id_header_present
    }

    /// Returns `true` if the message has a `Date` header.
    pub fn has_date_header(&self) -> bool {
        self.date_header_present
    }

    /// Returns the raw message bytes, headers and body.
    pub fn raw_message(&self) -> &[u8] {
        self.raw_message
    }

    /// Returns the raw header section of the message, including the blank
    /// line that separates it from the body when one is present. Prepended
    /// headers are not included.
    pub fn raw_headers(&self) -> &[u8] {
        self.raw_message
            .get(..self.body_offset as usize)
            .unwrap_or_default()
    }

    /// Returns every header as a `(name, value)` pair of raw bytes, in message
    /// order. Prepended headers come first. The name excludes the colon; the
    /// value keeps its folding and the trailing line ending.
    pub fn headers(&self) -> &[(&'x [u8], &'x [u8])] {
        &self.headers
    }

    /// Returns the raw message body. Empty when the message has no body.
    pub fn raw_body(&self) -> &[u8] {
        self.raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default()
    }

    /// Returns the byte offset of the body within
    /// [`raw_message`](Self::raw_message).
    pub fn body_offset(&self) -> usize {
        self.body_offset as usize
    }

    /// Returns the lowercased addresses found in the `From` header, including
    /// the members of address groups.
    pub fn from_addresses(&self) -> &[String] {
        &self.from
    }

    /// Returns the first `From` address, or an empty string if there is none.
    /// This is the author address used for DMARC (RFC 9989).
    pub fn first_from_address(&self) -> &str {
        self.from.first().map_or("", |f| f.as_str())
    }

    /// Returns the `DKIM-Signature` headers (RFC 6376) that parsed
    /// successfully, in message order.
    pub fn dkim_signatures(&self) -> &[Header<'x, dkim::Signature>] {
        &self.dkim_headers
    }

    /// Returns the `DKIM2-Signature` headers that parsed successfully. They
    /// are sorted by signature sequence number (`i=` tag) unless a DKIM2 header failed
    /// to parse.
    pub fn dkim2_signatures(&self) -> &[Header<'x, dkim2::Signature>] {
        &self.dkim2_signatures
    }

    /// Returns the `Message-Instance` headers that parsed successfully. They
    /// are sorted by revision number (`m=` tag) unless a DKIM2 header failed
    /// to parse.
    pub fn dkim2_instances(&self) -> &[Header<'x, dkim2::MessageInstance>] {
        &self.dkim2_instances
    }

    /// Returns the `ARC-Message-Signature` headers that parsed successfully
    /// (feature `arc`). They are sorted by instance number (`i=` tag) unless
    /// an ARC header failed to parse.
    #[cfg(feature = "arc")]
    pub fn arc_message_signatures(&self) -> &[Header<'x, arc::Signature>] {
        &self.ams_headers
    }

    /// Returns the `ARC-Seal` headers that parsed successfully (feature
    /// `arc`), sorted like [`arc_message_signatures`](Self::arc_message_signatures).
    #[cfg(feature = "arc")]
    pub fn arc_seals(&self) -> &[Header<'x, arc::Seal>] {
        &self.as_headers
    }

    /// Returns the `ARC-Authentication-Results` headers that parsed
    /// successfully (feature `arc`), sorted like
    /// [`arc_message_signatures`](Self::arc_message_signatures).
    #[cfg(feature = "arc")]
    pub fn arc_authentication_results(&self) -> &[Header<'x, arc::ArcAuthResults>] {
        &self.aar_headers
    }

    /// Returns the authentication headers that could not be parsed or were
    /// rejected, each paired with the reason.
    pub fn errors(&self) -> &[Header<'x, Error>] {
        &self.errors
    }

    /// Returns `true` if a `DKIM-Signature` header failed to parse or was
    /// rejected (including by
    /// [`retain_dkim_signatures`](Self::retain_dkim_signatures)).
    pub fn has_dkim_errors(&self) -> bool {
        self.has_dkim_errors
    }

    /// Returns `true` if a `DKIM2-Signature` or `Message-Instance` header
    /// failed to parse.
    pub fn has_dkim2_errors(&self) -> bool {
        self.has_dkim2_errors
    }

    /// Returns `true` if an ARC header failed to parse or was rejected. The
    /// ARC verifier reports a broken chain in that case.
    #[cfg(feature = "arc")]
    pub fn has_arc_errors(&self) -> bool {
        self.has_arc_errors
    }

    /// Keeps only the DKIM signatures accepted by `accept`.
    ///
    /// `accept` is called once for every parsed `DKIM-Signature`. Signatures
    /// for which it returns `Err` are removed from
    /// [`dkim_signatures`](Self::dkim_signatures); the error is added to
    /// [`errors`](Self::errors) as [`Error::Dkim`] and
    /// [`has_dkim_errors`](Self::has_dkim_errors) becomes `true`, so
    /// `verify_dkim` reports each rejected signature as `neutral` with that
    /// error. Use it to apply a local policy, such as rejecting `rsa-sha1`
    /// signatures, before verification.
    pub fn retain_dkim_signatures(
        &mut self,
        mut accept: impl FnMut(&dkim::Signature) -> Result<(), dkim::DkimError>,
    ) {
        let errors = &mut self.errors;
        let mut rejected = false;
        self.dkim_headers
            .retain(|header| match accept(&header.header) {
                Ok(()) => true,
                Err(err) => {
                    errors.push(Header::new(header.name, header.value, Error::Dkim(err)));
                    rejected = true;
                    false
                }
            });
        self.has_dkim_errors |= rejected;
    }
}
