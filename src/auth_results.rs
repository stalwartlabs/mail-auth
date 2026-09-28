/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Builders for the `Authentication-Results` and `Received-SPF` headers.
//!
//! - [`AuthenticationResults`] writes the `Authentication-Results` header
//!   defined in RFC 8601, with one method entry per `dkim`, `dkim-atps`
//!   (RFC 6541), `dkim2`, `spf`, `arc` (RFC 8617), `dmarc` (RFC 9989) and
//!   `iprev` (RFC 8601 Section 3) result.
//! - [`ReceivedSpf`] writes the `Received-SPF` header defined in RFC 7208
//!   Section 9.1.
//!
//! Both implement [`HeaderWriter`], so the finished header can be written with
//! [`HeaderWriter::write_header`] or rendered with [`HeaderWriter::to_header`].
//! Property values taken from the message or the SMTP session are sanitized
//! or quoted as required by the RFC 8601 `pvalue` grammar.

#[cfg(feature = "arc")]
use crate::{ArcOutput, arc::ArcError};
use crate::{
    Dkim2Result, DkimOutput, DkimResult, DmarcOutput, DmarcResult, DnsError, Error, IprevOutput,
    IprevResult, SpfOutput, SpfResult,
    crypto::CryptoError,
    dkim::DkimError,
    dkim2::Dkim2Output,
    dmarc::Policy,
    headers::{HeaderWriter, IntegerBuffer, Writer},
    spf::{SpfIdentity, verify::SpfParameters},
};
use encodify::base64;
use std::{
    borrow::Cow,
    fmt::{Display, Write},
    net::{IpAddr, Ipv4Addr},
};

/// An `Authentication-Results` header (RFC 8601) under construction.
///
/// Create one with [`new`](Self::new), naming the host that performed the
/// checks (the `authserv-id`), then add the output of each verifier. Every
/// result has a consuming `with_*` method for chaining and a `set_*` method
/// that takes `&mut self`. Results are written in the order they are added.
/// A header with no results is written as `Authentication-Results:
/// <authserv-id>; none`.
///
/// The [`Display`] implementation renders the header value without the field
/// name and without the trailing CRLF.
///
/// # Example
///
/// ```rust,no_run
/// use mail_auth::{
///     AuthenticatedMessage, AuthenticationResults, MessageAuthenticator,
///     headers::HeaderWriter, spf::verify::SpfParameters,
/// };
///
/// # async fn run(raw_message: &[u8]) {
/// let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();
/// let message = AuthenticatedMessage::parse(raw_message).unwrap();
/// let dkim = authenticator.verify_dkim(&message).await;
/// let spf_params = || {
///     SpfParameters::mail_from(
///         "192.0.2.10".parse().unwrap(),
///         "mail.example.org",
///         "mx.example.com",
///         "sender@example.org",
///     )
/// };
/// let spf = authenticator.verify_spf(spf_params()).await;
///
/// let header = AuthenticationResults::new("mx.example.com")
///     .with_dkim_results(&dkim, message.first_from_address())
///     .with_spf_result(&spf, &spf_params())
///     .to_header();
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResults<'x> {
    pub(crate) hostname: &'x str,
    pub(crate) auth_results: String,
}

/// A `Received-SPF` header (RFC 7208 Section 9.1).
///
/// Built from an SPF result with [`ReceivedSpf::new`] and written with
/// [`HeaderWriter`]. The header holds the result, a comment explaining it,
/// and the `receiver`, `client-ip`, `envelope-from` and `helo` keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSpf {
    pub(crate) received_spf: String,
}

impl<'x> AuthenticationResults<'x> {
    /// Creates an empty header. `hostname` is the `authserv-id` (RFC 8601
    /// Section 2.5): the name of the host that performed the checks.
    pub fn new(hostname: &'x str) -> Self {
        AuthenticationResults {
            hostname,
            auth_results: String::with_capacity(256),
        }
    }

    /// Adds one `dkim` entry per DKIM output. See
    /// [`set_dkim_result`](Self::set_dkim_result).
    pub fn with_dkim_results(mut self, dkim: &[DkimOutput], header_from: &str) -> Self {
        self.set_dkim_results(dkim, header_from);
        self
    }

    /// Adds one `dkim` entry per DKIM output. See
    /// [`set_dkim_result`](Self::set_dkim_result).
    pub fn set_dkim_results(&mut self, dkim: &[DkimOutput], header_from: &str) {
        for dkim in dkim {
            self.set_dkim_result(dkim, header_from);
        }
    }

    /// Adds a `dkim` or `dkim-atps` entry. See
    /// [`set_dkim_result`](Self::set_dkim_result).
    pub fn with_dkim_result(mut self, dkim: &DkimOutput, header_from: &str) -> Self {
        self.set_dkim_result(dkim, header_from);
        self
    }

    /// Adds a `dkim` entry (RFC 8601 Section 2.7.1) for one DKIM output.
    ///
    /// The entry reports `header.i` (or `header.d` when the signature has no
    /// `i=` tag), `header.s` and `header.b`, the first eight Base64
    /// characters of the signature (RFC 6008). An ATPS result (RFC 6541) is
    /// written as a `dkim-atps` entry and also reports `header.from`, taken
    /// from `header_from`, the RFC 5322 `From` address. `header_from` is
    /// ignored for other results.
    pub fn set_dkim_result(&mut self, dkim: &DkimOutput, header_from: &str) {
        if !dkim.is_atps {
            self.auth_results.push_str(";\r\n\tdkim=");
        } else {
            self.auth_results.push_str(";\r\n\tdkim-atps=");
        }
        dkim.result.as_auth_result(&mut self.auth_results);
        if let Some(signature) = &dkim.signature {
            if !signature.i.is_empty() {
                self.auth_results.push_str(" header.i=");
                push_quoted_pvalue(&mut self.auth_results, &signature.i);
            } else {
                self.auth_results.push_str(" header.d=");
                push_pvalue(&mut self.auth_results, &signature.d);
            }
            self.auth_results.push_str(" header.s=");
            push_pvalue(&mut self.auth_results, &signature.s);
            if let Some(prefix) = signature.b.get(..6) {
                self.auth_results.push_str(" header.b=");
                base64::STANDARD.encode_append(prefix, &mut self.auth_results);
            }
        }

        if dkim.is_atps {
            self.auth_results.push_str(" header.from=");
            push_quoted_pvalue(&mut self.auth_results, header_from);
        }
    }

    /// Adds a `dkim2` entry. See [`set_dkim2_result`](Self::set_dkim2_result).
    pub fn with_dkim2_result(mut self, dkim2: &Dkim2Output) -> Self {
        self.set_dkim2_result(dkim2);
        self
    }

    /// Adds a `dkim2` entry for the result of a DKIM2 chain verification.
    ///
    /// The entry reports `header.d` (signing domain) and `header.i`
    /// (signature instance number) of the first link in the chain when the
    /// chain passed, or of the first link that did not pass otherwise.
    pub fn set_dkim2_result(&mut self, dkim2: &Dkim2Output) {
        self.auth_results.push_str(";\r\n\tdkim2=");
        dkim2.result().as_auth_result(&mut self.auth_results);

        let link = if matches!(dkim2.result(), Dkim2Result::Pass) {
            dkim2.chain().first()
        } else {
            dkim2
                .chain()
                .iter()
                .find(|link| !matches!(link.result, Dkim2Result::Pass))
                .or_else(|| dkim2.chain().first())
        };
        if let Some(link) = link {
            self.auth_results.push_str(" header.d=");
            push_pvalue(&mut self.auth_results, &link.signature.d);
            self.auth_results.push_str(" header.i=");
            push_integer(&mut self.auth_results, link.signature.i as u64);
        }
    }

    /// Adds an `spf` entry. See [`set_spf_result`](Self::set_spf_result).
    pub fn with_spf_result(mut self, spf: &SpfOutput, params: &SpfParameters<'_>) -> Self {
        self.set_spf_result(spf, params);
        self
    }

    /// Adds an `spf` entry (RFC 8601 Section 2.7.2) for an SPF output.
    ///
    /// `params` supplies the client IP, the HELO domain, the host domain and
    /// the MAIL FROM address. Pass the MAIL FROM address as received, empty
    /// for the null reverse-path (`check_host` substitutes
    /// `postmaster@<domain>` on its own); a substituted address would be
    /// reported instead of `<>`. The reported
    /// identity follows the identity that `check_host` evaluated: `smtp.helo`
    /// when the HELO identity produced the result, otherwise `smtp.mailfrom`
    /// (written as `<>` for the null reverse-path). A comment explaining the
    /// result, including the client IP address, precedes the property.
    pub fn set_spf_result(&mut self, spf: &SpfOutput, params: &SpfParameters<'_>) {
        let ip_addr = params.ip();
        let helo_domain = sanitize_pvalue(params.helo_domain());
        self.auth_results.push_str(";\r\n\tspf=");
        match spf_mail_from(spf, params) {
            None => {
                spf.result.as_spf_result(
                    &mut self.auth_results,
                    self.hostname,
                    [POSTMASTER_AT, helo_domain.as_ref()],
                    ip_addr,
                );
                self.auth_results.push_str(" smtp.helo=");
                self.auth_results.push_str(helo_domain.as_ref());
            }
            Some(from) => {
                let sanitized_from = sanitize_pvalue(from);
                let mail_from = if !from.is_empty() {
                    [sanitized_from.as_ref(), ""]
                } else {
                    [POSTMASTER_AT, helo_domain.as_ref()]
                };
                spf.result
                    .as_spf_result(&mut self.auth_results, self.hostname, mail_from, ip_addr);
                self.auth_results.push_str(" smtp.mailfrom=");
                if !from.is_empty() {
                    push_quoted_pvalue(&mut self.auth_results, from);
                } else {
                    self.auth_results.push_str("<>");
                }
            }
        }
    }

    /// Adds an `arc` entry. See [`set_arc_result`](Self::set_arc_result).
    #[cfg(feature = "arc")]
    pub fn with_arc_result(mut self, arc: &ArcOutput, remote_ip: IpAddr) -> Self {
        self.set_arc_result(arc, remote_ip);
        self
    }

    /// Adds an `arc` entry (RFC 8617) for an ARC chain
    /// validation result. `remote_ip` is the SMTP client address, reported as
    /// `smtp.remote-ip`.
    #[cfg(feature = "arc")]
    pub fn set_arc_result(&mut self, arc: &ArcOutput, remote_ip: IpAddr) {
        self.auth_results.push_str(";\r\n\tarc=");
        arc.result.as_auth_result(&mut self.auth_results);
        self.auth_results.push_str(" smtp.remote-ip=");
        push_ip_as_pvalue(&mut self.auth_results, remote_ip);
    }

    /// Adds a `dmarc` entry. See [`set_dmarc_result`](Self::set_dmarc_result).
    pub fn with_dmarc_result(mut self, dmarc: &DmarcOutput) -> Self {
        self.set_dmarc_result(dmarc);
        self
    }

    /// Adds a `dmarc` entry for a DMARC output (RFC 9989).
    ///
    /// The result is the best of the DKIM and SPF alignment results. The
    /// entry reports `header.from` (the RFC 5322 `From` domain) and
    /// `policy.dmarc`, the policy published by that domain (`none`,
    /// `quarantine` or `reject`).
    pub fn set_dmarc_result(&mut self, dmarc: &DmarcOutput) {
        self.auth_results.push_str(";\r\n\tdmarc=");
        match dmarc.mechanism_result() {
            Some(result) => result.as_auth_result(&mut self.auth_results),
            None => dmarc.result().as_auth_result(&mut self.auth_results),
        }
        self.auth_results.push_str(" header.from=");
        push_pvalue(&mut self.auth_results, &dmarc.domain);
        self.auth_results.push_str(match dmarc.policy {
            Policy::Quarantine => " policy.dmarc=quarantine",
            Policy::Reject => " policy.dmarc=reject",
            Policy::None | Policy::Unspecified => " policy.dmarc=none",
        });
    }

    /// Adds an `iprev` entry. See [`set_iprev_result`](Self::set_iprev_result).
    pub fn with_iprev_result(mut self, iprev: &IprevOutput, remote_ip: IpAddr) -> Self {
        self.set_iprev_result(iprev, remote_ip);
        self
    }

    /// Adds an `iprev` entry (RFC 8601 Section 3) for an `iprev` output.
    /// `remote_ip` is the SMTP client address checked, reported as
    /// `policy.iprev`.
    pub fn set_iprev_result(&mut self, iprev: &IprevOutput, remote_ip: IpAddr) {
        self.auth_results.push_str(";\r\n\tiprev=");
        iprev.result.as_auth_result(&mut self.auth_results);
        self.auth_results.push_str(" policy.iprev=");
        push_ip_as_pvalue(&mut self.auth_results, remote_ip);
    }
}

impl Display for AuthenticationResults<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.hostname)?;
        f.write_str(&self.auth_results)
    }
}

impl HeaderWriter for AuthenticationResults<'_> {
    fn write_header(&self, writer: &mut impl Writer) {
        writer.write(b"Authentication-Results: ");
        writer.write(self.hostname.as_bytes());
        if !self.auth_results.is_empty() {
            writer.write(self.auth_results.as_bytes());
        } else {
            writer.write(b"; none");
        }
        writer.write(b"\r\n");
    }
}

impl HeaderWriter for ReceivedSpf {
    fn write_header(&self, writer: &mut impl Writer) {
        writer.write(b"Received-SPF: ");
        writer.write(self.received_spf.as_bytes());
        writer.write(b"\r\n");
    }
}

fn spf_mail_from<'x>(spf: &SpfOutput, params: &SpfParameters<'x>) -> Option<&'x str> {
    match spf.identity {
        Some(SpfIdentity::Helo) => None,
        Some(SpfIdentity::MailFrom) | None => params.mail_from_address(),
    }
}

impl ReceivedSpf {
    /// Builds a `Received-SPF` header (RFC 7208 Section 9.1) for an SPF
    /// output.
    ///
    /// `params` supplies the values reported, as for
    /// [`AuthenticationResults::set_spf_result`]: pass the MAIL FROM address
    /// as received, empty for the null reverse-path. `receiver` is
    /// the host domain, `client-ip` the SMTP client address, `helo` the
    /// HELO/EHLO domain, and `envelope-from` the MAIL FROM address, or
    /// `postmaster@<helo domain>` when the reverse-path is null or no MAIL FROM
    /// was given. The comment names the identity that was evaluated, as
    /// [`AuthenticationResults::set_spf_result`] does.
    pub fn new(spf: &SpfOutput, params: &SpfParameters<'_>) -> Self {
        let ip_addr = params.ip();
        let helo = params.helo_domain();
        let mail_from = params.mail_from_address().unwrap_or_default();
        let hostname = params.host_domain();
        let mut received_spf = String::with_capacity(256);
        let helo = sanitize_pvalue(helo);
        let checked = spf_mail_from(spf, params).unwrap_or_default();
        let sanitized_checked = sanitize_pvalue(checked);
        let envelope_from = if !mail_from.is_empty() {
            [mail_from, ""]
        } else {
            [POSTMASTER_AT, helo.as_ref()]
        };
        let pieces = if !checked.is_empty() {
            [sanitized_checked.as_ref(), ""]
        } else {
            [POSTMASTER_AT, helo.as_ref()]
        };

        spf.result
            .as_spf_result(&mut received_spf, hostname, pieces, ip_addr);

        received_spf.push_str("\r\n\treceiver=");
        received_spf.push_str(hostname);
        received_spf.push_str("; client-ip=");
        push_ip(&mut received_spf, ip_addr);
        received_spf.push_str("; envelope-from=\"");
        for piece in envelope_from {
            push_qcontent(&mut received_spf, piece);
        }
        received_spf.push_str("\"; helo=");
        received_spf.push_str(helo.as_ref());
        received_spf.push(';');

        ReceivedSpf { received_spf }
    }
}

const POSTMASTER_AT: &str = "postmaster@";
const MAX_IP_TEXT_LEN: usize = 46;

impl SpfResult {
    fn as_spf_result(
        &self,
        header: &mut String,
        hostname: &str,
        mail_from: [&str; 2],
        ip_addr: IpAddr,
    ) {
        let (result, reason, designation, close) = match self {
            SpfResult::Pass => (
                "pass (",
                ": domain of ",
                Some(" designates "),
                " as permitted sender)",
            ),
            SpfResult::Fail => (
                "fail (",
                ": domain of ",
                Some(" does not designate "),
                " as permitted sender)",
            ),
            SpfResult::SoftFail => (
                "softfail (",
                ": domain of ",
                Some(" reports soft fail for "),
                ")",
            ),
            SpfResult::Neutral => (
                "neutral (",
                ": domain of ",
                Some(" reports neutral for "),
                ")",
            ),
            SpfResult::TempError => (
                "temperror (",
                ": temporary dns error validating ",
                None,
                ")",
            ),
            SpfResult::PermError => (
                "permerror (",
                ": unable to verify SPF record for ",
                None,
                ")",
            ),
            SpfResult::None => ("none (", ": no SPF records found for ", None, ")"),
        };

        let mail_from_len = mail_from[0].len() + mail_from[1].len();
        header.reserve(
            result.len()
                + hostname.len()
                + reason.len()
                + mail_from_len
                + close.len()
                + designation.map_or(0, |text| text.len() + MAX_IP_TEXT_LEN),
        );

        header.push_str(result);
        header.push_str(hostname);
        header.push_str(reason);
        for piece in mail_from {
            header.push_str(piece);
        }
        if let Some(designation) = designation {
            header.push_str(designation);
            push_ip(header, ip_addr);
        }
        header.push_str(close);
    }
}

/// Formats a verifier result as an RFC 8601 result keyword.
///
/// Implemented for the result enums of each verifier and for [`Error`]. Used
/// by [`AuthenticationResults`] to write method results.
pub(crate) trait AsAuthResult {
    /// Appends the result keyword (such as `pass` or `temperror`) to `header`,
    /// followed by a parenthesized comment giving the reason when the result
    /// carries an error. For [`Error`], appends only the comment.
    fn as_auth_result(&self, header: &mut String);
}

impl AsAuthResult for DmarcResult {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            DmarcResult::Pass => header.push_str("pass"),
            DmarcResult::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            DmarcResult::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            DmarcResult::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            DmarcResult::None => header.push_str("none"),
        }
    }
}

impl AsAuthResult for IprevResult {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            IprevResult::Pass => header.push_str("pass"),
            IprevResult::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            IprevResult::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            IprevResult::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            IprevResult::None => header.push_str("none"),
        }
    }
}

impl AsAuthResult for DkimResult {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            DkimResult::Pass => header.push_str("pass"),
            DkimResult::Neutral(err) => {
                header.push_str("neutral");
                err.as_auth_result(header);
            }
            DkimResult::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            DkimResult::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            DkimResult::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            DkimResult::None => header.push_str("none"),
        }
    }
}

impl AsAuthResult for Dkim2Result {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            Dkim2Result::Pass => header.push_str("pass"),
            Dkim2Result::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            Dkim2Result::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            Dkim2Result::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            Dkim2Result::None => header.push_str("none"),
        }
    }
}

impl AsAuthResult for Error {
    fn as_auth_result(&self, header: &mut String) {
        header.push_str(" (");
        header.push_str(match self {
            Error::Parse => "dns record parse error",
            Error::MissingParameters => "missing parameters",
            Error::NoHeadersFound => "no headers found",
            Error::Crypto(CryptoError::Library(_)) => "verification failed",
            Error::Io(_) => "i/o error",
            Error::Base64 => "base64 error",
            Error::Dkim(DkimError::UnsupportedAlgorithm) => "unsupported algorithm",
            Error::Dkim(DkimError::UnsupportedCanonicalization) => "unsupported canonicalization",
            Error::Dkim(DkimError::UnsupportedKeyType) => "unsupported key type",
            Error::Crypto(CryptoError::FailedVerification) => "verification failed",
            Error::Crypto(CryptoError::IncompatibleAlgorithms) => {
                "incompatible record/signature algorithms"
            }
            Error::Dns(DnsError::Resolver(_)) => "dns error",
            Error::Dns(DnsError::RecordNotFound(_)) => "dns record not found",
            Error::Dkim(DkimError::UnsupportedVersion) => "unsupported version",
            Error::Dkim(DkimError::BodyHashMismatch) => "body hash did not verify",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::BodyHashMismatch) => "body hash did not verify",
            Error::Dkim(DkimError::AuidMismatch) => "auid does not match",
            Error::Dkim(DkimError::PublicKeyRevoked) => "revoked public key",
            Error::Dkim(DkimError::SignatureExpired) => "signature error",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::SignatureExpired) => "signature error",
            Error::Dkim(DkimError::BodyLengthTag) => {
                "signature length ignored due to security risk"
            }
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::BodyLengthTag) => "signature length ignored due to security risk",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::InvalidInstance(i)) => {
                write!(header, "invalid ARC instance {i})").ok();
                return;
            }
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::InvalidChainValidation) => "invalid ARC cv",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::ChainTooLong) => "too many ARC headers",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::HasHeaderTag) => "ARC has header tag",
            #[cfg(feature = "arc")]
            Error::Arc(ArcError::BrokenChain) => "broken ARC chain",
            Error::NotAligned => "policy not aligned",
            Error::Dns(DnsError::InvalidRecordType) => "invalid dns record type",
            Error::Dkim2(e) => {
                write!(header, "{e})").ok();
                return;
            }
        });
        header.push(')');
    }
}

/// Encodes the IP address to be used in a [`pvalue`] field.
///
/// IPv4 addresses can be used as-is, but IPv6 addresses need to be quoted
/// since they contain `:` characters.
///
/// [`pvalue`]: https://datatracker.ietf.org/doc/html/rfc8601#section-2.2
fn push_ip_as_pvalue(header: &mut String, ip: IpAddr) {
    match ip {
        IpAddr::V4(addr) => push_ipv4(header, addr),
        IpAddr::V6(addr) => {
            header.push('"');
            write!(header, "{addr}").ok();
            header.push('"');
        }
    }
}

fn push_ip(header: &mut String, ip: IpAddr) {
    match ip {
        IpAddr::V4(addr) => push_ipv4(header, addr),
        IpAddr::V6(addr) => {
            write!(header, "{addr}").ok();
        }
    }
}

fn push_ipv4(header: &mut String, addr: Ipv4Addr) {
    const MAX_IPV4_TEXT_LEN: usize = 15;

    let mut text = [0u8; MAX_IPV4_TEXT_LEN];
    let mut len = 0;
    let mut push = |byte: u8| {
        if let Some(slot) = text.get_mut(len) {
            *slot = byte;
            len += 1;
        }
    };

    for (pos, octet) in addr.octets().into_iter().enumerate() {
        if pos > 0 {
            push(b'.');
        }
        if octet >= 100 {
            push(b'0' + octet / 100);
        }
        if octet >= 10 {
            push(b'0' + (octet / 10) % 10);
        }
        push(b'0' + octet % 10);
    }

    header.push_str(std::str::from_utf8(text.get(..len).unwrap_or_default()).unwrap_or_default());
}

fn push_integer(header: &mut String, value: u64) {
    let mut integer = IntegerBuffer::new();
    header.push_str(integer.text(value));
}

#[inline]
fn is_pvalue_safe(ch: char) -> bool {
    !matches!(ch, '\0'..=' ' | '\u{7f}'..='\u{9f}' | '(' | ')' | ';' | '=' | '"' | '\\')
}

#[inline(always)]
fn is_pvalue_safe_ascii(ch: u8) -> bool {
    !matches!(ch, 0..=b' ' | 0x7f..=u8::MAX | b'(' | b')' | b';' | b'=' | b'"' | b'\\')
}

#[inline]
fn is_pvalue_clean(value: &str) -> bool {
    value.bytes().all(is_pvalue_safe_ascii) || value.chars().all(is_pvalue_safe)
}

#[inline]
fn sanitize_pvalue(value: &str) -> Cow<'_, str> {
    if is_pvalue_clean(value) {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(value.chars().filter(|&ch| is_pvalue_safe(ch)).collect())
    }
}

#[inline]
fn push_pvalue(header: &mut String, value: &str) {
    if is_pvalue_clean(value) {
        header.push_str(value);
    } else {
        header.extend(value.chars().filter(|&ch| is_pvalue_safe(ch)));
    }
}

#[inline]
fn push_quoted_pvalue(header: &mut String, value: &str) {
    if !value.is_empty() && is_pvalue_clean(value) {
        header.push_str(value);
    } else {
        header.push('"');
        push_qcontent(header, value);
        header.push('"');
    }
}

#[inline]
fn push_qcontent(header: &mut String, value: &str) {
    let mut start = 0;
    for (pos, ch) in value.char_indices() {
        match ch {
            '"' | '\\' => {
                header.push_str(value.get(start..pos).unwrap_or_default());
                header.push('\\');
                header.push(ch);
                start = pos + 1;
            }
            '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {
                header.push_str(value.get(start..pos).unwrap_or_default());
                start = pos + ch.len_utf8();
            }
            _ => {}
        }
    }
    header.push_str(value.get(start..).unwrap_or_default());
}

#[cfg(test)]
mod tests;
