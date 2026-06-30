/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::headers::{HeaderWriter, Writer};
use crate::{
    ArcOutput, AuthenticationResults, Dkim2Result, DkimOutput, DkimResult, DmarcOutput,
    DmarcResult, Error, IprevOutput, IprevResult, ReceivedSpf, SpfOutput, SpfResult, arc::ArcError,
    dkim::DkimError, dkim2::Dkim2Output,
};
use crate::{DnsError, common::crypto::CryptoError};
use mail_builder::encoders::base64::base64_encode;
use std::{
    borrow::Cow,
    fmt::{Display, Write},
    net::IpAddr,
};

impl<'x> AuthenticationResults<'x> {
    pub fn new(hostname: &'x str) -> Self {
        AuthenticationResults {
            hostname,
            auth_results: String::with_capacity(64),
        }
    }

    pub fn with_dkim_results(mut self, dkim: &[DkimOutput], header_from: &str) -> Self {
        for dkim in dkim {
            self.set_dkim_result(dkim, header_from);
        }
        self
    }

    pub fn with_dkim_result(mut self, dkim: &DkimOutput, header_from: &str) -> Self {
        self.set_dkim_result(dkim, header_from);
        self
    }

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
            if signature.b.len() >= 6 {
                self.auth_results.push_str(" header.b=");
                self.auth_results.push_str(
                    &String::from_utf8(base64_encode(&signature.b[..6]).unwrap_or_default())
                        .unwrap_or_default(),
                );
            }
        }

        if dkim.is_atps {
            self.auth_results.push_str(" header.from=");
            push_quoted_pvalue(&mut self.auth_results, header_from);
        }
    }

    pub fn with_dkim2_result(mut self, dkim2: &Dkim2Output) -> Self {
        self.set_dkim2_result(dkim2);
        self
    }

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
            write!(self.auth_results, " header.i={}", link.signature.i).ok();
        }
    }

    pub fn with_spf_ehlo_result(
        mut self,
        spf: &SpfOutput,
        ip_addr: IpAddr,
        ehlo_domain: &str,
    ) -> Self {
        let ehlo_domain = sanitize_pvalue(ehlo_domain);
        self.auth_results.push_str(";\r\n\tspf=");
        spf.result.as_spf_result(
            &mut self.auth_results,
            self.hostname,
            &format!("postmaster@{ehlo_domain}"),
            ip_addr,
        );
        write!(self.auth_results, " smtp.helo={ehlo_domain}").ok();
        self
    }

    pub fn with_spf_mailfrom_result(
        mut self,
        spf: &SpfOutput,
        ip_addr: IpAddr,
        from: &str,
        ehlo_domain: &str,
    ) -> Self {
        let ehlo_domain = sanitize_pvalue(ehlo_domain);
        let mail_from = if !from.is_empty() {
            sanitize_pvalue(from)
        } else {
            Cow::Owned(format!("postmaster@{ehlo_domain}"))
        };
        self.auth_results.push_str(";\r\n\tspf=");
        spf.result.as_spf_result(
            &mut self.auth_results,
            self.hostname,
            mail_from.as_ref(),
            ip_addr,
        );
        self.auth_results.push_str(" smtp.mailfrom=");
        if !from.is_empty() {
            push_quoted_pvalue(&mut self.auth_results, from);
        } else {
            self.auth_results.push_str("<>");
        }
        self
    }

    pub fn with_arc_result(mut self, arc: &ArcOutput, remote_ip: IpAddr) -> Self {
        self.auth_results.push_str(";\r\n\tarc=");
        arc.result.as_auth_result(&mut self.auth_results);
        let _ = write!(self.auth_results, " smtp.remote-ip=");
        let _ = format_ip_as_pvalue(&mut self.auth_results, remote_ip);
        self
    }

    pub fn with_dmarc_result(mut self, dmarc: &DmarcOutput) -> Self {
        self.auth_results.push_str(";\r\n\tdmarc=");
        if dmarc.spf_result == DmarcResult::Pass || dmarc.dkim_result == DmarcResult::Pass {
            DmarcResult::Pass.as_auth_result(&mut self.auth_results);
        } else if dmarc.spf_result != DmarcResult::None {
            dmarc.spf_result.as_auth_result(&mut self.auth_results);
        } else if dmarc.dkim_result != DmarcResult::None {
            dmarc.dkim_result.as_auth_result(&mut self.auth_results);
        } else {
            DmarcResult::None.as_auth_result(&mut self.auth_results);
        }
        write!(
            self.auth_results,
            " header.from={} policy.dmarc={}",
            sanitize_pvalue(&dmarc.domain),
            dmarc.policy
        )
        .ok();
        self
    }

    pub fn with_iprev_result(mut self, iprev: &IprevOutput, remote_ip: IpAddr) -> Self {
        self.auth_results.push_str(";\r\n\tiprev=");
        iprev.result.as_auth_result(&mut self.auth_results);
        let _ = write!(self.auth_results, " policy.iprev=");
        let _ = format_ip_as_pvalue(&mut self.auth_results, remote_ip);
        self
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

impl ReceivedSpf {
    pub fn new(
        spf: &SpfOutput,
        ip_addr: IpAddr,
        helo: &str,
        mail_from: &str,
        hostname: &str,
    ) -> Self {
        let mut received_spf = String::with_capacity(64);
        let helo = sanitize_pvalue(helo);
        let envelope_from = if !mail_from.is_empty() {
            Cow::Borrowed(mail_from)
        } else {
            Cow::Owned(format!("postmaster@{helo}"))
        };
        let mail_from = sanitize_pvalue(&envelope_from);

        spf.result
            .as_spf_result(&mut received_spf, hostname, mail_from.as_ref(), ip_addr);

        write!(
            received_spf,
            "\r\n\treceiver={hostname}; client-ip={ip_addr}; envelope-from=\""
        )
        .ok();
        push_qcontent(&mut received_spf, &envelope_from);
        write!(received_spf, "\"; helo={helo};").ok();

        ReceivedSpf { received_spf }
    }
}

impl SpfResult {
    fn as_spf_result(&self, header: &mut String, hostname: &str, mail_from: &str, ip_addr: IpAddr) {
        match &self {
            SpfResult::Pass => write!(
                header,
                "pass ({hostname}: domain of {mail_from} designates {ip_addr} as permitted sender)",
            ),
            SpfResult::Fail => write!(
                header,
                "fail ({hostname}: domain of {mail_from} does not designate {ip_addr} as permitted sender)",
            ),
            SpfResult::SoftFail => write!(
                header,
                "softfail ({hostname}: domain of {mail_from} reports soft fail for {ip_addr})",
            ),
            SpfResult::Neutral => write!(
                header,
                "neutral ({hostname}: domain of {mail_from} reports neutral for {ip_addr})",
            ),
            SpfResult::TempError => write!(
                header,
                "temperror ({hostname}: temporary dns error validating {mail_from})",
            ),
            SpfResult::PermError => write!(
                header,
                "permerror ({hostname}: unable to verify SPF record for {mail_from})",
            ),
            SpfResult::None => write!(
                header,
                "none ({hostname}: no SPF records found for {mail_from})",
            ),
        }
        .ok();
    }
}

pub trait AsAuthResult {
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
            Error::ParseError => "dns record parse error",
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
            Error::Dkim(DkimError::FailedBodyHashMatch)
            | Error::Arc(ArcError::FailedBodyHashMatch) => "body hash did not verify",
            Error::Dkim(DkimError::FailedAuidMatch) => "auid does not match",
            Error::Dkim(DkimError::RevokedPublicKey) => "revoked public key",
            Error::Dkim(DkimError::SignatureExpired) | Error::Arc(ArcError::SignatureExpired) => {
                "signature error"
            }
            Error::Dkim(DkimError::SignatureLength) | Error::Arc(ArcError::SignatureLength) => {
                "signature length ignored due to security risk"
            }
            Error::Arc(ArcError::InvalidInstance(i)) => {
                write!(header, "invalid ARC instance {i})").ok();
                return;
            }
            Error::Arc(ArcError::InvalidCV) => "invalid ARC cv",
            Error::Arc(ArcError::ChainTooLong) => "too many ARC headers",
            Error::Arc(ArcError::HasHeaderTag) => "ARC has header tag",
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
fn format_ip_as_pvalue(w: &mut impl Write, ip: IpAddr) -> std::fmt::Result {
    match ip {
        IpAddr::V4(addr) => write!(w, "{addr}"),
        IpAddr::V6(addr) => write!(w, "\"{addr}\""),
    }
}

#[inline]
fn is_pvalue_safe(ch: char) -> bool {
    !matches!(ch, '\0'..=' ' | '\u{7f}'..='\u{9f}' | '(' | ')' | ';' | '=' | '"' | '\\')
}

#[inline]
fn sanitize_pvalue(value: &str) -> Cow<'_, str> {
    if value.chars().all(is_pvalue_safe) {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(value.chars().filter(|&ch| is_pvalue_safe(ch)).collect())
    }
}

#[inline]
fn push_pvalue(header: &mut String, value: &str) {
    header.extend(value.chars().filter(|&ch| is_pvalue_safe(ch)));
}

#[inline]
fn push_quoted_pvalue(header: &mut String, value: &str) {
    if !value.is_empty() && value.chars().all(is_pvalue_safe) {
        header.push_str(value);
    } else {
        header.push('"');
        push_qcontent(header, value);
        header.push('"');
    }
}

#[inline]
fn push_qcontent(header: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' | '\\' => {
                header.push('\\');
                header.push(ch);
            }
            '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {}
            ch => header.push(ch),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        ArcOutput, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput, DmarcResult,
        DnsError, Error, IprevOutput, IprevResult, ReceivedSpf, SpfOutput, SpfResult,
        arc::ArcError, common::crypto::CryptoError, dkim::Signature, dmarc::Policy,
    };

    #[test]
    fn authentication_results() {
        let mut auth_results = AuthenticationResults::new("mydomain.org");

        for (expected_auth_results, dkim) in [
            (
                "dkim=pass header.d=example.org header.s=myselector",
                DkimOutput {
                    result: DkimResult::Pass,
                    signature: (&Signature {
                        d: "example.org".into(),
                        s: "myselector".into(),
                        ..Default::default()
                    })
                        .into(),
                    report: None,
                    is_atps: false,
                },
            ),
            (
                concat!(
                    "dkim=fail (verification failed) header.d=example.org ",
                    "header.s=myselector header.b=MTIzNDU2"
                ),
                DkimOutput {
                    result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
                    signature: (&Signature {
                        d: "example.org".into(),
                        s: "myselector".into(),
                        b: b"123456".to_vec(),
                        ..Default::default()
                    })
                        .into(),
                    report: None,
                    is_atps: false,
                },
            ),
            (
                concat!(
                    "dkim-atps=temperror (dns error) header.d=atps.example.org ",
                    "header.s=otherselctor header.b=YWJjZGVm header.from=jdoe@example.org"
                ),
                DkimOutput {
                    result: DkimResult::TempError(Error::Dns(DnsError::Resolver("".to_string()))),
                    signature: (&Signature {
                        d: "atps.example.org".into(),
                        s: "otherselctor".into(),
                        b: b"abcdef".to_vec(),
                        ..Default::default()
                    })
                        .into(),
                    report: None,
                    is_atps: true,
                },
            ),
        ] {
            auth_results = auth_results.with_dkim_results(&[dkim], "jdoe@example.org");
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected_auth_results
            );
        }

        for (
            expected_auth_results,
            expected_received_spf,
            result,
            ip_addr,
            receiver,
            helo,
            mail_from,
        ) in [
            (
                concat!(
                    "spf=pass (localhost: domain of jdoe@example.org designates 192.168.1.1 ",
                    "as permitted sender) smtp.mailfrom=jdoe@example.org"
                ),
                concat!(
                    "pass (localhost: domain of jdoe@example.org designates 192.168.1.1 as ",
                    "permitted sender)\r\n\treceiver=localhost; client-ip=192.168.1.1; ",
                    "envelope-from=\"jdoe@example.org\"; helo=example.org;"
                ),
                SpfResult::Pass,
                "192.168.1.1".parse().unwrap(),
                "localhost",
                "example.org",
                "jdoe@example.org",
            ),
            (
                concat!(
                    "spf=fail (mx.domain.org: domain of sender@otherdomain.org does not ",
                    "designate a:b:c::f as permitted sender) smtp.mailfrom=sender@otherdomain.org"
                ),
                concat!(
                    "fail (mx.domain.org: domain of sender@otherdomain.org does not designate ",
                    "a:b:c::f as permitted sender)\r\n\treceiver=mx.domain.org; ",
                    "client-ip=a:b:c::f; envelope-from=\"sender@otherdomain.org\"; ",
                    "helo=otherdomain.org;"
                ),
                SpfResult::Fail,
                "a:b:c::f".parse().unwrap(),
                "mx.domain.org",
                "otherdomain.org",
                "sender@otherdomain.org",
            ),
            (
                concat!(
                    "spf=neutral (mx.domain.org: domain of postmaster@example.org reports neutral ",
                    "for a:b:c::f) smtp.mailfrom=<>"
                ),
                concat!(
                    "neutral (mx.domain.org: domain of postmaster@example.org reports neutral for ",
                    "a:b:c::f)\r\n\treceiver=mx.domain.org; client-ip=a:b:c::f; ",
                    "envelope-from=\"postmaster@example.org\"; helo=example.org;"
                ),
                SpfResult::Neutral,
                "a:b:c::f".parse().unwrap(),
                "mx.domain.org",
                "example.org",
                "",
            ),
        ] {
            auth_results.hostname = receiver;
            auth_results = auth_results.with_spf_mailfrom_result(
                &SpfOutput {
                    result,
                    domain: "".to_string(),
                    report: None,
                    explanation: None,
                },
                ip_addr,
                mail_from,
                helo,
            );
            let received_spf = ReceivedSpf::new(
                &SpfOutput {
                    result,
                    domain: "".to_string(),
                    report: None,
                    explanation: None,
                },
                ip_addr,
                helo,
                mail_from,
                receiver,
            );
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected_auth_results
            );
            assert_eq!(received_spf.received_spf, expected_received_spf);
        }

        for (expected_auth_results, dmarc) in [
            (
                "dmarc=pass header.from=example.org policy.dmarc=none",
                DmarcOutput {
                    spf_result: DmarcResult::Pass,
                    dkim_result: DmarcResult::None,
                    domain: "example.org".to_string(),
                    policy: Policy::None,
                    record: None,
                },
            ),
            (
                "dmarc=fail (policy not aligned) header.from=example.com policy.dmarc=quarantine",
                DmarcOutput {
                    dkim_result: DmarcResult::Fail(Error::NotAligned),
                    spf_result: DmarcResult::None,
                    domain: "example.com".to_string(),
                    policy: Policy::Quarantine,
                    record: None,
                },
            ),
        ] {
            auth_results = auth_results.with_dmarc_result(&dmarc);
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected_auth_results
            );
        }

        for (expected_auth_results, arc, remote_ip) in [
            (
                "arc=pass smtp.remote-ip=192.127.9.2",
                DkimResult::Pass,
                "192.127.9.2".parse().unwrap(),
            ),
            (
                "arc=neutral (body hash did not verify) smtp.remote-ip=\"1:2:3::a\"",
                DkimResult::Neutral(Error::Arc(ArcError::FailedBodyHashMatch)),
                "1:2:3::a".parse().unwrap(),
            ),
        ] {
            auth_results = auth_results.with_arc_result(
                &ArcOutput {
                    result: arc,
                    set: vec![],
                },
                remote_ip,
            );
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected_auth_results
            );
        }

        for (expected_auth_results, iprev, remote_ip) in [
            (
                "iprev=pass policy.iprev=192.127.9.2",
                IprevOutput {
                    result: IprevResult::Pass,
                    ptr: None,
                },
                "192.127.9.2".parse().unwrap(),
            ),
            (
                "iprev=fail (policy not aligned) policy.iprev=\"1:2:3::a\"",
                IprevOutput {
                    result: IprevResult::Fail(Error::NotAligned),
                    ptr: None,
                },
                "1:2:3::a".parse().unwrap(),
            ),
        ] {
            auth_results = auth_results.with_iprev_result(&iprev, remote_ip);
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected_auth_results
            );
        }
    }

    #[test]
    fn dkim2_authentication_results() {
        use crate::{
            Dkim2Result,
            dkim2::{ChainLink, Dkim2Error, Dkim2Output, Signature as Dkim2Signature},
        };

        let originator = Dkim2Signature {
            i: 1,
            d: "example.org".into(),
            ..Default::default()
        };
        let relay = Dkim2Signature {
            i: 2,
            d: "relay.example.com".into(),
            ..Default::default()
        };

        let pass = Dkim2Output {
            result: Dkim2Result::Pass,
            chain: vec![
                ChainLink {
                    signature: &originator,
                    instance: None,
                    result: Dkim2Result::Pass,
                    custody_ok: true,
                },
                ChainLink {
                    signature: &relay,
                    instance: None,
                    result: Dkim2Result::Pass,
                    custody_ok: true,
                },
            ],
        };

        let fail = Dkim2Output {
            result: Dkim2Result::Fail(Error::Dkim2(Dkim2Error::BodyHashMismatch(2))),
            chain: vec![
                ChainLink {
                    signature: &originator,
                    instance: None,
                    result: Dkim2Result::Pass,
                    custody_ok: true,
                },
                ChainLink {
                    signature: &relay,
                    instance: None,
                    result: Dkim2Result::Fail(Error::Dkim2(Dkim2Error::BodyHashMismatch(2))),
                    custody_ok: true,
                },
            ],
        };

        let permerror: Dkim2Output =
            Dkim2Result::PermError(Error::Dkim2(Dkim2Error::SignatureMissing(1))).into();

        let none: Dkim2Output = Dkim2Result::None.into();

        for (expected, output) in [
            ("dkim2=pass header.d=example.org header.i=1", &pass),
            (
                concat!(
                    "dkim2=fail (Message-Instance m=2 body hash mismatch) ",
                    "header.d=relay.example.com header.i=2"
                ),
                &fail,
            ),
            ("dkim2=permerror (DKIM2-Signature i=1 missing)", &permerror),
            ("dkim2=none", &none),
        ] {
            let auth_results = AuthenticationResults::new("mydomain.org").with_dkim2_result(output);
            assert_eq!(
                auth_results.auth_results.rsplit_once(';').unwrap().1.trim(),
                expected
            );
        }
    }

    #[test]
    fn dkim_result_header_injection() {
        let signature = Signature {
            i: "u@evil.test\r\nReply-To: attacker@evil.test\r\nX-Injected: yes".into(),
            d: "evil.test\r\nX-Injected-D: yes".into(),
            s: "sel\r\nX-Injected-S: yes".into(),
            b: b"123456".to_vec(),
            ..Default::default()
        };
        let output = DkimOutput {
            result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
            signature: Some(&signature),
            report: None,
            is_atps: false,
        };
        let auth_results = AuthenticationResults::new("mx.example.org")
            .with_dkim_result(&output, "from@example.org");

        assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
        let value = auth_results.auth_results.split_once("header.i=").unwrap().1;
        assert!(!value.contains('\r') && !value.contains('\n'));
        assert!(value.starts_with("\"u@evil.test"));
        assert!(value.contains("Reply-To: attacker@evil.test"));
    }

    #[test]
    fn dkim_result_header_i_quoted_local_part() {
        let signature = Signature {
            i: "a;b=c (note)\"x@example.org".into(),
            d: "example.org".into(),
            s: "sel".into(),
            ..Default::default()
        };
        let output = DkimOutput {
            result: DkimResult::Pass,
            signature: Some(&signature),
            report: None,
            is_atps: false,
        };
        let auth_results = AuthenticationResults::new("mx.example.org")
            .with_dkim_result(&output, "from@example.org");
        let value = auth_results.auth_results.split_once("header.i=").unwrap().1;

        assert!(value.starts_with("\"a;b=c (note)\\\"x@example.org\""));
        assert_eq!(value.matches('"').count(), 3);
    }

    #[test]
    fn dkim_result_header_d_injection() {
        let signature = Signature {
            d: "evil.test\r\nX-Injected: yes".into(),
            s: "sel\"; smtp.bogus=1".into(),
            ..Default::default()
        };
        let output = DkimOutput {
            result: DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
            signature: Some(&signature),
            report: None,
            is_atps: false,
        };
        let auth_results = AuthenticationResults::new("mx.example.org")
            .with_dkim_result(&output, "from@example.org");

        assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
        let value = auth_results.auth_results.split_once("header.d=").unwrap().1;
        assert!(!value.contains('\r') && !value.contains('\n'));
        assert!(!value.contains('"') && !value.contains(';'));
    }

    #[test]
    fn spf_result_header_injection() {
        let spf = SpfOutput {
            result: SpfResult::Pass,
            domain: String::new(),
            report: None,
            explanation: None,
        };
        let auth_results = AuthenticationResults::new("mx.example.org").with_spf_mailfrom_result(
            &spf,
            "192.168.1.1".parse().unwrap(),
            "a@evil.test\r\nX-Injected: yes",
            "helo.test\r\nX-Injected-Helo: yes",
        );
        assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);

        let auth_results = AuthenticationResults::new("mx.example.org").with_spf_ehlo_result(
            &spf,
            "192.168.1.1".parse().unwrap(),
            "helo.test\r\nX-Injected: yes",
        );
        assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
    }

    #[test]
    fn dmarc_result_header_injection() {
        let auth_results =
            AuthenticationResults::new("mx.example.org").with_dmarc_result(&DmarcOutput {
                spf_result: DmarcResult::Pass,
                dkim_result: DmarcResult::None,
                domain: "evil.test\r\nX-Injected: yes".to_string(),
                policy: Policy::None,
                record: None,
            });
        assert_eq!(auth_results.auth_results.matches("\r\n").count(), 1);
        let value = auth_results
            .auth_results
            .split_once("header.from=")
            .unwrap()
            .1;
        assert!(!value.contains('\r') && !value.contains('\n'));
    }

    #[test]
    fn received_spf_header_injection() {
        let spf = SpfOutput {
            result: SpfResult::Pass,
            domain: String::new(),
            report: None,
            explanation: None,
        };
        let received_spf = ReceivedSpf::new(
            &spf,
            "192.168.1.1".parse().unwrap(),
            "helo.test\r\nX-Injected-Helo: yes",
            "a@evil.test\r\nX-Injected: yes\r\nReply-To: attacker@evil.test",
            "mx.example.org",
        );
        assert_eq!(received_spf.received_spf.matches("\r\n").count(), 1);
        assert!(
            !received_spf.received_spf.contains('"')
                || received_spf.received_spf.matches('"').count() == 2
        );
    }
}
