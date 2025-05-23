/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    borrow::Cow,
    fmt::{Display, Write},
    net::IpAddr,
};

use mail_builder::encoders::base64::base64_encode;

use crate::{
    ArcOutput, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput, DmarcResult, Error,
    IprevOutput, IprevResult, ReceivedSpf, SpfOutput, SpfResult,
};

use super::headers::{HeaderWriter, Writer};

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
                self.auth_results.push_str(&signature.i);
            } else {
                self.auth_results.push_str(" header.d=");
                self.auth_results.push_str(&signature.d);
            }
            self.auth_results.push_str(" header.s=");
            self.auth_results.push_str(&signature.s);
            if signature.b.len() >= 6 {
                self.auth_results.push_str(" header.b=");
                self.auth_results.push_str(
                    &String::from_utf8(base64_encode(&signature.b[..6]).unwrap_or_default())
                        .unwrap_or_default(),
                );
            }
        }

        if dkim.is_atps {
            write!(self.auth_results, " header.from={header_from}").ok();
        }
    }

    pub fn with_spf_ehlo_result(
        mut self,
        spf: &SpfOutput,
        ip_addr: IpAddr,
        ehlo_domain: &str,
    ) -> Self {
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
        let (mail_from, addr) = if !from.is_empty() {
            (Cow::from(from), from)
        } else {
            (format!("postmaster@{ehlo_domain}").into(), "<>")
        };
        self.auth_results.push_str(";\r\n\tspf=");
        spf.result.as_spf_result(
            &mut self.auth_results,
            self.hostname,
            mail_from.as_ref(),
            ip_addr,
        );
        write!(self.auth_results, " smtp.mailfrom={addr}").ok();
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
            dmarc.domain, dmarc.policy
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
        let mail_from = if !mail_from.is_empty() {
            Cow::from(mail_from)
        } else {
            format!("postmaster@{helo}").into()
        };

        spf.result
            .as_spf_result(&mut received_spf, hostname, mail_from.as_ref(), ip_addr);

        write!(
            received_spf,
            "\r\n\treceiver={hostname}; client-ip={ip_addr}; envelope-from=\"{mail_from}\"; helo={helo};",
        )
        .ok();

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

impl AsAuthResult for Error {
    fn as_auth_result(&self, header: &mut String) {
        header.push_str(" (");
        header.push_str(match self {
            Error::ParseError => "dns record parse error",
            Error::MissingParameters => "missing parameters",
            Error::NoHeadersFound => "no headers found",
            Error::CryptoError(_) => "verification failed",
            Error::Io(_) => "i/o error",
            Error::Base64 => "base64 error",
            Error::UnsupportedVersion => "unsupported version",
            Error::UnsupportedAlgorithm => "unsupported algorithm",
            Error::UnsupportedCanonicalization => "unsupported canonicalization",
            Error::UnsupportedKeyType => "unsupported key type",
            Error::FailedBodyHashMatch => "body hash did not verify",
            Error::FailedVerification => "verification failed",
            Error::FailedAuidMatch => "auid does not match",
            Error::RevokedPublicKey => "revoked public key",
            Error::IncompatibleAlgorithms => "incompatible record/signature algorithms",
            Error::SignatureExpired => "signature error",
            Error::DnsError(_) => "dns error",
            Error::DnsRecordNotFound(_) => "dns record not found",
            Error::ArcInvalidInstance(i) => {
                write!(header, "invalid ARC instance {i})").ok();
                return;
            }
            Error::ArcInvalidCV => "invalid ARC cv",
            Error::ArcChainTooLong => "too many ARC headers",
            Error::ArcHasHeaderTag => "ARC has header tag",
            Error::ArcBrokenChain => "broken ARC chain",
            Error::NotAligned => "policy not aligned",
            Error::InvalidRecordType => "invalid dns record type",
            Error::SignatureLength => "signature length ignored due to security risk",
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

#[cfg(test)]
mod test {
    use crate::{
        dkim::Signature, dmarc::Policy, ArcOutput, AuthenticationResults, DkimOutput, DkimResult,
        DmarcOutput, DmarcResult, Error, IprevOutput, IprevResult, ReceivedSpf, SpfOutput,
        SpfResult,
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
                    result: DkimResult::Fail(Error::FailedVerification),
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
                    result: DkimResult::TempError(Error::DnsError("".to_string())),
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
                DkimResult::Neutral(Error::FailedBodyHashMatch),
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
}
