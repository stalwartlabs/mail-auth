use std::{borrow::Cow, fmt::Write, net::IpAddr};

use mail_builder::encoders::base64::base64_encode;

use crate::{
    ARCOutput, AuthenticationResults, DKIMOutput, DKIMResult, DMARCOutput, DMARCResult, Error,
    ReceivedSPF, SPFOutput, SPFResult,
};

use super::headers::HeaderWriter;

impl<'x> AuthenticationResults<'x> {
    pub fn new(hostname: &'x str) -> Self {
        AuthenticationResults {
            hostname,
            auth_results: String::with_capacity(64),
        }
    }

    pub fn with_dkim_result(mut self, dkim: &[DKIMOutput], header_from: &str) -> Self {
        for dkim in dkim {
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
                write!(self.auth_results, " header.from={}", header_from).ok();
            }
        }
        self
    }

    pub fn with_spf_result(
        mut self,
        spf: &SPFOutput,
        ip_addr: IpAddr,
        helo: &str,
        mail_from: &str,
    ) -> Self {
        let mail_from = if !mail_from.is_empty() {
            Cow::from(mail_from)
        } else {
            format!("postmaster@{}", helo).into()
        };
        self.auth_results.push_str(";\r\n\tspf=");
        spf.result.as_spf_result(
            &mut self.auth_results,
            self.hostname,
            mail_from.as_ref(),
            ip_addr,
        );
        write!(
            self.auth_results,
            " smtp.mailfrom={} smtp.helo={}",
            mail_from, helo
        )
        .ok();
        self
    }

    pub fn with_arc_result(mut self, arc: &ARCOutput, remote_ip: IpAddr) -> Self {
        self.auth_results.push_str(";\r\n\tarc=");
        arc.result.as_auth_result(&mut self.auth_results);
        write!(self.auth_results, " smtp.remote-ip={}", remote_ip).ok();
        self
    }

    pub fn with_dmarc_result(mut self, dmarc: &DMARCOutput) -> Self {
        self.auth_results.push_str(";\r\n\tdmarc=");
        if dmarc.spf_result == DMARCResult::Pass || dmarc.dkim_result == DMARCResult::Pass {
            DMARCResult::Pass.as_auth_result(&mut self.auth_results);
        } else if dmarc.spf_result != DMARCResult::None {
            dmarc.spf_result.as_auth_result(&mut self.auth_results);
        } else if dmarc.dkim_result != DMARCResult::None {
            dmarc.dkim_result.as_auth_result(&mut self.auth_results);
        } else {
            DMARCResult::None.as_auth_result(&mut self.auth_results);
        }
        write!(
            self.auth_results,
            " header.from={} policy.dmarc={}",
            dmarc.domain, dmarc.policy
        )
        .ok();
        self
    }
}

impl<'x> HeaderWriter for AuthenticationResults<'x> {
    fn write_header(&self, mut writer: impl std::io::Write) -> std::io::Result<()> {
        writer.write_all(b"Authentication-Results: ")?;
        writer.write_all(self.hostname.as_bytes())?;
        if !self.auth_results.is_empty() {
            writer.write_all(self.auth_results.as_bytes())?;
        } else {
            writer.write_all(b"; none")?;
        }
        writer.write_all(b"\r\n")
    }
}

impl HeaderWriter for ReceivedSPF {
    fn write_header(&self, mut writer: impl std::io::Write) -> std::io::Result<()> {
        writer.write_all(b"Received-SPF: ")?;
        writer.write_all(self.received_spf.as_bytes())?;
        writer.write_all(b"\r\n")
    }
}

impl ReceivedSPF {
    pub fn new(
        spf: &SPFOutput,
        ip_addr: IpAddr,
        helo: &str,
        mail_from: &str,
        hostname: &str,
    ) -> Self {
        let mut received_spf = String::with_capacity(64);
        let mail_from = if !mail_from.is_empty() {
            Cow::from(mail_from)
        } else {
            format!("postmaster@{}", helo).into()
        };

        spf.result
            .as_spf_result(&mut received_spf, hostname, mail_from.as_ref(), ip_addr);

        write!(
            received_spf,
            "\r\n\treceiver={}; client-ip={}; envelope-from=\"{}\"; helo={};",
            hostname, ip_addr, mail_from, helo
        )
        .ok();

        ReceivedSPF { received_spf }
    }
}

impl SPFResult {
    fn as_spf_result(&self, header: &mut String, hostname: &str, mail_from: &str, ip_addr: IpAddr) {
        match &self {
            SPFResult::Pass => write!(
                header,
                "pass ({}: domain of {} designates {} as permitted sender)",
                hostname, mail_from, ip_addr
            ),
            SPFResult::Fail => write!(
                header,
                "fail ({}: domain of {} does not designate {} as permitted sender)",
                hostname, mail_from, ip_addr
            ),
            SPFResult::SoftFail => write!(
                header,
                "softfail ({}: domain of {} reports soft fail for {})",
                hostname, mail_from, ip_addr
            ),
            SPFResult::Neutral => write!(
                header,
                "neutral ({}: domain of {} reports neutral for {})",
                hostname, mail_from, ip_addr
            ),
            SPFResult::TempError => write!(
                header,
                "temperror ({}: temporary dns error validating {})",
                hostname, mail_from
            ),
            SPFResult::PermError => write!(
                header,
                "permerror ({}: unable to verify SPF record for {})",
                hostname, mail_from,
            ),
            SPFResult::None => write!(
                header,
                "none ({}: no SPF records found for {})",
                hostname, mail_from
            ),
        }
        .ok();
    }
}

pub trait AsAuthResult {
    fn as_auth_result(&self, header: &mut String);
}

impl AsAuthResult for DMARCResult {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            DMARCResult::Pass => header.push_str("pass"),
            DMARCResult::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            DMARCResult::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            DMARCResult::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            DMARCResult::None => header.push_str("none"),
        }
    }
}

impl AsAuthResult for DKIMResult {
    fn as_auth_result(&self, header: &mut String) {
        match &self {
            DKIMResult::Pass => header.push_str("pass"),
            DKIMResult::Neutral(err) => {
                header.push_str("neutral");
                err.as_auth_result(header);
            }
            DKIMResult::Fail(err) => {
                header.push_str("fail");
                err.as_auth_result(header);
            }
            DKIMResult::PermError(err) => {
                header.push_str("permerror");
                err.as_auth_result(header);
            }
            DKIMResult::TempError(err) => {
                header.push_str("temperror");
                err.as_auth_result(header);
            }
            DKIMResult::None => header.push_str("none"),
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
            Error::FailedAUIDMatch => "auid does not match",
            Error::RevokedPublicKey => "revoked public key",
            Error::IncompatibleAlgorithms => "incompatible record/signature algorithms",
            Error::SignatureExpired => "signature error",
            Error::DNSError => "dns error",
            Error::DNSRecordNotFound(_) => "dns record not found",
            Error::ARCInvalidInstance(i) => {
                write!(header, "invalid ARC instance {})", i).ok();
                return;
            }
            Error::ARCInvalidCV => "invalid ARC cv",
            Error::ARCChainTooLong => "too many ARC headers",
            Error::ARCHasHeaderTag => "ARC has header tag",
            Error::ARCBrokenChain => "broken ARC chain",
            Error::DMARCNotAligned => "dmarc not aligned",
            Error::InvalidRecordType => "invalid dns record type",
        });
        header.push(')');
    }
}

#[cfg(test)]
mod test {
    use crate::{
        dkim::Signature, dmarc::Policy, ARCOutput, AuthenticationResults, DKIMOutput, DKIMResult,
        DMARCOutput, DMARCResult, Error, ReceivedSPF, SPFOutput, SPFResult,
    };

    #[test]
    fn authentication_results() {
        let mut auth_results = AuthenticationResults::new("mydomain.org");

        for (expected_auth_results, dkim) in [
            (
                "dkim=pass header.d=example.org header.s=myselector",
                DKIMOutput {
                    result: DKIMResult::Pass,
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
                DKIMOutput {
                    result: DKIMResult::Fail(Error::FailedVerification),
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
                DKIMOutput {
                    result: DKIMResult::TempError(Error::DNSError),
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
            auth_results = auth_results.with_dkim_result(&[dkim], "jdoe@example.org");
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
                    "as permitted sender) smtp.mailfrom=jdoe@example.org smtp.helo=example.org"
                ),
                concat!(
                    "pass (localhost: domain of jdoe@example.org designates 192.168.1.1 as ",
                    "permitted sender)\r\n\treceiver=localhost; client-ip=192.168.1.1; ",
                    "envelope-from=\"jdoe@example.org\"; helo=example.org;"
                ),
                SPFResult::Pass,
                "192.168.1.1".parse().unwrap(),
                "localhost",
                "example.org",
                "jdoe@example.org",
            ),
            (
                concat!(
                    "spf=fail (mx.domain.org: domain of sender@otherdomain.org does not ",
                    "designate a:b:c::f as permitted sender) smtp.mailfrom=sender@otherdomain.org ",
                    "smtp.helo=otherdomain.org"
                ),
                concat!(
                    "fail (mx.domain.org: domain of sender@otherdomain.org does not designate ",
                    "a:b:c::f as permitted sender)\r\n\treceiver=mx.domain.org; ",
                    "client-ip=a:b:c::f; envelope-from=\"sender@otherdomain.org\"; ",
                    "helo=otherdomain.org;"
                ),
                SPFResult::Fail,
                "a:b:c::f".parse().unwrap(),
                "mx.domain.org",
                "otherdomain.org",
                "sender@otherdomain.org",
            ),
            (
                concat!(
                    "spf=neutral (mx.domain.org: domain of postmaster@example.org reports neutral ",
                    "for a:b:c::f) smtp.mailfrom=postmaster@example.org smtp.helo=example.org"
                ),
                concat!(
                    "neutral (mx.domain.org: domain of postmaster@example.org reports neutral for ",
                    "a:b:c::f)\r\n\treceiver=mx.domain.org; client-ip=a:b:c::f; ",
                    "envelope-from=\"postmaster@example.org\"; helo=example.org;"
                ),
                SPFResult::Neutral,
                "a:b:c::f".parse().unwrap(),
                "mx.domain.org",
                "example.org",
                "",
            ),
        ] {
            auth_results.hostname = receiver;
            auth_results = auth_results.with_spf_result(
                &SPFOutput {
                    result,
                    domain: "".to_string(),
                    report: None,
                    explanation: None,
                },
                ip_addr,
                helo,
                mail_from,
            );
            let received_spf = ReceivedSPF::new(
                &SPFOutput {
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
                DMARCOutput {
                    spf_result: DMARCResult::Pass,
                    dkim_result: DMARCResult::None,
                    domain: "example.org".to_string(),
                    policy: Policy::None,
                    record: None,
                },
            ),
            (
                "dmarc=fail (dmarc not aligned) header.from=example.com policy.dmarc=quarantine",
                DMARCOutput {
                    dkim_result: DMARCResult::Fail(Error::DMARCNotAligned),
                    spf_result: DMARCResult::None,
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
                DKIMResult::Pass,
                "192.127.9.2".parse().unwrap(),
            ),
            (
                "arc=neutral (body hash did not verify) smtp.remote-ip=1:2:3::a",
                DKIMResult::Neutral(Error::FailedBodyHashMatch),
                "1:2:3::a".parse().unwrap(),
            ),
        ] {
            auth_results = auth_results.with_arc_result(
                &ARCOutput {
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
    }
}
