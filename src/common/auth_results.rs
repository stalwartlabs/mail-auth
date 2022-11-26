use std::{borrow::Cow, fmt::Write, net::IpAddr};

use mail_builder::encoders::base64::base64_encode;

use crate::{
    ARCOutput, AuthenticatedMessage, DKIMOutput, DKIMResult, DMARCOutput, DMARCResult, Error,
    SPFOutput, SPFResult,
};

impl<'x> AuthenticatedMessage<'x> {
    pub fn add_dkim_result(&mut self, dkim: &DKIMOutput) {
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
            write!(
                self.auth_results,
                " header.from={}",
                self.from.last().map(|s| s.as_str()).unwrap_or_default()
            )
            .ok();
        }
    }

    pub fn add_spf_result(
        &mut self,
        spf: &SPFOutput,
        ip_addr: IpAddr,
        receiver: &str,
        helo: &str,
        mail_from: &str,
    ) {
        let mail_from = if !mail_from.is_empty() {
            Cow::from(mail_from)
        } else {
            format!("postmaster@{}", helo).into()
        };
        self.auth_results.push_str(";\r\n\tspf=");
        match &spf.result {
            SPFResult::Pass => write!(
                self.received_spf,
                "pass ({}: domain of {} designates {} as permitted sender)",
                receiver, mail_from, ip_addr
            ),
            SPFResult::Fail => write!(
                self.received_spf,
                "fail ({}: domain of {} does not designate {} as permitted sender)",
                receiver, mail_from, ip_addr
            ),
            SPFResult::SoftFail => write!(
                self.received_spf,
                "softfail ({}: domain of {} reports soft fail for {})",
                receiver, mail_from, ip_addr
            ),
            SPFResult::Neutral => write!(
                self.received_spf,
                "neutral ({}: domain of {} reports neutral for {})",
                receiver, mail_from, ip_addr
            ),
            SPFResult::TempError => write!(
                self.received_spf,
                "temperror ({}: temporary dns error validating {})",
                receiver, mail_from
            ),
            SPFResult::PermError => write!(
                self.received_spf,
                "permerror ({}: unable to verify SPF record for {})",
                receiver, mail_from,
            ),
            SPFResult::None => write!(
                self.received_spf,
                "none ({}: no SPF records found for {})",
                receiver, mail_from
            ),
        }
        .ok();

        self.auth_results += &self.received_spf;
        write!(
            self.received_spf,
            "\r\n\treceiver={}; client-ip={}; envelope-from=\"{}\"; helo={};",
            receiver, ip_addr, mail_from, helo
        )
        .ok();

        write!(
            self.auth_results,
            " smtp.mailfrom={} smtp.helo={}",
            mail_from, helo
        )
        .ok();
    }

    pub fn add_arc_result(&mut self, arc: &ARCOutput, remote_ip: IpAddr) {
        self.auth_results.push_str(";\r\n\tarc=");
        arc.result.as_auth_result(&mut self.auth_results);
        write!(self.auth_results, " smtp.remote-ip={}", remote_ip).ok();
    }

    pub fn add_dmarc_result(&mut self, dmarc: &DMARCOutput) {
        self.auth_results.push_str(";\r\n\tdmarc=");
        match &dmarc.result {
            DMARCResult::Pass => self.auth_results.push_str("pass"),
            DMARCResult::Fail(err) => {
                self.auth_results.push_str("fail");
                err.as_auth_result(&mut self.auth_results);
            }
            DMARCResult::PermError(err) => {
                self.auth_results.push_str("permerror");
                err.as_auth_result(&mut self.auth_results);
            }
            DMARCResult::TempError(err) => {
                self.auth_results.push_str("temperror");
                err.as_auth_result(&mut self.auth_results);
            }
            DMARCResult::None => self.auth_results.push_str("none"),
        }
        write!(
            self.auth_results,
            " header.from={} policy.dmarc={}",
            dmarc.domain, dmarc.policy
        )
        .ok();
    }
}

pub trait AsAuthResult {
    fn as_auth_result(&self, header: &mut String);
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
            Error::ARCInvalidInstance => "invalid ARC instance",
            Error::ARCInvalidCV => "invalid ARC cv",
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
        dkim::Signature, dmarc::Policy, ARCOutput, AuthenticatedMessage, DKIMOutput, DKIMResult,
        DMARCOutput, DMARCResult, Error, SPFOutput, SPFResult,
    };

    #[test]
    fn authentication_results() {
        let mut message = AuthenticatedMessage {
            headers: vec![],
            from: vec!["jdoe@example.org".to_string()],
            dkim_output: vec![],
            arc_output: ARCOutput {
                result: DKIMResult::None,
                set: vec![],
            },
            auth_results: "mydomain.org".to_string(),
            received_spf: String::new(),
        };

        for (auth_results, dkim) in [
            (
                "dkim=pass header.d=example.org header.s=myselector",
                DKIMOutput {
                    result: DKIMResult::Pass,
                    signature: Signature {
                        d: "example.org".to_string(),
                        s: "myselector".to_string(),
                        ..Default::default()
                    }
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
                    signature: Signature {
                        d: "example.org".to_string(),
                        s: "myselector".to_string(),
                        b: b"123456".to_vec(),
                        ..Default::default()
                    }
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
                    signature: Signature {
                        d: "atps.example.org".to_string(),
                        s: "otherselctor".to_string(),
                        b: b"abcdef".to_vec(),
                        ..Default::default()
                    }
                    .into(),
                    report: None,
                    is_atps: true,
                },
            ),
        ] {
            message.add_dkim_result(&dkim);
            assert_eq!(
                message.auth_results.rsplit_once(';').unwrap().1.trim(),
                auth_results
            );
        }

        for (auth_results, received_spf, result, ip_addr, receiver, helo, mail_from) in [
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
            message.add_spf_result(
                &SPFOutput {
                    result,
                    report: None,
                    explanation: None,
                },
                ip_addr,
                receiver,
                helo,
                mail_from,
            );
            assert_eq!(
                message.auth_results.rsplit_once(';').unwrap().1.trim(),
                auth_results
            );
            assert_eq!(message.received_spf, received_spf);
            message.received_spf.clear();
        }

        for (auth_results, dmarc) in [
            (
                "dmarc=pass header.from=example.org policy.dmarc=none",
                DMARCOutput {
                    result: DMARCResult::Pass,
                    domain: "example.org".to_string(),
                    policy: Policy::None,
                    record: None,
                },
            ),
            (
                "dmarc=fail (dmarc not aligned) header.from=example.com policy.dmarc=quarantine",
                DMARCOutput {
                    result: DMARCResult::Fail(Error::DMARCNotAligned),
                    domain: "example.com".to_string(),
                    policy: Policy::Quarantine,
                    record: None,
                },
            ),
        ] {
            message.add_dmarc_result(&dmarc);
            assert_eq!(
                message.auth_results.rsplit_once(';').unwrap().1.trim(),
                auth_results
            );
        }

        for (auth_results, arc, remote_ip) in [
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
            message.add_arc_result(
                &ARCOutput {
                    result: arc,
                    set: vec![],
                },
                remote_ip,
            );
            assert_eq!(
                message.auth_results.rsplit_once(';').unwrap().1.trim(),
                auth_results
            );
        }
    }
}
