pub mod macros;
pub mod parse;
pub mod verify;

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{is_within_pct, SPFOutput, SPFResult, Version};

/*
      "+" pass
      "-" fail
      "~" softfail
      "?" neutral
*/

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

/*
   mechanism        = ( all / include
                      / a / mx / ptr / ip4 / ip6 / exists )
*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Mechanism {
    All,
    Include {
        macro_string: Macro,
    },
    A {
        macro_string: Macro,
        ip4_mask: u32,
        ip6_mask: u128,
    },
    Mx {
        macro_string: Macro,
        ip4_mask: u32,
        ip6_mask: u128,
    },
    Ptr {
        macro_string: Macro,
    },
    Ip4 {
        addr: Ipv4Addr,
        mask: u32,
    },
    Ip6 {
        addr: Ipv6Addr,
        mask: u128,
    },
    Exists {
        macro_string: Macro,
    },
}

/*
    directive        = [ qualifier ] mechanism
*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Directive {
    pub(crate) qualifier: Qualifier,
    pub(crate) mechanism: Mechanism,
}

/*
      s = <sender>
      l = local-part of <sender>
      o = domain of <sender>
      d = <domain>
      i = <ip>
      p = the validated domain name of <ip> (do not use)
      v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
      h = HELO/EHLO domain
   The following macro letters are allowed only in "exp" text:

      c = SMTP client IP (easily readable format)
      r = domain name of host performing the check
      t = current timestamp
*/

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum Variable {
    Sender = 0,
    SenderLocalPart = 1,
    SenderDomainPart = 2,
    Domain = 3,
    Ip = 4,
    ValidatedDomain = 5,
    IpVersion = 6,
    HeloDomain = 7,
    SmtpIp = 8,
    HostDomain = 9,
    CurrentTime = 10,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct Variables<'x> {
    vars: [Cow<'x, [u8]>; 11],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Macro {
    Literal(Vec<u8>),
    Variable {
        letter: Variable,
        num_parts: u32,
        reverse: bool,
        escape: bool,
        delimiters: u64,
    },
    List(Vec<Macro>),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SPF {
    version: Version,
    directives: Vec<Directive>,
    exp: Option<Macro>,
    redirect: Option<Macro>,
    ra: Option<Vec<u8>>,
    rp: u8,
    rr: u8,
}

pub(crate) const RR_TEMP_PERM_ERROR: u8 = 0x01;
pub(crate) const RR_FAIL: u8 = 0x02;
pub(crate) const RR_SOFTFAIL: u8 = 0x04;
pub(crate) const RR_NEUTRAL_NONE: u8 = 0x08;

impl Directive {
    pub fn new(qualifier: Qualifier, mechanism: Mechanism) -> Self {
        Directive {
            qualifier,
            mechanism,
        }
    }
}

impl Mechanism {
    pub fn needs_ptr(&self) -> bool {
        match self {
            Mechanism::All
            | Mechanism::Ip4 { .. }
            | Mechanism::Ip6 { .. }
            | Mechanism::Ptr { .. } => false,
            Mechanism::Include { macro_string } => macro_string.needs_ptr(),
            Mechanism::A { macro_string, .. } => macro_string.needs_ptr(),
            Mechanism::Mx { macro_string, .. } => macro_string.needs_ptr(),
            Mechanism::Exists { macro_string } => macro_string.needs_ptr(),
        }
    }
}

impl TryFrom<&str> for SPFResult {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("pass") {
            Ok(SPFResult::Pass)
        } else if value.eq_ignore_ascii_case("fail") {
            Ok(SPFResult::Fail)
        } else if value.eq_ignore_ascii_case("softfail") {
            Ok(SPFResult::SoftFail)
        } else if value.eq_ignore_ascii_case("neutral") {
            Ok(SPFResult::Neutral)
        } else if value.eq_ignore_ascii_case("temperror") {
            Ok(SPFResult::TempError)
        } else if value.eq_ignore_ascii_case("permerror") {
            Ok(SPFResult::PermError)
        } else if value.eq_ignore_ascii_case("none") {
            Ok(SPFResult::None)
        } else {
            Err(())
        }
    }
}

impl TryFrom<String> for SPFResult {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        TryFrom::try_from(value.as_str())
    }
}

impl SPFOutput {
    pub(crate) fn new(domain: &str, ip_addr: IpAddr) -> Self {
        SPFOutput {
            domain: domain.to_string(),
            ip_addr,
            result: SPFResult::None,
            report: None,
            explanation: None,
        }
    }

    pub(crate) fn with_result(mut self, result: SPFResult) -> Self {
        self.result = result;
        self
    }

    pub(crate) fn with_report(mut self, spf: &SPF) -> Self {
        match &spf.ra {
            Some(ra) if is_within_pct(spf.rp) => {
                if match self.result {
                    SPFResult::Fail => (spf.rr & RR_FAIL) != 0,
                    SPFResult::SoftFail => (spf.rr & RR_SOFTFAIL) != 0,
                    SPFResult::Neutral | SPFResult::None => (spf.rr & RR_NEUTRAL_NONE) != 0,
                    SPFResult::TempError | SPFResult::PermError => {
                        (spf.rr & RR_TEMP_PERM_ERROR) != 0
                    }
                    SPFResult::Pass => false,
                } {
                    self.report = format!("{}@{}", String::from_utf8_lossy(ra), self.domain).into();
                }
            }
            _ => (),
        }
        self
    }

    pub(crate) fn with_explanation(mut self, explanation: String) -> Self {
        self.explanation = explanation.into();
        self
    }

    pub fn result(&self) -> SPFResult {
        self.result
    }

    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    pub fn report_address(&self) -> Option<&str> {
        self.report.as_deref()
    }
}
