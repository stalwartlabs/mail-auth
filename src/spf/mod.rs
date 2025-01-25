/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod macros;
pub mod parse;
pub mod verify;

use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{is_within_pct, SpfOutput, SpfResult, Version};

/*
      "+" pass
      "-" fail
      "~" softfail
      "?" neutral
*/

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Qualifier {
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
pub enum Mechanism {
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
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
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
pub enum Variable {
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
pub struct Variables<'x> {
    vars: [Cow<'x, [u8]>; 11],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Macro {
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
pub struct Spf {
    pub version: Version,
    pub directives: Vec<Directive>,
    pub exp: Option<Macro>,
    pub redirect: Option<Macro>,
    pub ra: Option<Vec<u8>>,
    pub rp: u8,
    pub rr: u8,
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

impl TryFrom<&str> for SpfResult {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("pass") {
            Ok(SpfResult::Pass)
        } else if value.eq_ignore_ascii_case("fail") {
            Ok(SpfResult::Fail)
        } else if value.eq_ignore_ascii_case("softfail") {
            Ok(SpfResult::SoftFail)
        } else if value.eq_ignore_ascii_case("neutral") {
            Ok(SpfResult::Neutral)
        } else if value.eq_ignore_ascii_case("temperror") {
            Ok(SpfResult::TempError)
        } else if value.eq_ignore_ascii_case("permerror") {
            Ok(SpfResult::PermError)
        } else if value.eq_ignore_ascii_case("none") {
            Ok(SpfResult::None)
        } else {
            Err(())
        }
    }
}

impl TryFrom<String> for SpfResult {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        TryFrom::try_from(value.as_str())
    }
}

impl SpfOutput {
    pub fn new(domain: String) -> Self {
        SpfOutput {
            result: SpfResult::None,
            report: None,
            explanation: None,
            domain,
        }
    }

    pub fn with_result(mut self, result: SpfResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_report(mut self, spf: &Spf) -> Self {
        match &spf.ra {
            Some(ra) if is_within_pct(spf.rp) => {
                if match self.result {
                    SpfResult::Fail => (spf.rr & RR_FAIL) != 0,
                    SpfResult::SoftFail => (spf.rr & RR_SOFTFAIL) != 0,
                    SpfResult::Neutral | SpfResult::None => (spf.rr & RR_NEUTRAL_NONE) != 0,
                    SpfResult::TempError | SpfResult::PermError => {
                        (spf.rr & RR_TEMP_PERM_ERROR) != 0
                    }
                    SpfResult::Pass => false,
                } {
                    self.report = format!("{}@{}", String::from_utf8_lossy(ra), self.domain).into();
                }
            }
            _ => (),
        }
        self
    }

    pub fn with_explanation(mut self, explanation: String) -> Self {
        self.explanation = explanation.into();
        self
    }

    pub fn result(&self) -> SpfResult {
        self.result
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    pub fn report_address(&self) -> Option<&str> {
        self.report.as_deref()
    }
}
