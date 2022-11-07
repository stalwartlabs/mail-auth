pub mod macros;
pub mod parse;

use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

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
        ip4_cidr_length: u8,
        ip6_cidr_length: u8,
    },
    Mx {
        macro_string: Macro,
        ip4_cidr_length: u8,
        ip6_cidr_length: u8,
    },
    Ptr {
        macro_string: Macro,
    },
    Ip4 {
        addr: Ipv4Addr,
        cidr_length: u8,
    },
    Ip6 {
        addr: Ipv6Addr,
        cidr_length: u8,
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
    modifier         = redirect / explanation / unknown-modifier
*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Modifier {
    Redirect(Macro),
    Explanation(Macro),
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
pub(crate) struct SPF {
    version: Version,
    directives: Vec<Directive>,
    modifiers: Vec<Modifier>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Version {
    Spf1,
}

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    InvalidRecord,
    InvalidIp4,
    InvalidIp6,
    InvalidMacro,
    ParseFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Directive {
    pub fn new(qualifier: Qualifier, mechanism: Mechanism) -> Self {
        Directive {
            qualifier,
            mechanism,
        }
    }
}
