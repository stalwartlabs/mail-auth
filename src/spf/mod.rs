pub mod parse;

use std::net::{Ipv4Addr, Ipv6Addr};

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
        domain_spec: DomainSpec,
    },
    A {
        domain_spec: DomainSpec,
        ip4_cidr_length: u8,
        ip6_cidr_length: u8,
    },
    Mx {
        domain_spec: DomainSpec,
        ip4_cidr_length: u8,
        ip6_cidr_length: u8,
    },
    Ptr {
        domain_spec: DomainSpec,
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
        domain_spec: DomainSpec,
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
    Redirect(DomainSpec),
    Explanation(DomainSpec),
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Macro {
    Sender,
    SenderLocalPart,
    SenderDomainPart,
    Domain,
    Ip,
    ValidatedDomain,
    IpVersion,
    HeloDomain,
    SmtpIp,
    HostDomain,
    CurrentTime,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum DomainSpec {
    Literal(Vec<u8>),
    Macro {
        letter: Macro,
        num_parts: u32,
        reverse: bool,
        delimiters: Vec<u8>,
    },
    List(Vec<DomainSpec>),
    None,
}

/*
    terms            = *( 1*SP ( directive / modifier ) )
*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Term {
    Directive(Directive),
    Modifier(Modifier),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct SPF {
    version: Version,
    terms: Vec<Term>,
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
