/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Sender Policy Framework (SPF).
//!
//! Implements SPF verification as specified in
//! [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), including the
//! failure reporting extension of
//! [RFC 6652](https://datatracker.ietf.org/doc/html/rfc6652) (`ra=`, `rp=`
//! and `rr=` modifiers).
//!
//! The entry points are [`MessageAuthenticator::verify_spf`] and
//! [`MessageAuthenticator::check_host`], which take [`SpfParameters`] and
//! return an [`SpfOutput`].
//!
//! [`MessageAuthenticator::verify_spf`]: crate::MessageAuthenticator::verify_spf
//! [`MessageAuthenticator::check_host`]: crate::MessageAuthenticator::check_host
//! [`SpfParameters`]: verify::SpfParameters

/// Macro expansion (RFC 7208, Section 7): evaluation of [`Macro`] strings
/// against a set of [`Variables`].
pub mod macros;
/// Verification result types: [`SpfOutput`] and [`SpfResult`].
pub mod output;
/// Parser for `v=spf1` TXT records and `exp=` explanation strings.
pub mod parse;
/// The `check_host()` function (RFC 7208, Section 4) and its parameters.
pub mod verify;

pub(crate) use output::SpfIdentity;
pub use output::{SpfOutput, SpfResult};

use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

/// The qualifier prefix of an SPF directive (RFC 7208, Section 4.6.2).
///
/// ```text
/// "+" pass
/// "-" fail
/// "~" softfail
/// "?" neutral
/// ```
///
/// A directive without a qualifier defaults to [`Qualifier::Pass`]. When the
/// mechanism matches, the qualifier becomes the [`SpfResult`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Qualifier {
    /// `+`: the client is authorized; maps to [`SpfResult::Pass`].
    Pass,
    /// `-`: the client is explicitly not authorized; maps to [`SpfResult::Fail`].
    Fail,
    /// `~`: the client is probably not authorized; maps to [`SpfResult::SoftFail`].
    SoftFail,
    /// `?`: no assertion is made; maps to [`SpfResult::Neutral`].
    Neutral,
}

/// An SPF mechanism (RFC 7208, Section 5).
///
/// ```text
/// mechanism        = ( all / include
///                    / a / mx / ptr / ip4 / ip6 / exists )
/// ```
///
/// Masks are stored as network bitmasks derived from the CIDR prefix length
/// at parse time, not as prefix lengths: a `/24` IPv4 prefix is stored as
/// `0xFFFF_FF00`, a missing prefix as all ones (host match) and `/0` as zero
/// (matches any address). An address matches when
/// `ip & mask == addr & mask`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Mechanism {
    /// `all`: always matches (Section 5.1).
    All,
    /// `include:<domain-spec>`: matches when the SPF record of the target
    /// domain evaluates to `pass` (Section 5.2).
    Include {
        /// Target domain, as a macro string.
        macro_string: Macro,
    },
    /// `a[:<domain-spec>][/<ip4-cidr>][//<ip6-cidr>]`: matches when the client
    /// IP is one of the target domain's A or AAAA addresses (Section 5.3).
    A {
        /// Target domain, as a macro string; [`Macro::None`] means the
        /// current `<domain>`.
        macro_string: Macro,
        /// IPv4 network bitmask built from the `ip4-cidr-length` (default
        /// `/32`, all ones).
        ip4_mask: u32,
        /// IPv6 network bitmask built from the `ip6-cidr-length` (default
        /// `/128`, all ones).
        ip6_mask: u128,
    },
    /// `mx[:<domain-spec>][/<ip4-cidr>][//<ip6-cidr>]`: matches when the client
    /// IP is an address of one of the target domain's MX hosts (Section 5.4).
    Mx {
        /// Target domain, as a macro string; [`Macro::None`] means the
        /// current `<domain>`.
        macro_string: Macro,
        /// IPv4 network bitmask built from the `ip4-cidr-length` (default
        /// `/32`, all ones).
        ip4_mask: u32,
        /// IPv6 network bitmask built from the `ip6-cidr-length` (default
        /// `/128`, all ones).
        ip6_mask: u128,
    },
    /// `ptr[:<domain-spec>]`: matches when a validated reverse DNS name of the
    /// client IP ends in the target domain (Section 5.5; use is discouraged).
    Ptr {
        /// Target domain, as a macro string; [`Macro::None`] means the
        /// current `<domain>`.
        macro_string: Macro,
    },
    /// `ip4:<ip4-network>[/<ip4-cidr>]`: matches when the client IP is in the
    /// given IPv4 network (Section 5.6).
    Ip4 {
        /// Network address.
        addr: Ipv4Addr,
        /// IPv4 network bitmask built from the CIDR prefix length (default
        /// `/32`, all ones).
        mask: u32,
    },
    /// `ip6:<ip6-network>[/<ip6-cidr>]`: matches when the client IP is in the
    /// given IPv6 network (Section 5.6).
    Ip6 {
        /// Network address.
        addr: Ipv6Addr,
        /// IPv6 network bitmask built from the CIDR prefix length (default
        /// `/128`, all ones).
        mask: u128,
    },
    /// `exists:<domain-spec>`: matches when the target name has an A record
    /// (Section 5.7).
    Exists {
        /// Name to look up, as a macro string.
        macro_string: Macro,
    },
}

/// A single SPF directive (RFC 7208, Section 4.6.2).
///
/// ```text
/// directive        = [ qualifier ] mechanism
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Directive {
    /// Result returned when the mechanism matches.
    pub qualifier: Qualifier,
    /// The mechanism to evaluate.
    pub mechanism: Mechanism,
}

/// A macro letter (RFC 7208, Section 7.2).
///
/// ```text
/// s = <sender>
/// l = local-part of <sender>
/// o = domain of <sender>
/// d = <domain>
/// i = <ip>
/// p = the validated domain name of <ip> (do not use)
/// v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
/// h = HELO/EHLO domain
/// ```
///
/// The following macro letters are allowed only in `exp` text:
///
/// ```text
/// c = SMTP client IP (easily readable format)
/// r = domain name of host performing the check
/// t = current timestamp
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Variable {
    /// `s`: the full `<sender>` address.
    Sender = 0,
    /// `l`: the local part of `<sender>`.
    SenderLocalPart = 1,
    /// `o`: the domain of `<sender>`.
    SenderDomainPart = 2,
    /// `d`: the `<domain>` currently being evaluated.
    Domain = 3,
    /// `i`: the client IP, as dotted decimal (IPv4) or dot-separated nibbles
    /// (IPv6).
    Ip = 4,
    /// `p`: the validated domain name of the client IP (use is discouraged).
    ValidatedDomain = 5,
    /// `v`: `in-addr` for IPv4 clients, `ip6` for IPv6 clients.
    IpVersion = 6,
    /// `h`: the HELO or EHLO domain.
    HeloDomain = 7,
    /// `c`: the client IP in readable form (`exp` text only).
    SmtpIp = 8,
    /// `r`: the domain name of the host performing the check (`exp` text only).
    HostDomain = 9,
    /// `t`: the current time in seconds since the Unix epoch (`exp` text only).
    CurrentTime = 10,
}

/// The values substituted for each [`Variable`] during macro expansion
/// (RFC 7208, Section 7).
///
/// [`MessageAuthenticator::check_host`](crate::MessageAuthenticator::check_host)
/// fills it from its [`SpfParameters`](verify::SpfParameters); it can also be
/// built with [`Variables::new`] and the `set_*` methods to expand a
/// [`Macro`] with [`Macro::eval`].
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Variables<'x> {
    vars: [Cow<'x, [u8]>; 11],
    current_time_on_demand: bool,
}

/// A parsed SPF macro string (RFC 7208, Section 7.1).
///
/// Appears as the domain-spec of mechanisms, in the `redirect=` and `exp=`
/// modifiers, and as the explanation text fetched from the `exp=` target.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Macro {
    /// Literal text, copied verbatim.
    Literal(Box<[u8]>),
    /// A `%{...}` macro expansion.
    Variable {
        /// The macro letter.
        letter: Variable,
        /// Number of right-hand parts to keep after splitting; `0` keeps all.
        num_parts: u32,
        /// Reverse the order of the parts (`r` transformer).
        reverse: bool,
        /// URL-encode the result (uppercase macro letter).
        escape: bool,
        /// Bitmask of delimiter characters: bit `n` set means the byte
        /// `b'+' + n` is a delimiter. Defaults to `.` only.
        delimiters: u64,
    },
    /// A concatenation of literals and variables.
    List(Box<[Macro]>),
    /// No macro string was given; [`Macro::eval`] returns the supplied default.
    None,
}

/// A parsed SPF record (RFC 7208, Section 4.5).
///
/// Parsed from a `v=spf1` DNS TXT record published at the domain being
/// checked, or at the target of an `include:` mechanism or `redirect=`
/// modifier.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpfRecord {
    /// Directives in the order they appear in the record.
    pub directives: Box<[Directive]>,
    /// `exp=` modifier: domain whose TXT record holds the explanation for a
    /// `fail` result (Section 6.2).
    pub exp: Option<Macro>,
    /// `redirect=` modifier: domain whose record is evaluated when no
    /// directive matches (Section 6.1).
    pub redirect: Option<Macro>,
    /// `ra=` modifier (RFC 6652): local part of the address that receives
    /// failure reports; the domain is the one being checked.
    pub ra: Option<Box<[u8]>>,
    /// `rp=` modifier (RFC 6652): percentage (0 to 100) of failures to report.
    /// Defaults to 100.
    pub rp: u8,
    /// `rr=` modifier (RFC 6652): bitmask of the result types that trigger a
    /// report (`0x01` temperror or permerror, `0x02` fail, `0x04` softfail,
    /// `0x08` neutral or none). Defaults to all bits set (`rr=all`).
    pub rr: u8,
}

pub(crate) const RR_TEMP_PERM_ERROR: u8 = 0x01;
pub(crate) const RR_FAIL: u8 = 0x02;
pub(crate) const RR_SOFTFAIL: u8 = 0x04;
pub(crate) const RR_NEUTRAL_NONE: u8 = 0x08;

impl Directive {
    /// Creates a directive from a qualifier and a mechanism.
    pub fn new(qualifier: Qualifier, mechanism: Mechanism) -> Self {
        Directive {
            qualifier,
            mechanism,
        }
    }
}

impl Mechanism {
    /// Returns `true` when the mechanism's domain-spec uses the `p` macro,
    /// which requires a PTR lookup of the client IP before expansion.
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
