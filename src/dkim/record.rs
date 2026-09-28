/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM1 DNS records: the `_domainkey` key record, the RFC 6651 report
//! record and the RFC 6541 ATPS record.

use super::Canonicalization;
use crate::crypto::{Algorithm, VerifyingKey};

/// A DKIM1 public key record (RFC 6376, Section 3.6.1).
///
/// Parsed from the TXT record at `<selector>._domainkey.<domain>` with
/// [`TxtRecordParser::parse`](crate::parse::TxtRecordParser::parse); the
/// verifier fetches it for every signature. Holds the public key (`p=`, of
/// type `k=`) and the `t=` flags.
pub struct DomainKey {
    pub(crate) p: Box<dyn VerifyingKey + Send + Sync>,
    pub(crate) f: u64,
}

/// An RFC 6651 DKIM failure reporting record (RFC 6651, Section 3.3).
///
/// Parsed from the TXT record at `_report._domainkey.<domain>`. The verifier
/// fetches it when a signature with `r=y` does not pass, to decide whether
/// and where to send a failure report (see
/// [`DkimOutput::report_address`](super::DkimOutput::report_address)).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DkimReportRecord {
    pub(crate) ra: String,
    pub(crate) rp: u8,
    pub(crate) rr: u8,
    pub(crate) rs: Option<String>,
}

/// An RFC 6541 Authorized Third-Party Signature record (RFC 6541,
/// Section 4.3).
///
/// Parsed from the TXT record at `<hashed-or-plain-d>._atps.<atps-domain>`.
/// Its existence (with `v=ATPS1`) authorizes the signing domain to sign on
/// behalf of the `atps=` domain.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AtpsRecord {
    pub(crate) d: Option<String>,
}

pub(crate) const R_SVC_ALL: u64 = 0x04;
pub(crate) const R_SVC_EMAIL: u64 = 0x08;
pub(crate) const R_FLAG_TESTING: u64 = 0x10;
pub(crate) const R_FLAG_MATCH_DOMAIN: u64 = 0x20;

pub(crate) const RR_DNS: u8 = 0x01;
pub(crate) const RR_OTHER: u8 = 0x02;
pub(crate) const RR_POLICY: u8 = 0x04;
pub(crate) const RR_SIGNATURE: u8 = 0x08;
pub(crate) const RR_UNKNOWN_TAG: u8 = 0x10;
pub(crate) const RR_VERIFICATION: u8 = 0x20;
pub(crate) const RR_EXPIRATION: u8 = 0x40;

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u64)]
pub(crate) enum Service {
    All = R_SVC_ALL,
    Email = R_SVC_EMAIL,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u64)]
pub(crate) enum Flag {
    Testing = R_FLAG_TESTING,
    MatchDomain = R_FLAG_MATCH_DOMAIN,
}

impl From<Flag> for u64 {
    fn from(v: Flag) -> Self {
        v as u64
    }
}

impl From<Service> for u64 {
    fn from(v: Service) -> Self {
        v as u64
    }
}

impl DomainKey {
    /// Returns `true` when the record has `t=y`: the domain is testing DKIM
    /// and verifiers should not treat failures differently from unsigned
    /// mail (RFC 6376, Section 3.6.1).
    pub fn is_testing(&self) -> bool {
        (self.f & R_FLAG_TESTING) != 0
    }

    /// Returns `true` when the record has `t=s`: the domain of the `i=` tag
    /// must equal `d=` exactly, not a subdomain of it (RFC 6376,
    /// Section 3.6.1).
    pub fn requires_strict_identity(&self) -> bool {
        (self.f & R_FLAG_MATCH_DOMAIN) != 0
    }

    pub(crate) fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        input: &impl VerifySignature,
        canonicalization: Canonicalization,
    ) -> crate::Result<()> {
        self.p.verify(
            headers,
            input.signature(),
            canonicalization,
            input.algorithm(),
        )
    }
}

/// A signature that can be checked against a [`DomainKey`].
///
/// Implemented by DKIM1 [`Signature`](super::Signature) and by ARC seals and
/// message signatures, which share the `_domainkey` key lookup.
pub trait VerifySignature {
    /// Returns the selector (`s=` tag).
    fn selector(&self) -> &str;

    /// Returns the signing domain (`d=` tag).
    fn domain(&self) -> &str;

    /// Returns the decoded signature data (`b=` tag).
    fn signature(&self) -> &[u8];

    /// Returns the signing algorithm (`a=` tag).
    fn algorithm(&self) -> Algorithm;

    /// Returns the fully qualified name of the key record,
    /// `<selector>._domainkey.<domain>.`, with a trailing dot.
    fn domain_key(&self) -> String {
        let s = self.selector();
        let d = self.domain();
        let mut key = String::with_capacity(s.len() + d.len() + 13);
        key.push_str(s);
        key.push_str("._domainkey.");
        key.push_str(d);
        key.push('.');
        key
    }
}
