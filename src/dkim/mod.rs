/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::borrow::Cow;

use rsa::RsaPublicKey;

use crate::{
    arc::Set, common::verify::VerifySignature, ARCOutput, DKIMOutput, DKIMResult, Error, Version,
};

pub mod canonicalize;
pub mod headers;
pub mod parse;
pub mod sign;
pub mod verify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    Relaxed,
    Simple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha1 = R_HASH_SHA1,
    Sha256 = R_HASH_SHA256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature<'x> {
    pub(crate) v: u32,
    pub(crate) a: Algorithm,
    pub(crate) d: Cow<'x, str>,
    pub(crate) s: Cow<'x, str>,
    pub(crate) b: Vec<u8>,
    pub(crate) bh: Vec<u8>,
    pub(crate) h: Vec<Cow<'x, str>>,
    pub(crate) z: Vec<Cow<'x, str>>,
    pub(crate) i: Cow<'x, str>,
    pub(crate) l: u64,
    pub(crate) x: u64,
    pub(crate) t: u64,
    pub(crate) r: bool,                      // RFC 6651
    pub(crate) atps: Option<Cow<'x, str>>,   // RFC 6541
    pub(crate) atpsh: Option<HashAlgorithm>, // RFC 6541
    pub(crate) ch: Canonicalization,
    pub(crate) cb: Canonicalization,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::RsaSha256
    }
}

impl Default for Canonicalization {
    fn default() -> Self {
        Canonicalization::Relaxed
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct DomainKey {
    pub(crate) v: Version,
    pub(crate) p: PublicKey,
    pub(crate) f: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Report {
    pub(crate) ra: Option<String>,
    pub(crate) rp: u8,
    pub(crate) rr: u8,
    pub(crate) rs: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Atps {
    pub(crate) v: Version,
    pub(crate) d: Option<String>,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;
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

impl From<HashAlgorithm> for u64 {
    fn from(v: HashAlgorithm) -> Self {
        v as u64
    }
}

impl From<Service> for u64 {
    fn from(v: Service) -> Self {
        v as u64
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    Ed25519(ed25519_dalek::PublicKey),
    Revoked,
}

impl From<Algorithm> for HashAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => HashAlgorithm::Sha256,
            Algorithm::RsaSha1 => HashAlgorithm::Sha1,
        }
    }
}

impl<'x> VerifySignature for Signature<'x> {
    fn b(&self) -> &[u8] {
        &self.b
    }

    fn a(&self) -> Algorithm {
        self.a
    }

    fn s(&self) -> &str {
        &self.s
    }

    fn d(&self) -> &str {
        &self.d
    }
}

impl<'x> DKIMOutput<'x> {
    pub(crate) fn pass() -> Self {
        DKIMOutput {
            result: DKIMResult::Pass,
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn perm_err(err: Error) -> Self {
        DKIMOutput {
            result: DKIMResult::PermError(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn temp_err(err: Error) -> Self {
        DKIMOutput {
            result: DKIMResult::TempError(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn fail(err: Error) -> Self {
        DKIMOutput {
            result: DKIMResult::Fail(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn neutral(err: Error) -> Self {
        DKIMOutput {
            result: DKIMResult::Neutral(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn dns_error(err: Error) -> Self {
        if matches!(&err, Error::DNSError) {
            DKIMOutput::temp_err(err)
        } else {
            DKIMOutput::perm_err(err)
        }
    }

    pub(crate) fn with_signature(mut self, signature: &'x Signature<'x>) -> Self {
        self.signature = signature.into();
        self
    }

    pub(crate) fn with_atps(mut self) -> Self {
        self.is_atps = true;
        self
    }

    pub fn result(&self) -> &DKIMResult {
        &self.result
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature
    }
}

impl<'x> ARCOutput<'x> {
    pub fn result(&self) -> &DKIMResult {
        &self.result
    }

    pub fn sets(&self) -> &[Set] {
        &self.set
    }
}

impl From<Error> for DKIMResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::DNSError) {
            DKIMResult::TempError(err)
        } else {
            DKIMResult::PermError(err)
        }
    }
}
