/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

pub mod headers;
pub mod parse;
pub mod seal;
pub mod verify;

use std::borrow::Cow;

use crate::{
    common::{headers::Header, verify::VerifySignature},
    dkim::{Algorithm, Canonicalization},
    ARCOutput, AuthenticationResults, DKIMResult,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature<'x> {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) d: Cow<'x, str>,
    pub(crate) s: Cow<'x, str>,
    pub(crate) b: Vec<u8>,
    pub(crate) bh: Vec<u8>,
    pub(crate) h: Vec<Cow<'x, str>>,
    pub(crate) z: Vec<Cow<'x, str>>,
    pub(crate) l: u64,
    pub(crate) x: u64,
    pub(crate) t: u64,
    pub(crate) ch: Canonicalization,
    pub(crate) cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Seal<'x> {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) b: Vec<u8>,
    pub(crate) d: Cow<'x, str>,
    pub(crate) s: Cow<'x, str>,
    pub(crate) t: u64,
    pub(crate) cv: ChainValidation,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Results {
    pub(crate) i: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARC<'x> {
    pub(crate) signature: Signature<'x>,
    pub(crate) seal: Seal<'x>,
    pub(crate) results: &'x AuthenticationResults<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set<'x> {
    pub(crate) signature: Header<'x, &'x Signature<'x>>,
    pub(crate) seal: Header<'x, &'x Seal<'x>>,
    pub(crate) results: Header<'x, &'x Results>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum ChainValidation {
    None,
    Fail,
    Pass,
}

impl Default for ChainValidation {
    fn default() -> Self {
        ChainValidation::None
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

impl<'x> VerifySignature for Seal<'x> {
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

impl<'x> ARCOutput<'x> {
    pub(crate) fn with_result(mut self, result: DKIMResult) -> Self {
        self.result = result;
        self
    }

    pub fn can_be_sealed(&self) -> bool {
        self.set.is_empty() || self.set.last().unwrap().seal.header.cv != ChainValidation::Fail
    }
}

impl<'x> Default for ARCOutput<'x> {
    fn default() -> Self {
        Self {
            result: DKIMResult::None,
            set: Vec::new(),
        }
    }
}
