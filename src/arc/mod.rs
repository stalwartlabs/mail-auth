/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

pub mod builder;
pub mod headers;
pub mod parse;
pub mod seal;
pub mod verify;

use sha2::Sha256;

use crate::{
    common::{
        crypto::{Algorithm, SigningKey},
        headers::Header,
        verify::VerifySignature,
    },
    dkim::{Canonicalization, NeedDomain},
    ArcOutput, AuthenticationResults, DkimResult,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ArcSealer<T: SigningKey<Hasher = Sha256>, State = NeedDomain> {
    _state: std::marker::PhantomData<State>,
    pub(crate) key: T,
    pub(crate) signature: Signature,
    pub(crate) seal: Seal,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) d: String,
    pub(crate) s: String,
    pub(crate) b: Vec<u8>,
    pub(crate) bh: Vec<u8>,
    pub(crate) h: Vec<String>,
    pub(crate) z: Vec<String>,
    pub(crate) l: u64,
    pub(crate) x: u64,
    pub(crate) t: u64,
    pub(crate) ch: Canonicalization,
    pub(crate) cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Seal {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) b: Vec<u8>,
    pub(crate) d: String,
    pub(crate) s: String,
    pub(crate) t: u64,
    pub(crate) cv: ChainValidation,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Results {
    pub(crate) i: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcSet<'x> {
    pub(crate) signature: Signature,
    pub(crate) seal: Seal,
    pub(crate) results: &'x AuthenticationResults<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set<'x> {
    pub(crate) signature: Header<'x, &'x Signature>,
    pub(crate) seal: Header<'x, &'x Seal>,
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

impl VerifySignature for Signature {
    fn signature(&self) -> &[u8] {
        &self.b
    }

    fn algorithm(&self) -> Algorithm {
        self.a
    }

    fn selector(&self) -> &str {
        &self.s
    }

    fn domain(&self) -> &str {
        &self.d
    }
}

impl VerifySignature for Seal {
    fn signature(&self) -> &[u8] {
        &self.b
    }

    fn algorithm(&self) -> Algorithm {
        self.a
    }

    fn selector(&self) -> &str {
        &self.s
    }

    fn domain(&self) -> &str {
        &self.d
    }
}

impl<'x> ArcOutput<'x> {
    pub(crate) fn with_result(mut self, result: DkimResult) -> Self {
        self.result = result;
        self
    }

    pub fn can_be_sealed(&self) -> bool {
        self.set.is_empty() || self.set.last().unwrap().seal.header.cv != ChainValidation::Fail
    }
}

impl<'x> Default for ArcOutput<'x> {
    fn default() -> Self {
        Self {
            result: DkimResult::None,
            set: Vec::new(),
        }
    }
}
