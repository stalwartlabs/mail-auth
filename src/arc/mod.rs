/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod builder;
pub mod headers;
pub mod parse;
pub mod seal;
pub mod verify;

use crate::{
    common::{
        crypto::{Algorithm, Sha256, SigningKey},
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
    pub i: u32,
    pub a: Algorithm,
    pub d: String,
    pub s: String,
    pub b: Vec<u8>,
    pub bh: Vec<u8>,
    pub h: Vec<String>,
    pub z: Vec<String>,
    pub l: u64,
    pub x: u64,
    pub t: u64,
    pub ch: Canonicalization,
    pub cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Seal {
    pub i: u32,
    pub a: Algorithm,
    pub b: Vec<u8>,
    pub d: String,
    pub s: String,
    pub t: u64,
    pub cv: ChainValidation,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Results {
    pub i: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcSet<'x> {
    pub signature: Signature,
    pub seal: Seal,
    pub results: &'x AuthenticationResults<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set<'x> {
    pub signature: Header<'x, &'x Signature>,
    pub seal: Header<'x, &'x Seal>,
    pub results: Header<'x, &'x Results>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum ChainValidation {
    #[default]
    None,
    Fail,
    Pass,
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
    pub fn with_result(mut self, result: DkimResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_set(mut self, set: Set<'x>) -> Self {
        self.set.push(set);
        self
    }

    pub fn can_be_sealed(&self) -> bool {
        self.set.is_empty() || self.set.last().unwrap().seal.header.cv != ChainValidation::Fail
    }
}

impl Default for ArcOutput<'_> {
    fn default() -> Self {
        Self {
            result: DkimResult::None,
            set: Vec::new(),
        }
    }
}
