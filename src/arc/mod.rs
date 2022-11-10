pub mod parse;

use std::borrow::Cow;

use crate::{
    common::{headers::Header, verify::VerifySignature},
    dkim::{Algorithm, Canonicalization},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature<'x> {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) d: Cow<'x, [u8]>,
    pub(crate) s: Cow<'x, [u8]>,
    pub(crate) b: Vec<u8>,
    pub(crate) bh: Vec<u8>,
    pub(crate) h: Vec<Vec<u8>>,
    pub(crate) z: Vec<Vec<u8>>,
    pub(crate) l: u64,
    pub(crate) x: u64,
    pub(crate) t: u64,
    pub(crate) ch: Canonicalization,
    pub(crate) cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Seal<'x> {
    pub(crate) i: u32,
    pub(crate) a: Algorithm,
    pub(crate) b: Vec<u8>,
    pub(crate) d: Cow<'x, [u8]>,
    pub(crate) s: Cow<'x, [u8]>,
    pub(crate) t: u64,
    pub(crate) cv: ChainValidation,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Results {
    pub(crate) i: u32,
}

#[derive(Debug, Clone)]
pub struct Set<'x> {
    pub(crate) signature: Header<'x, Signature<'x>>,
    pub(crate) seal: Header<'x, Seal<'x>>,
    pub(crate) results: Header<'x, Results>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ChainValidation {
    None,
    Fail,
    Pass,
}

impl<'x> VerifySignature for Signature<'x> {
    fn b(&self) -> &[u8] {
        &self.b
    }

    fn a(&self) -> Algorithm {
        self.a
    }

    fn s(&self) -> &[u8] {
        &self.s
    }

    fn d(&self) -> &[u8] {
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

    fn s(&self) -> &[u8] {
        &self.s
    }

    fn d(&self) -> &[u8] {
        &self.d
    }
}
