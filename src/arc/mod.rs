pub mod parse;

use crate::{
    common::{headers::Header, verify::VerifySignature},
    dkim::{Algorithm, Canonicalization},
};

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
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
pub struct Set<'x> {
    pub(crate) signature: Header<'x, Signature>,
    pub(crate) seal: Header<'x, Seal>,
    pub(crate) results: Header<'x, Results>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ChainValidation {
    None,
    Fail,
    Pass,
}

impl VerifySignature for Signature {
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

impl VerifySignature for Seal {
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
