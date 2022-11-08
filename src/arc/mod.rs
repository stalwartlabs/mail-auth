pub mod parse;
pub mod verify;

use std::borrow::Cow;

use crate::{
    common::headers::Header,
    dkim::{Algorithm, Canonicalization},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature<'x> {
    pub(crate) i: u32,
    a: Algorithm,
    d: Cow<'x, [u8]>,
    s: Cow<'x, [u8]>,
    b: Vec<u8>,
    bh: Vec<u8>,
    h: Vec<Vec<u8>>,
    z: Vec<Vec<u8>>,
    l: u64,
    x: u64,
    t: u64,
    ch: Canonicalization,
    cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Seal<'x> {
    pub(crate) i: u32,
    a: Algorithm,
    b: Vec<u8>,
    d: Cow<'x, [u8]>,
    s: Cow<'x, [u8]>,
    t: u64,
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

#[derive(Debug)]
pub enum Error {
    ParseError,
    InvalidInstance,
    InvalidChainValidation,
    MissingParameters,
    Base64,
    HasHeaderTag,
    BrokenArcChain,
    DKIM(crate::dkim::Error),
}

impl From<crate::dkim::Error> for Error {
    fn from(err: crate::dkim::Error) -> Self {
        Error::DKIM(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
