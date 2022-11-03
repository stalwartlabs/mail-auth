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

use std::{borrow::Cow, fmt::Display};

use rsa::{RsaPrivateKey, RsaPublicKey};

pub mod canonicalize;
pub mod parse;
pub mod sign;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    Relaxed,
    Simple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
}

#[derive(Debug)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    RSA(rsa::errors::Error),
    PKCS(rsa::pkcs1::Error),
    SPKI(rsa::pkcs8::spki::Error),

    /// I/O error
    Io(std::io::Error),

    /// Base64 decode/encode error
    Base64,

    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCanonicalization,

    UnsupportedRecordVersion,
    UnsupportedKeyType,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct DKIMSigner<'x> {
    private_key: RsaPrivateKey,
    sign_headers: Vec<Cow<'x, [u8]>>,
    a: Algorithm,
    d: Cow<'x, [u8]>,
    s: Cow<'x, [u8]>,
    i: Cow<'x, [u8]>,
    l: bool,
    x: u64,
    ch: Canonicalization,
    cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature<'x> {
    v: u32,
    a: Algorithm,
    d: Cow<'x, [u8]>,
    s: Cow<'x, [u8]>,
    b: Vec<u8>,
    bh: Vec<u8>,
    h: Vec<Vec<u8>>,
    z: Vec<Vec<u8>>,
    i: Cow<'x, [u8]>,
    l: u64,
    x: u64,
    t: u64,
    ch: Canonicalization,
    cb: Canonicalization,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Record {
    v: Version,
    h: Vec<Algorithm>,
    p: Key,
    s: Vec<Service>,
    t: Vec<Flag>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Version {
    Dkim1,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Service {
    All,
    Email,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Flag {
    Testing,
    MatchDomain,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Key {
    Rsa(RsaPublicKey),
    Revoked,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError => write!(f, "Parse error"),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::NoHeadersFound => write!(f, "No headers found"),
            Error::RSA(err) => write!(f, "RSA error: {}", err),
            Error::PKCS(err) => write!(f, "PKCS error: {}", err),
            Error::SPKI(err) => write!(f, "SPKI error: {}", err),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Base64 => write!(f, "Base64 encode or decode error."),
            Error::UnsupportedVersion => write!(f, "Unsupported version in DKIM Signature."),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm in DKIM Signature."),
            Error::UnsupportedCanonicalization => {
                write!(f, "Unsupported canonicalization method in DKIM Signature.")
            }
            Error::UnsupportedRecordVersion => {
                write!(f, "Unsupported version in DKIM DNS record.")
            }
            Error::UnsupportedKeyType => {
                write!(f, "Unsupported key type in DKIM DNS record.")
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
