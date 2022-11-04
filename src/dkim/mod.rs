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
pub mod verify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    Relaxed,
    Simple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

#[derive(Debug)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    RSA(rsa::errors::Error),
    PKCS(rsa::pkcs1::Error),
    Ed25519Signature(ed25519_dalek::SignatureError),
    Ed25519(ed25519_dalek::ed25519::Error),

    /// I/O error
    Io(std::io::Error),

    /// Base64 decode/encode error
    Base64,

    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCanonicalization,

    UnsupportedRecordVersion,
    UnsupportedKeyType,

    FailedBodyHashMatch,
    RevokedPublicKey,
    IncompatibleAlgorithms,
    FailedVerification,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct DKIMSigner<'x> {
    private_key: PrivateKey,
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
pub struct Record {
    v: Version,
    h: Vec<HashAlgorithm>,
    p: PublicKey,
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

#[derive(Debug)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::Keypair),
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    Ed25519(ed25519_dalek::PublicKey),
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
            Error::Ed25519Signature(err) => write!(f, "Ed25519 signature error: {}", err),
            Error::Ed25519(err) => write!(f, "Ed25519 error: {}", err),
            Error::FailedBodyHashMatch => {
                write!(f, "Calculated body hash does not match signature hash.")
            }
            Error::RevokedPublicKey => write!(f, "Public key for this signature has been revoked."),
            Error::IncompatibleAlgorithms => write!(
                f,
                "Incompatible algorithms used in signature and DKIM DNS record."
            ),
            Error::FailedVerification => write!(f, "Signature verification failed."),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
