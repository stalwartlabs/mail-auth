/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcAuthResults, ArcError, ChainValidation, Seal, Signature};
use crate::parse::*;
use crate::{
    Error,
    crypto::Algorithm,
    dkim::{Canonicalization, parse::SignatureParser},
    parse::TagParser,
};

pub(crate) const CV: u64 = (b'c' as u64) | ((b'v' as u64) << 8);

impl Signature {
    /// Parses the value of an `ARC-Message-Signature` header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Arc`] with [`ArcError::InvalidInstance`] when `i=` is
    /// present and outside 1 to 50 (a missing `i=` parses as 0 and is
    /// rejected by `verify_arc`), [`Error::Base64`] when `b=` or `bh=` is not valid
    /// base64, [`Error::MissingParameters`] when `d=`, `s=`, `b=`, `bh=` or
    /// `h=` is missing, and [`Error::Dkim`] with
    /// [`DkimError::UnsupportedAlgorithm`](crate::dkim::DkimError::UnsupportedAlgorithm)
    /// or
    /// [`DkimError::UnsupportedCanonicalization`](crate::dkim::DkimError::UnsupportedCanonicalization)
    /// for an unknown `a=` or `c=` value.
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut signature = Signature {
            a: Algorithm::RsaSha256,
            d: "".into(),
            s: "".into(),
            b: Vec::with_capacity(0),
            bh: Vec::with_capacity(0),
            h: Vec::with_capacity(0),
            z: Vec::with_capacity(0),
            l: 0,
            x: 0,
            t: 0,
            i: 0,
            ch: Canonicalization::Simple,
            cb: Canonicalization::Simple,
        };
        let mut header = header.iter();

        while let Some(key) = header.key() {
            match key {
                I => {
                    signature.i = header.number().unwrap_or(0) as u32;
                    if !(1..=50).contains(&signature.i) {
                        return Err(Error::Arc(ArcError::InvalidInstance(signature.i)));
                    }
                }
                A => {
                    signature.a = header.algorithm()?;
                }
                B => signature.b = header.base64().ok_or(Error::Base64)?,
                BH => signature.bh = header.base64().ok_or(Error::Base64)?,
                C => {
                    let (ch, cb) = header.canonicalization(Canonicalization::Simple)?;
                    signature.ch = ch;
                    signature.cb = cb;
                }
                D => signature.d = header.text(true),
                H => signature.h = header.items(),
                L => signature.l = header.number().unwrap_or(0),
                S => signature.s = header.text(true),
                T => signature.t = header.number().unwrap_or(0),
                X => signature.x = header.number().unwrap_or(0),
                Z => signature.z = header.headers_qp(),
                _ => header.ignore(),
            }
        }

        if !signature.d.is_empty()
            && !signature.s.is_empty()
            && !signature.b.is_empty()
            && !signature.bh.is_empty()
            && !signature.h.is_empty()
        {
            Ok(signature)
        } else {
            Err(Error::MissingParameters)
        }
    }
}

impl Seal {
    /// Parses the value of an `ARC-Seal` header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Arc`] with [`ArcError::InvalidInstance`] when `i=` is
    /// outside 1 to 50, [`ArcError::InvalidChainValidation`] when `cv=` is
    /// missing or not `none`, `fail` or `pass`, and [`ArcError::HasHeaderTag`]
    /// when an `h=` tag is present; [`Error::Base64`] when `b=` is not valid
    /// base64, [`Error::MissingParameters`] when `d=`, `s=` or `b=` is
    /// missing, and [`Error::Dkim`] with
    /// [`DkimError::UnsupportedAlgorithm`](crate::dkim::DkimError::UnsupportedAlgorithm)
    /// for an unknown `a=` value.
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut seal = Seal {
            a: Algorithm::RsaSha256,
            d: "".into(),
            s: "".into(),
            b: Vec::with_capacity(0),
            t: 0,
            i: 0,
            cv: ChainValidation::None,
        };
        let mut header = header.iter();
        let mut cv = None;

        while let Some(key) = header.key() {
            match key {
                I => {
                    seal.i = header.number().unwrap_or(0) as u32;
                }
                A => {
                    seal.a = header.algorithm()?;
                }
                B => seal.b = header.base64().ok_or(Error::Base64)?,
                D => seal.d = header.text(true),
                S => seal.s = header.text(true),
                T => seal.t = header.number().unwrap_or(0),
                CV => {
                    match header.next_skip_whitespaces().unwrap_or(0) {
                        b'n' | b'N' if header.match_bytes(b"one") => {
                            cv = ChainValidation::None.into();
                        }
                        b'f' | b'F' if header.match_bytes(b"ail") => {
                            cv = ChainValidation::Fail.into();
                        }
                        b'p' | b'P' if header.match_bytes(b"ass") => {
                            cv = ChainValidation::Pass.into();
                        }
                        _ => return Err(Error::Arc(ArcError::InvalidChainValidation)),
                    }
                    if !header.seek_tag_end() {
                        return Err(Error::Arc(ArcError::InvalidChainValidation));
                    }
                }
                H => {
                    return Err(Error::Arc(ArcError::HasHeaderTag));
                }
                _ => header.ignore(),
            }
        }
        seal.cv = cv.ok_or(Error::Arc(ArcError::InvalidChainValidation))?;

        if !(1..=50).contains(&seal.i) {
            Err(Error::Arc(ArcError::InvalidInstance(seal.i)))
        } else if !seal.d.is_empty() && !seal.s.is_empty() && !seal.b.is_empty() {
            Ok(seal)
        } else {
            Err(Error::MissingParameters)
        }
    }
}

impl ArcAuthResults {
    /// Parses the value of an `ARC-Authentication-Results` header, reading
    /// only its `i=` tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Arc`] with [`ArcError::InvalidInstance`] when `i=` is
    /// missing or outside 1 to 50.
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut results = ArcAuthResults { i: 0 };
        let mut header = header.iter();

        while let Some(key) = header.key() {
            match key {
                I => {
                    results.i = header.number().unwrap_or(0) as u32;
                    break;
                }
                _ => header.ignore(),
            }
        }

        if (1..=50).contains(&results.i) {
            Ok(results)
        } else {
            Err(Error::Arc(ArcError::InvalidInstance(results.i)))
        }
    }
}
