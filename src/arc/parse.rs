/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_parser::decoders::base64::base64_decode_stream;

use crate::{
    common::{crypto::Algorithm, parse::TagParser},
    dkim::{parse::SignatureParser, Canonicalization},
    Error,
};

use super::{ChainValidation, Results, Seal, Signature};

use crate::common::parse::*;

pub(crate) const CV: u64 = (b'c' as u64) | ((b'v' as u64) << 8);

impl Signature {
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
        let header_len = header.len();
        let mut header = header.iter();

        while let Some(key) = header.key() {
            match key {
                I => {
                    signature.i = header.number().unwrap_or(0) as u32;
                    if !(1..=50).contains(&signature.i) {
                        return Err(Error::ArcInvalidInstance(signature.i));
                    }
                }
                A => {
                    signature.a = header.algorithm()?;
                }
                B => {
                    signature.b =
                        base64_decode_stream(&mut header, header_len, b';').ok_or(Error::Base64)?
                }
                BH => {
                    signature.bh =
                        base64_decode_stream(&mut header, header_len, b';').ok_or(Error::Base64)?
                }
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
        let header_len = header.len();
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
                B => {
                    seal.b =
                        base64_decode_stream(&mut header, header_len, b';').ok_or(Error::Base64)?
                }
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
                        _ => return Err(Error::ArcInvalidCV),
                    }
                    if !header.seek_tag_end() {
                        return Err(Error::ArcInvalidCV);
                    }
                }
                H => {
                    return Err(Error::ArcHasHeaderTag);
                }
                _ => header.ignore(),
            }
        }
        seal.cv = cv.ok_or(Error::ArcInvalidCV)?;

        if !(1..=50).contains(&seal.i) {
            Err(Error::ArcInvalidInstance(seal.i))
        } else if !seal.d.is_empty() && !seal.s.is_empty() && !seal.b.is_empty() {
            Ok(seal)
        } else {
            Err(Error::MissingParameters)
        }
    }
}

impl Results {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut results = Results { i: 0 };
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
            Err(Error::ArcInvalidInstance(results.i))
        }
    }
}
