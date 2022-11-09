use mail_parser::decoders::base64::base64_decode_stream;

use crate::{
    common::parse::TagParser,
    dkim::{parse::SignatureParser, Algorithm, Canonicalization},
    Error,
};

use super::{ChainValidation, Results, Seal, Signature};

use crate::common::parse::*;

pub(crate) const CV: u16 = (b'c' as u16) | ((b'v' as u16) << 8);

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut signature = Signature {
            a: Algorithm::RsaSha256,
            d: (b""[..]).into(),
            s: (b""[..]).into(),
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
                        return Err(Error::ARCInvalidInstance);
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
                D => signature.d = header.tag().into(),
                H => signature.h = header.items(),
                L => signature.l = header.number().unwrap_or(0),
                S => signature.s = header.tag().into(),
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

impl<'x> Seal<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> crate::Result<Self> {
        let mut seal = Seal {
            a: Algorithm::RsaSha256,
            d: (b""[..]).into(),
            s: (b""[..]).into(),
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
                D => seal.d = header.tag().into(),
                S => seal.s = header.tag().into(),
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
                        _ => return Err(Error::ARCInvalidCV),
                    }
                    if !header.seek_tag_end() {
                        return Err(Error::ARCInvalidCV);
                    }
                }
                H => {
                    return Err(Error::ARCHasHeaderTag);
                }
                _ => header.ignore(),
            }
        }
        seal.cv = cv.ok_or(Error::ARCInvalidCV)?;

        if !(1..=50).contains(&seal.i) {
            Err(Error::ARCInvalidInstance)
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
            Err(Error::ARCInvalidInstance)
        }
    }
}
