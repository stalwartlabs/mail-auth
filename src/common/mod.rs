use std::borrow::Cow;

use crate::{
    arc::Set,
    dkim::{self},
};

use self::headers::Header;

pub mod headers;
pub mod message;
pub mod parse;
pub mod verify;

#[derive(Debug, Clone)]
pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<Cow<'x, str>>,
    pub(crate) dkim_headers: Vec<Header<'x, dkim::Signature<'x>>>,
    pub(crate) arc_sets: Vec<Set<'x>>,
    pub(crate) arc_result: AuthResult<'x, ()>,
    pub(crate) dkim_result: AuthResult<'x, dkim::Signature<'x>>,
    pub(crate) phase: AuthPhase,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthPhase {
    Dkim,
    Ams,
    As(usize),
    Done,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthResult<'x, T> {
    None,
    PermFail(Header<'x, crate::Error>),
    TempFail(Header<'x, crate::Error>),
    Pass(T),
}
