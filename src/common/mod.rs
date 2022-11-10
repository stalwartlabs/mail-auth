use std::borrow::Cow;

use crate::{
    arc::Set,
    dkim::{self},
};

use self::headers::Header;

pub mod headers;
pub mod lru;
pub mod message;
pub mod parse;
pub mod resolver;
pub mod verify;

#[derive(Debug, Clone)]
pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<Cow<'x, str>>,
    pub(crate) dkim_pass: Vec<Header<'x, dkim::Signature<'x>>>,
    pub(crate) dkim_fail: Vec<Header<'x, crate::Error>>,
    pub(crate) arc_pass: Vec<Set<'x>>,
    pub(crate) arc_fail: Vec<Header<'x, crate::Error>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthResult {
    None,
    PermFail(crate::Error),
    TempFail(crate::Error),
    Pass,
}
