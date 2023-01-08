use std::borrow::Cow;

use sha2::Sha256;

use crate::{
    common::crypto::SigningKey,
    dkim::{Canonicalization, Done, NeedDomain, NeedHeaders, NeedSelector},
};

use super::{ArcSealer, Seal, Signature};

impl<'x, T: SigningKey<Hasher = Sha256>> ArcSealer<'x, T> {
    pub fn from_key(key: T) -> ArcSealer<'x, T, NeedDomain> {
        ArcSealer {
            _state: Default::default(),
            signature: Signature {
                a: key.algorithm(),
                ..Default::default()
            },
            seal: Seal {
                a: key.algorithm(),
                ..Default::default()
            },
            key,
        }
    }
}

impl<'x, T: SigningKey<Hasher = Sha256>> ArcSealer<'x, T, NeedDomain> {
    /// Sets the domain to use for signing.
    pub fn domain(
        mut self,
        domain: impl Into<Cow<'x, str>> + Clone,
    ) -> ArcSealer<'x, T, NeedSelector> {
        self.signature.d = domain.clone().into();
        self.seal.d = domain.into();
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<'x, T: SigningKey<Hasher = Sha256>> ArcSealer<'x, T, NeedSelector> {
    /// Sets the selector to use for signing.
    pub fn selector(
        mut self,
        selector: impl Into<Cow<'x, str>> + Clone,
    ) -> ArcSealer<'x, T, NeedHeaders> {
        self.signature.s = selector.clone().into();
        self.seal.s = selector.into();
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<'x, T: SigningKey<Hasher = Sha256>> ArcSealer<'x, T, NeedHeaders> {
    /// Sets the headers to sign.
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<Cow<'x, str>>>,
    ) -> ArcSealer<'x, T, Done> {
        self.signature.h = headers.into_iter().map(|h| h.into()).collect();
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<'x, T: SigningKey<Hasher = Sha256>> ArcSealer<'x, T, Done> {
    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.signature.x = expiration;
        self
    }

    /// Include the body length in the signature.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.signature.l = u64::from(body_length);
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.signature.ch = ch;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.signature.cb = cb;
        self
    }
}
