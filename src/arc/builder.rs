/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use sha2::Sha256;

use crate::{
    common::crypto::SigningKey,
    dkim::{Canonicalization, Done, NeedDomain, NeedHeaders, NeedSelector},
};

use super::{ArcSealer, Seal, Signature};

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T> {
    pub fn from_key(key: T) -> ArcSealer<T, NeedDomain> {
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

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, NeedDomain> {
    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: impl Into<String> + Clone) -> ArcSealer<T, NeedSelector> {
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

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, NeedSelector> {
    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<String> + Clone) -> ArcSealer<T, NeedHeaders> {
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

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, NeedHeaders> {
    /// Sets the headers to sign.
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<String>>,
    ) -> ArcSealer<T, Done> {
        self.signature.h = headers.into_iter().map(|h| h.into()).collect();
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, Done> {
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
