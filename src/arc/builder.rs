/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{ArcSealer, Seal, Signature};
use crate::{
    crypto::{Sha256, SigningKey},
    dkim::Canonicalization,
    signer::{NeedDomain, NeedHeaders, NeedSelector, Ready},
};
use std::time::Duration;

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T> {
    /// Creates a sealer from a SHA-256 signing key. The `a=` algorithm of
    /// both headers is taken from the key.
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
    /// Sets the signing domain (`d=` of both the `ARC-Seal` and the
    /// `ARC-Message-Signature`).
    pub fn domain(mut self, domain: impl Into<String>) -> ArcSealer<T, NeedSelector> {
        let domain = domain.into();
        self.seal.d = domain.clone();
        self.signature.d = domain;
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, NeedSelector> {
    /// Sets the selector (`s=` of both headers); verifiers fetch the key from
    /// `<selector>._domainkey.<domain>`.
    pub fn selector(mut self, selector: impl Into<String>) -> ArcSealer<T, NeedHeaders> {
        let selector = selector.into();
        self.seal.s = selector.clone();
        self.signature.s = selector;
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, NeedHeaders> {
    /// Sets the names of the header fields covered by the
    /// `ARC-Message-Signature` (`h=`). Names are matched case-insensitively;
    /// names absent from the message are still listed, which prevents them
    /// from being added later.
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<String>>,
    ) -> ArcSealer<T, Ready> {
        self.signature.h = headers.into_iter().map(|h| h.into()).collect();
        ArcSealer {
            _state: Default::default(),
            key: self.key,
            signature: self.signature,
            seal: self.seal,
        }
    }
}

impl<T: SigningKey<Hasher = Sha256>> ArcSealer<T, Ready> {
    /// Sets the `ARC-Message-Signature` validity period, counted from the
    /// sealing time (`x=`), rounded up to whole seconds and capped at
    /// `u64::MAX`. A zero duration, the default, omits the `x=` tag.
    pub fn expiration(mut self, expiration: Duration) -> Self {
        self.signature.x = expiration
            .as_secs()
            .saturating_add(u64::from(expiration.subsec_nanos() > 0));
        self
    }

    /// Includes the body length (`l=`) in the `ARC-Message-Signature` when
    /// `true`. Off by default; not recommended, since content can be appended
    /// after the signed length.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.signature.l = u64::from(body_length);
        self
    }

    /// Sets the header canonicalization of the `ARC-Message-Signature`
    /// (default `relaxed`). The `ARC-Seal` always uses `relaxed`.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.signature.ch = ch;
        self
    }

    /// Sets the body canonicalization of the `ARC-Message-Signature`
    /// (default `relaxed`).
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.signature.cb = cb;
        self
    }
}
