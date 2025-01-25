/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::common::crypto::{HashAlgorithm, SigningKey};

use super::{Canonicalization, DkimSigner, Done, NeedDomain, NeedHeaders, NeedSelector, Signature};

impl<T: SigningKey> DkimSigner<T> {
    pub fn from_key(key: T) -> DkimSigner<T, NeedDomain> {
        DkimSigner {
            _state: Default::default(),
            template: Signature {
                v: 1,
                a: key.algorithm(),
                ..Default::default()
            },
            key,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedDomain> {
    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: impl Into<String>) -> DkimSigner<T, NeedSelector> {
        self.template.d = domain.into();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedSelector> {
    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<String>) -> DkimSigner<T, NeedHeaders> {
        self.template.s = selector.into();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedHeaders> {
    /// Sets the headers to sign.
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<String>>,
    ) -> DkimSigner<T, Done> {
        self.template.h = headers.into_iter().map(|h| h.into()).collect();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, Done> {
    /// Sets the third party signature.
    pub fn atps(mut self, atps: impl Into<String>) -> Self {
        self.template.atps = Some(atps.into());
        self
    }

    /// Sets the third-party signature hashing algorithm.
    pub fn atpsh(mut self, atpsh: HashAlgorithm) -> Self {
        self.template.atpsh = atpsh.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn agent_user_identifier(mut self, auid: impl Into<String>) -> Self {
        self.template.i = auid.into();
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.template.x = expiration;
        self
    }

    /// Include the body length in the signature.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.template.l = u64::from(body_length);
        self
    }

    /// Request reports.
    pub fn reporting(mut self, reporting: bool) -> Self {
        self.template.r = reporting;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.template.ch = ch;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.template.cb = cb;
        self
    }
}
