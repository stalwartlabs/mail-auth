/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Dkim2Signer, Done, Flag, NeedDomain, NeedSelector};
use crate::common::crypto::SigningKey;

impl<T: SigningKey> Dkim2Signer<T> {
    pub fn from_key(key: T) -> Dkim2Signer<T, NeedDomain> {
        Dkim2Signer {
            _state: Default::default(),
            key,
            domain: String::new(),
            selector: String::new(),
            flags: Vec::new(),
            nonce: None,
        }
    }
}

impl<T: SigningKey> Dkim2Signer<T, NeedDomain> {
    /// Sets the domain to use for signing.
    pub fn domain(self, domain: impl Into<String>) -> Dkim2Signer<T, NeedSelector> {
        Dkim2Signer {
            _state: Default::default(),
            key: self.key,
            domain: domain.into(),
            selector: self.selector,
            flags: self.flags,
            nonce: self.nonce,
        }
    }
}

impl<T: SigningKey> Dkim2Signer<T, NeedSelector> {
    /// Sets the selector to use for signing.
    pub fn selector(self, selector: impl Into<String>) -> Dkim2Signer<T, Done> {
        Dkim2Signer {
            _state: Default::default(),
            key: self.key,
            domain: self.domain,
            selector: selector.into(),
            flags: self.flags,
            nonce: self.nonce,
        }
    }
}

impl<T: SigningKey> Dkim2Signer<T, Done> {
    /// Sets the flags (f= tag) to add to the signature.
    pub fn flags(mut self, flags: impl IntoIterator<Item = Flag>) -> Self {
        self.flags = flags.into_iter().collect();
        self
    }

    /// Sets the nonce (n= tag) to add to the signature.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}
