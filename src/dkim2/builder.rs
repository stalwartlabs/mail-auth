/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Dkim2Signer, Done, Flag, KeyEntry, NeedDomain, NeedSelector};
use crate::common::crypto::DkimKey;

impl Dkim2Signer<NeedDomain> {
    pub fn from_key(key: impl Into<DkimKey>) -> Dkim2Signer<NeedDomain> {
        Dkim2Signer {
            _state: Default::default(),
            keys: vec![KeyEntry {
                key: key.into(),
                selector: String::new(),
            }],
            domain: String::new(),
            flags: Vec::new(),
            nonce: None,
        }
    }

    /// Sets the domain to use for signing.
    pub fn domain(self, domain: impl Into<String>) -> Dkim2Signer<NeedSelector> {
        Dkim2Signer {
            _state: Default::default(),
            keys: self.keys,
            domain: domain.into(),
            flags: self.flags,
            nonce: self.nonce,
        }
    }
}

impl Dkim2Signer<NeedSelector> {
    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<String>) -> Dkim2Signer<Done> {
        if let Some(entry) = self.keys.first_mut() {
            entry.selector = selector.into();
        }
        Dkim2Signer {
            _state: Default::default(),
            keys: self.keys,
            domain: self.domain,
            flags: self.flags,
            nonce: self.nonce,
        }
    }
}

impl Dkim2Signer<Done> {
    /// Adds an additional signing key and selector.
    pub fn additional_key(mut self, key: impl Into<DkimKey>, selector: impl Into<String>) -> Self {
        self.keys.push(KeyEntry {
            key: key.into(),
            selector: selector.into(),
        });
        self
    }

    /// Sets the flags (f= tag) to add to the signature.
    pub fn flags(mut self, flags: impl IntoIterator<Item = Flag>) -> Self {
        for flag in flags {
            if !self.flags.contains(&flag) {
                self.flags.push(flag);
            }
        }
        self
    }

    /// Sets the nonce (n= tag) to add to the signature.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}
