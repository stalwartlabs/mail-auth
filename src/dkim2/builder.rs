/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Typestate builder steps of [`Dkim2Signer`].

use super::{Dkim2Signer, Flag, KeyEntry};
use crate::{
    crypto::DkimKey,
    signer::{NeedDomain, NeedSelector, Ready},
};

impl Dkim2Signer<NeedDomain> {
    /// Starts a signer with its first private key (RSA-SHA256 or
    /// Ed25519-SHA256). Continue with [`domain`](Self::domain).
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

    /// Sets the signing domain (`d=`). Its public keys are looked up under
    /// `<selector>._domainkey.<domain>`. Continue with
    /// [`selector`](Dkim2Signer::selector).
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
    /// Sets the selector of the first key, which completes the signer.
    pub fn selector(mut self, selector: impl Into<String>) -> Dkim2Signer<Ready> {
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

impl Dkim2Signer<Ready> {
    /// Adds another signing key under its own selector.
    ///
    /// Each key adds one entry to the `s=` tag of the same signature
    /// (algorithmic dexterity, §8.9). Each key needs a distinct selector,
    /// since the public key record fixes the algorithm.
    pub fn additional_key(mut self, key: impl Into<DkimKey>, selector: impl Into<String>) -> Self {
        self.keys.push(KeyEntry {
            key: key.into(),
            selector: selector.into(),
        });
        self
    }

    /// Adds flags to the `f=` tag of the signature (§8.10). Repeated flags
    /// are added once.
    pub fn flags(mut self, flags: impl IntoIterator<Item = Flag>) -> Self {
        for flag in flags {
            if !self.flags.contains(&flag) {
                self.flags.push(flag);
            }
        }
        self
    }

    /// Sets the nonce (`n=` tag, §8.3): an opaque value meaningful only to
    /// the signer, for example a key to match a returned DSN. Verifiers
    /// reject nonces longer than 64 characters; the value must be printable
    /// ASCII without semicolons.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}
