/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Typestate builder steps of [`Dkim2Signer`].

use super::{Dkim2Hash, Dkim2Signer, Flag, KeyEntry};
use crate::{
    crypto::DkimKey,
    signer::{NeedDomain, NeedSelector, Ready},
};

impl Dkim2Signer<NeedDomain> {
    /// Starts a signer with its first private key (RSA-SHA256,
    /// Ed25519-SHA256 or MLDSA44-Ed25519-SHA512). Continue with
    /// [`domain`](Self::domain).
    pub fn from_key(key: impl Into<DkimKey>) -> Dkim2Signer<NeedDomain> {
        Dkim2Signer {
            _state: Default::default(),
            keys: vec![KeyEntry {
                key: key.into(),
                selector: String::new(),
            }],
            domain: String::new(),
            hashes: vec![Dkim2Hash::Sha256],
            flags: Vec::new(),
            nonce: None,
            out_of_band: false,
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
            hashes: self.hashes,
            flags: self.flags,
            nonce: self.nonce,
            out_of_band: self.out_of_band,
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
            hashes: self.hashes,
            flags: self.flags,
            nonce: self.nonce,
            out_of_band: self.out_of_band,
        }
    }
}

impl Dkim2Signer<Ready> {
    /// Adds another signing key under its own selector.
    ///
    /// Each key adds one entry to the `s=` tag of the same signature
    /// (algorithmic dexterity, §10.9). Selectors must be distinct, and at
    /// most two keys may use the same algorithm; signing fails with
    /// [`Dkim2Error::DuplicateSelector`](super::Dkim2Error::DuplicateSelector)
    /// or [`Dkim2Error::TooManySelectors`](super::Dkim2Error::TooManySelectors)
    /// otherwise.
    pub fn additional_key(mut self, key: impl Into<DkimKey>, selector: impl Into<String>) -> Self {
        self.keys.push(KeyEntry {
            key: key.into(),
            selector: selector.into(),
        });
        self
    }

    /// Sets the hash algorithms of the `Message-Instance` header fields this
    /// signer adds (§3.1 and §9.3). Repeated algorithms are added once; an
    /// empty list keeps the default, SHA-256 only.
    pub fn hashes(mut self, hashes: impl IntoIterator<Item = Dkim2Hash>) -> Self {
        let mut selected = Vec::with_capacity(2);
        for hash in hashes {
            if !selected.contains(&hash) {
                selected.push(hash);
            }
        }
        if !selected.is_empty() {
            self.hashes = selected;
        }
        self
    }

    /// Adds flags to the `f=` tag of the signature (§10.10). Repeated flags
    /// are added once. [`Flag::Unknown`] values must be textstrings (letters,
    /// digits, `-` and `_`), or signing fails with
    /// [`Dkim2Error::SignatureSyntax`](super::Dkim2Error::SignatureSyntax);
    /// unknown values that spell a defined flag are treated as that flag.
    ///
    /// The `exploded` flag is not allowed on the first signature of a
    /// message (§12.5). It is added automatically to a later signature
    /// whose [`Hop`](super::Hop) has more than one `RCPT TO`; a Forwarder that
    /// sends separate copies to several recipients must set it itself.
    pub fn flags(mut self, flags: impl IntoIterator<Item = Flag>) -> Self {
        for flag in flags {
            if !self.flags.contains(&flag) {
                self.flags.push(flag);
            }
        }
        self
    }

    /// Sets the nonce (`n=` tag, §10.3): an opaque value meaningful only to
    /// the signer, for example a key to match a returned DSN. It must be at
    /// most 64 printable ASCII characters without semicolons; signing fails
    /// with [`Dkim2Error::SignatureSyntax`](super::Dkim2Error::SignatureSyntax)
    /// otherwise. An empty nonce means no `n=` tag.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into()).filter(|nonce| !nonce.is_empty());
        self
    }

    /// Declares an out-of-band arrangement (§12 and §12.3) that allows this
    /// signer to sign messages that are not Validly Signed DKIM2 Messages,
    /// such as a message whose most recent signature carries `nd=` for an
    /// imaginary hop made by the same system. Without it, a message that
    /// already has DKIM2 header fields is signed only with a passing full
    /// verification of it. The chain of custody, `mf=`/`d=` and `exploded`
    /// checks still apply.
    pub fn out_of_band_arrangement(mut self) -> Self {
        self.out_of_band = true;
        self
    }
}
