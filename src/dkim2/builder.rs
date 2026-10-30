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
    /// Ed25519-SHA256 or ML-DSA-44). Continue with
    /// [`domain`](Self::domain).
    pub fn from_key(key: impl Into<DkimKey>) -> Dkim2Signer<NeedDomain> {
        Dkim2Signer {
            _state: Default::default(),
            keys: vec![KeyEntry {
                key: key.into(),
                selector: String::new(),
                group: 0,
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
    /// Adds another signing key under its own selector as an alternative to
    /// the keys added before it.
    ///
    /// The key adds a new `|`-separated group to the `s=` tag of the same
    /// signature (algorithmic agility, §10.9): the signature passes when
    /// either this key or an earlier group verifies, so a Verifier that does
    /// not implement one of the algorithms can still check the others.
    /// Selectors must be distinct and a signature holds at most eight keys;
    /// signing fails with
    /// [`Dkim2Error::DuplicateSelector`](super::Dkim2Error::DuplicateSelector)
    /// or [`Dkim2Error::TooManySelectors`](super::Dkim2Error::TooManySelectors)
    /// otherwise.
    pub fn additional_key(self, key: impl Into<DkimKey>, selector: impl Into<String>) -> Self {
        let group = self
            .keys
            .last()
            .map_or(0, |entry| entry.group.saturating_add(1));
        self.push_key(key.into(), selector.into(), group)
    }

    /// Adds another signing key under its own selector that must verify
    /// together with the key added before it.
    ///
    /// The key joins the last `|`-separated group of the `s=` tag with a `,`
    /// (a "hybrid" signature, §10.9): that group passes only when every key
    /// in it verifies. The same limits as
    /// [`additional_key`](Self::additional_key) apply.
    pub fn hybrid_key(self, key: impl Into<DkimKey>, selector: impl Into<String>) -> Self {
        let group = self.keys.last().map_or(0, |entry| entry.group);
        self.push_key(key.into(), selector.into(), group)
    }

    fn push_key(mut self, key: DkimKey, selector: String, group: u32) -> Self {
        self.keys.push(KeyEntry {
            key,
            selector,
            group,
        });
        self
    }

    /// Sets the hash algorithms of the `Message-Instance` header fields this
    /// signer adds (§3.1 and §9.3). They form a single `,`-separated group,
    /// so all of them must match. Repeated algorithms are added once; an
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
    /// sends separate copies to several recipients marks each copy's hop with
    /// [`Hop::exploded`](super::Hop::exploded) instead.
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
    /// signer to sign messages that are not Fully Verified DKIM2 Messages,
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
