/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Type state builder for [`DkimSigner`]: key, then domain, selector and
//! signed headers, then optional settings.

use super::{Canonicalization, DkimSigner, Signature};
use crate::{
    crypto::{HashAlgorithm, SigningKey},
    signer::{NeedDomain, NeedHeaders, NeedSelector, Ready},
};
use std::time::Duration;

impl<T: SigningKey> DkimSigner<T> {
    /// Starts a signer for `key`.
    ///
    /// The `a=` algorithm is taken from the key. Continue with
    /// [`domain`](DkimSigner::domain), [`selector`](DkimSigner::selector) and
    /// [`headers`](DkimSigner::headers) to obtain a signer in the
    /// [`Ready`] state.
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
    /// Sets the signing domain (`d=` tag).
    ///
    /// The public key must be published under this domain, at
    /// `<selector>._domainkey.<domain>`.
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
    /// Sets the selector (`s=` tag) naming the key record under the signing
    /// domain.
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
    /// Sets the names of the header fields to sign (`h=` tag) and returns a
    /// signer ready to sign.
    ///
    /// Names are matched case insensitively. Every occurrence of a listed
    /// header present in the message is signed, and `h=` lists them bottom
    /// up. Listed names absent from the message are still appended to `h=`,
    /// so adding such a header later breaks the signature (RFC 6376,
    /// Section 5.4). Include at least `From` (RFC 6376, Section 5.4.1).
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<String>>,
    ) -> DkimSigner<T, Ready> {
        self.template.h = headers.into_iter().map(|h| h.into()).collect();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, Ready> {
    /// Sets the RFC 6541 `atps=` tag: the author domain on whose behalf this
    /// third-party signature is made.
    ///
    /// Without [`atps_hash`](DkimSigner::atps_hash), `atpsh=none` is written.
    pub fn atps(mut self, atps: impl Into<String>) -> Self {
        self.template.atps = Some(atps.into());
        self
    }

    /// Sets the RFC 6541 `atpsh=` tag: the hash applied to `d=` when the
    /// verifier builds the ATPS query name. Only written together with
    /// [`atps`](DkimSigner::atps).
    pub fn atps_hash(mut self, atps_hash: HashAlgorithm) -> Self {
        self.template.atpsh = atps_hash.into();
        self
    }

    /// Sets the agent or user identifier (`i=` tag).
    ///
    /// Its domain must be the signing domain or a subdomain of it, otherwise
    /// verification fails with [`DkimError::AuidMismatch`](super::DkimError::AuidMismatch).
    pub fn identity(mut self, identity: impl Into<String>) -> Self {
        self.template.i = identity.into();
        self
    }

    /// Sets the signature validity period, counted from the signing time.
    ///
    /// The produced signature carries `x=` equal to `t=` plus `expiration`,
    /// rounded up to whole seconds and capped at `u64::MAX`, so
    /// `Duration::MAX` means no practical expiry. A zero duration, the
    /// default, omits the `x=` tag.
    pub fn expiration(mut self, expiration: Duration) -> Self {
        self.template.x = expiration
            .as_secs()
            .saturating_add(u64::from(expiration.subsec_nanos() > 0));
        self
    }

    /// Includes the body length (`l=` tag) in the signature when `true`.
    ///
    /// Off by default. Signing the length lets anyone append content
    /// after the signed body without breaking the signature (RFC 6376,
    /// Section 8.2), and strict verifiers ignore such signatures.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.template.l = u64::from(body_length);
        self
    }

    /// Requests RFC 6651 failure reports (`r=y` tag) when `true`.
    ///
    /// Off by default. Verifiers send reports to the address published in
    /// the `_report._domainkey.<domain>` record.
    pub fn reporting(mut self, reporting: bool) -> Self {
        self.template.r = reporting;
        self
    }

    /// Sets the header canonicalization (first half of the `c=` tag).
    /// Defaults to [`Canonicalization::Relaxed`].
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.template.ch = ch;
        self
    }

    /// Sets the body canonicalization (second half of the `c=` tag).
    /// Defaults to [`Canonicalization::Relaxed`].
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.template.cb = cb;
        self
    }
}
