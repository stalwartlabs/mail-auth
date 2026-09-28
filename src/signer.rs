/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Typestate markers for the signer builders.
//!
//! [`DkimSigner`](crate::dkim::DkimSigner), `ArcSealer` (feature `arc`) and
//! [`Dkim2Signer`](crate::dkim2::Dkim2Signer) carry one of these markers as
//! a type parameter. Each builder method consumes the signer and returns it in
//! the next state, so the compiler rejects a signer that is used before every
//! mandatory field is set:
//!
//! - `DkimSigner` and `ArcSealer`: [`NeedDomain`] (after `from_key`), then
//!   [`NeedSelector`] (after `domain`), then [`NeedHeaders`] (after
//!   `selector`), then [`Ready`] (after `headers`).
//! - `Dkim2Signer`: [`NeedDomain`], then [`NeedSelector`], then [`Ready`]
//!   (after `selector`). DKIM2 does not take a list of signed headers.
//!
//! Only a signer in the [`Ready`] state exposes the optional setters and the
//! signing methods. The markers are zero-sized and carry no data.

/// The signer has a key but no signing domain (`d=` tag) yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NeedDomain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// The signer has a signing domain but no selector (`s=` tag) yet.
pub struct NeedSelector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// The signer has a domain and selector but no list of headers to sign
/// (`h=` tag) yet. Used by `DkimSigner` and `ArcSealer` only.
pub struct NeedHeaders;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Every mandatory field is set; the signer can sign messages.
pub struct Ready;
