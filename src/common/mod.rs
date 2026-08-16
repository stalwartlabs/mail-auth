/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::DnsError;
use crate::{Error, IprevResult};
use std::borrow::Cow;

pub mod auth_results;
pub mod base32;
pub mod cache;
pub mod crypto;
#[cfg(feature = "dns-doh")]
pub mod doh;
pub mod headers;
pub mod message;
pub mod parse;
pub mod resolver;
pub mod verify;

pub fn to_a_label(domain: &str) -> Cow<'_, str> {
    if !domain.is_ascii() {
        idna::domain_to_ascii(domain)
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(domain))
    } else if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}

impl From<Error> for IprevResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            IprevResult::TempError(err)
        } else {
            IprevResult::PermError(err)
        }
    }
}
