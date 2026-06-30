/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::DnsError;
use crate::{Error, IprevResult};

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

impl From<Error> for IprevResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            IprevResult::TempError(err)
        } else {
            IprevResult::PermError(err)
        }
    }
}
