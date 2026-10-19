/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

/*
    DISCLAIMER:
    This code has been written by an LLM and is inefficient and unidiomatic.
    It was created to demonstrate mail-auth in the browser and is not intended for production use.
    It may contain errors, security vulnerabilities, or other issues that could cause harm if used
    in a real-world application. Use at your own risk.
*/

use crate::cache::OfflineCache;
use mail_auth::{MessageAuthenticator, Parameters};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsOpts {
    mode: String,
    doh_endpoint: String,
    doh_format: String,
    records: String,
    #[serde(default)]
    local_records: String,
}

impl DnsOpts {
    fn is_offline(&self) -> bool {
        self.mode == "offline"
    }

    pub fn resolver(&self) -> MessageAuthenticator {
        if self.is_offline() {
            MessageAuthenticator::new_doh("https://offline.invalid/dns-query")
        } else if self.doh_format == "wire" {
            MessageAuthenticator::new_doh_wire(self.doh_endpoint.clone())
        } else {
            MessageAuthenticator::new_doh(self.doh_endpoint.clone())
        }
    }

    pub fn cache(&self) -> Result<OfflineCache, String> {
        let cache = if self.is_offline() {
            OfflineCache::offline()
        } else {
            OfflineCache::default()
        };
        cache
            .add_records(&self.local_records)
            .map_err(|err| format!("Active key record: {err}"))?;
        if self.is_offline() {
            cache.add_records(&self.records)?;
        }
        Ok(cache)
    }
}

pub fn params<'x, P>(inner: P, cache: &'x OfflineCache) -> Parameters<'x, P, OfflineCache> {
    Parameters::new(inner).with_cache(cache)
}
