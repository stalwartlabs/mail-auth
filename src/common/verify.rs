/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::dkim::Canonicalization;

use super::crypto::{Algorithm, VerifyingKey};

pub struct DomainKey {
    pub(crate) p: Box<dyn VerifyingKey>,
    pub(crate) f: u64,
}

impl DomainKey {
    pub(crate) fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        input: &impl VerifySignature,
        canonicalization: Canonicalization,
    ) -> crate::Result<()> {
        self.p.verify(
            headers,
            input.signature(),
            canonicalization,
            input.algorithm(),
        )
    }
}

pub(crate) trait VerifySignature {
    fn selector(&self) -> &str;

    fn domain(&self) -> &str;

    fn signature(&self) -> &[u8];

    fn algorithm(&self) -> Algorithm;

    fn domain_key(&self) -> String {
        let s = self.selector();
        let d = self.domain();
        let mut key = String::with_capacity(s.len() + d.len() + 13);
        key.push_str(s);
        key.push_str("._domainkey.");
        key.push_str(d);
        key.push('.');
        key
    }
}
