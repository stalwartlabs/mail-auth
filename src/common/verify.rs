/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::{common::crypto::Algorithm, dkim::DomainKey};

pub(crate) trait VerifySignature {
    fn s(&self) -> &str;

    fn d(&self) -> &str;

    fn b(&self) -> &[u8];

    fn a(&self) -> Algorithm;

    fn domain_key(&self) -> String {
        let s = self.s();
        let d = self.d();
        let mut key = String::with_capacity(s.len() + d.len() + 13);
        key.push_str(s);
        key.push_str("._domainkey.");
        key.push_str(d);
        key.push('.');
        key
    }

    fn verify(&self, record: &DomainKey, hh: &[u8]) -> crate::Result<()> {
        record.p.verify(hh, self.b(), self.a())
    }
}
