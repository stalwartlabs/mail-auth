/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::net::IpAddr;

use crate::{dkim::Canonicalization, Error, IprevOutput, IprevResult};

use super::crypto::{Algorithm, VerifyingKey};

pub struct DomainKey {
    pub p: Box<dyn VerifyingKey + Send + Sync>,
    pub f: u64,
}

#[cfg(feature = "resolver")]
impl crate::Resolver {
    pub async fn verify_iprev(&self, addr: IpAddr) -> IprevOutput {
        match self.ptr_lookup(addr).await {
            Ok(ptr) => {
                let mut last_err = None;
                for host in ptr.iter().take(2) {
                    match &addr {
                        IpAddr::V4(ip) => match self.ipv4_lookup(host).await {
                            Ok(ips) => {
                                if ips.iter().any(|cip| cip == ip) {
                                    return IprevOutput {
                                        result: IprevResult::Pass,
                                        ptr: ptr.into(),
                                    };
                                }
                            }
                            Err(err) => {
                                last_err = err.into();
                            }
                        },
                        IpAddr::V6(ip) => match self.ipv6_lookup(host).await {
                            Ok(ips) => {
                                if ips.iter().any(|cip| cip == ip) {
                                    return IprevOutput {
                                        result: IprevResult::Pass,
                                        ptr: ptr.into(),
                                    };
                                }
                            }
                            Err(err) => {
                                last_err = err.into();
                            }
                        },
                    }
                }

                IprevOutput {
                    result: if let Some(err) = last_err {
                        err.into()
                    } else {
                        IprevResult::Fail(Error::NotAligned)
                    },
                    ptr: ptr.into(),
                }
            }
            Err(err) => IprevOutput {
                result: err.into(),
                ptr: None,
            },
        }
    }
}

impl IprevOutput {
    pub fn result(&self) -> &IprevResult {
        &self.result
    }
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

pub trait VerifySignature {
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
