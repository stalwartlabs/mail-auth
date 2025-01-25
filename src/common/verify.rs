/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{
    dkim::Canonicalization, Error, IprevOutput, IprevResult, MessageAuthenticator, Parameters,
    ResolverCache, Txt, MX,
};

use super::{
    cache::NoCache,
    crypto::{Algorithm, VerifyingKey},
};

pub struct DomainKey {
    pub p: Box<dyn VerifyingKey + Send + Sync>,
    pub f: u64,
}

impl MessageAuthenticator {
    pub async fn verify_iprev<'x, TXT, MXX, IPV4, IPV6, PTR>(
        &self,
        params: impl Into<Parameters<'x, IpAddr, TXT, MXX, IPV4, IPV6, PTR>>,
    ) -> IprevOutput
    where
        TXT: ResolverCache<String, Txt> + 'x,
        MXX: ResolverCache<String, Arc<Vec<MX>>> + 'x,
        IPV4: ResolverCache<String, Arc<Vec<Ipv4Addr>>> + 'x,
        IPV6: ResolverCache<String, Arc<Vec<Ipv6Addr>>> + 'x,
        PTR: ResolverCache<IpAddr, Arc<Vec<String>>> + 'x,
    {
        let params = params.into();
        match self.ptr_lookup(params.params, params.cache_ptr).await {
            Ok(ptr) => {
                let mut last_err = None;
                for host in ptr.iter().take(2) {
                    match &params.params {
                        IpAddr::V4(ip) => match self.ipv4_lookup(host, params.cache_ipv4).await {
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
                        IpAddr::V6(ip) => match self.ipv6_lookup(host, params.cache_ipv6).await {
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

impl From<IpAddr>
    for Parameters<
        '_,
        IpAddr,
        NoCache<String, Txt>,
        NoCache<String, Arc<Vec<MX>>>,
        NoCache<String, Arc<Vec<Ipv4Addr>>>,
        NoCache<String, Arc<Vec<Ipv6Addr>>>,
        NoCache<IpAddr, Arc<Vec<String>>>,
    >
{
    fn from(params: IpAddr) -> Self {
        Parameters::new(params)
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
