/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{MX, Parameters, ResolverCache, Txt};
use std::{
    borrow::Borrow,
    hash::Hash,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub struct NoCache<K, V>(PhantomData<(K, V)>);

impl<K, V> ResolverCache<K, V> for NoCache<K, V> {
    fn get<Q>(&self, _: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn remove<Q>(&self, _: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _: K, _: V, _: std::time::Instant) {}
}

impl<P>
    Parameters<
        '_,
        P,
        NoCache<Box<str>, Txt>,
        NoCache<Box<str>, Arc<[MX]>>,
        NoCache<Box<str>, Arc<[Ipv4Addr]>>,
        NoCache<Box<str>, Arc<[Ipv6Addr]>>,
        NoCache<IpAddr, Arc<[Box<str>]>>,
    >
{
    pub fn new(params: P) -> Self {
        Parameters {
            params,
            cache_txt: None,
            cache_mx: None,
            cache_ptr: None,
            cache_ipv4: None,
            cache_ipv6: None,
        }
    }
}

impl<'x, P, TXT, MXX, IPV4, IPV6, PTR> Parameters<'x, P, TXT, MXX, IPV4, IPV6, PTR>
where
    TXT: ResolverCache<Box<str>, Txt>,
    MXX: ResolverCache<Box<str>, Arc<[MX]>>,
    IPV4: ResolverCache<Box<str>, Arc<[Ipv4Addr]>>,
    IPV6: ResolverCache<Box<str>, Arc<[Ipv6Addr]>>,
    PTR: ResolverCache<IpAddr, Arc<[Box<str>]>>,
{
    pub fn with_txt_cache<NewTXT: ResolverCache<Box<str>, Txt>>(
        self,
        cache: &'x NewTXT,
    ) -> Parameters<'x, P, NewTXT, MXX, IPV4, IPV6, PTR> {
        Parameters {
            params: self.params,
            cache_txt: Some(cache),
            cache_mx: self.cache_mx,
            cache_ptr: self.cache_ptr,
            cache_ipv4: self.cache_ipv4,
            cache_ipv6: self.cache_ipv6,
        }
    }

    pub fn with_mx_cache<NewMX: ResolverCache<Box<str>, Arc<[MX]>>>(
        self,
        cache: &'x NewMX,
    ) -> Parameters<'x, P, TXT, NewMX, IPV4, IPV6, PTR> {
        Parameters {
            params: self.params,
            cache_txt: self.cache_txt,
            cache_mx: Some(cache),
            cache_ptr: self.cache_ptr,
            cache_ipv4: self.cache_ipv4,
            cache_ipv6: self.cache_ipv6,
        }
    }

    pub fn with_ptr_cache<NewPTR: ResolverCache<IpAddr, Arc<[Box<str>]>>>(
        self,
        cache: &'x NewPTR,
    ) -> Parameters<'x, P, TXT, MXX, IPV4, IPV6, NewPTR> {
        Parameters {
            params: self.params,
            cache_txt: self.cache_txt,
            cache_mx: self.cache_mx,
            cache_ptr: Some(cache),
            cache_ipv4: self.cache_ipv4,
            cache_ipv6: self.cache_ipv6,
        }
    }

    pub fn with_ipv4_cache<NewIPV4: ResolverCache<Box<str>, Arc<[Ipv4Addr]>>>(
        self,
        cache: &'x NewIPV4,
    ) -> Parameters<'x, P, TXT, MXX, NewIPV4, IPV6, PTR> {
        Parameters {
            params: self.params,
            cache_txt: self.cache_txt,
            cache_mx: self.cache_mx,
            cache_ptr: self.cache_ptr,
            cache_ipv4: Some(cache),
            cache_ipv6: self.cache_ipv6,
        }
    }

    pub fn with_ipv6_cache<NewIPV6: ResolverCache<Box<str>, Arc<[Ipv6Addr]>>>(
        self,
        cache: &'x NewIPV6,
    ) -> Parameters<'x, P, TXT, MXX, IPV4, NewIPV6, PTR> {
        Parameters {
            params: self.params,
            cache_txt: self.cache_txt,
            cache_mx: self.cache_mx,
            cache_ptr: self.cache_ptr,
            cache_ipv4: self.cache_ipv4,
            cache_ipv6: Some(cache),
        }
    }

    pub fn clone_with<NewP>(
        &self,
        params: NewP,
    ) -> Parameters<'x, NewP, TXT, MXX, IPV4, IPV6, PTR> {
        Parameters {
            params,
            cache_txt: self.cache_txt,
            cache_mx: self.cache_mx,
            cache_ptr: self.cache_ptr,
            cache_ipv4: self.cache_ipv4,
            cache_ipv6: self.cache_ipv6,
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::{
        borrow::Borrow,
        hash::Hash,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use crate::{MX, Parameters, ResolverCache, Txt, common::resolver::ToFqdn};

    pub(crate) struct DummyCache<K, V>(std::sync::Mutex<std::collections::HashMap<K, V>>);

    impl<K: Hash + Eq, V: Clone> DummyCache<K, V> {
        pub fn new() -> Self {
            DummyCache(std::sync::Mutex::new(std::collections::HashMap::new()))
        }
    }

    impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for DummyCache<K, V> {
        fn get<Q>(&self, key: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().get(key).cloned()
        }

        fn remove<Q>(&self, key: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().remove(key)
        }

        fn insert(&self, key: K, value: V, _: std::time::Instant) {
            self.0.lock().unwrap().insert(key, value);
        }
    }

    pub(crate) struct DummyCaches {
        pub txt: DummyCache<Box<str>, Txt>,
        pub mx: DummyCache<Box<str>, Arc<[MX]>>,
        pub ptr: DummyCache<IpAddr, Arc<[Box<str>]>>,
        pub ipv4: DummyCache<Box<str>, Arc<[Ipv4Addr]>>,
        pub ipv6: DummyCache<Box<str>, Arc<[Ipv6Addr]>>,
    }

    impl DummyCaches {
        pub fn new() -> Self {
            Self {
                txt: DummyCache::new(),
                mx: DummyCache::new(),
                ptr: DummyCache::new(),
                ipv4: DummyCache::new(),
                ipv6: DummyCache::new(),
            }
        }

        pub fn with_txt(
            self,
            name: impl ToFqdn,
            value: impl Into<Txt>,
            valid_until: std::time::Instant,
        ) -> Self {
            self.txt.insert(name.to_fqdn(), value.into(), valid_until);
            self
        }

        pub fn txt_add(
            &self,
            name: impl ToFqdn,
            value: impl Into<Txt>,
            valid_until: std::time::Instant,
        ) {
            self.txt.insert(name.to_fqdn(), value.into(), valid_until);
        }

        pub fn ipv4_add(
            &self,
            name: impl ToFqdn,
            value: Vec<Ipv4Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv4.insert(
                name.to_fqdn(),
                Arc::from(value.into_boxed_slice()),
                valid_until,
            );
        }

        pub fn ipv6_add(
            &self,
            name: impl ToFqdn,
            value: Vec<Ipv6Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv6.insert(
                name.to_fqdn(),
                Arc::from(value.into_boxed_slice()),
                valid_until,
            );
        }

        pub fn ptr_add(&self, name: IpAddr, value: Vec<Box<str>>, valid_until: std::time::Instant) {
            self.ptr
                .insert(name, Arc::from(value.into_boxed_slice()), valid_until);
        }

        pub fn mx_add(&self, name: impl ToFqdn, value: Vec<MX>, valid_until: std::time::Instant) {
            self.mx.insert(
                name.to_fqdn(),
                Arc::from(value.into_boxed_slice()),
                valid_until,
            );
        }

        #[allow(clippy::type_complexity)]
        pub fn parameters<T>(
            &self,
            param: T,
        ) -> Parameters<
            '_,
            T,
            DummyCache<Box<str>, Txt>,
            DummyCache<Box<str>, Arc<[MX]>>,
            DummyCache<Box<str>, Arc<[Ipv4Addr]>>,
            DummyCache<Box<str>, Arc<[Ipv6Addr]>>,
            DummyCache<IpAddr, Arc<[Box<str>]>>,
        > {
            Parameters::new(param)
                .with_txt_cache(&self.txt)
                .with_mx_cache(&self.mx)
                .with_ptr_cache(&self.ptr)
                .with_ipv4_cache(&self.ipv4)
                .with_ipv6_cache(&self.ipv6)
        }
    }
}
