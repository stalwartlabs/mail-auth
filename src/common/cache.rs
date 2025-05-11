/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    borrow::Borrow,
    hash::Hash,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{Parameters, ResolverCache, Txt, MX};

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
        NoCache<String, Txt>,
        NoCache<String, Arc<Vec<MX>>>,
        NoCache<String, Arc<Vec<Ipv4Addr>>>,
        NoCache<String, Arc<Vec<Ipv6Addr>>>,
        NoCache<IpAddr, Arc<Vec<String>>>,
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
    TXT: ResolverCache<String, Txt>,
    MXX: ResolverCache<String, Arc<Vec<MX>>>,
    IPV4: ResolverCache<String, Arc<Vec<Ipv4Addr>>>,
    IPV6: ResolverCache<String, Arc<Vec<Ipv6Addr>>>,
    PTR: ResolverCache<IpAddr, Arc<Vec<String>>>,
{
    pub fn with_txt_cache<NewTXT: ResolverCache<String, Txt>>(
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

    pub fn with_mx_cache<NewMX: ResolverCache<String, Arc<Vec<MX>>>>(
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

    pub fn with_ptr_cache<NewPTR: ResolverCache<IpAddr, Arc<Vec<String>>>>(
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

    pub fn with_ipv4_cache<NewIPV4: ResolverCache<String, Arc<Vec<Ipv4Addr>>>>(
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

    pub fn with_ipv6_cache<NewIPV6: ResolverCache<String, Arc<Vec<Ipv6Addr>>>>(
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

    use crate::{common::resolver::IntoFqdn, Parameters, ResolverCache, Txt, MX};

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
        pub txt: DummyCache<String, Txt>,
        pub mx: DummyCache<String, Arc<Vec<MX>>>,
        pub ptr: DummyCache<IpAddr, Arc<Vec<String>>>,
        pub ipv4: DummyCache<String, Arc<Vec<Ipv4Addr>>>,
        pub ipv6: DummyCache<String, Arc<Vec<Ipv6Addr>>>,
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

        pub fn with_txt<'x>(
            self,
            name: impl IntoFqdn<'x>,
            value: impl Into<Txt>,
            valid_until: std::time::Instant,
        ) -> Self {
            self.txt
                .insert(name.into_fqdn().into_owned(), value.into(), valid_until);
            self
        }

        pub fn txt_add<'x>(
            &self,
            name: impl IntoFqdn<'x>,
            value: impl Into<Txt>,
            valid_until: std::time::Instant,
        ) {
            self.txt
                .insert(name.into_fqdn().into_owned(), value.into(), valid_until);
        }

        pub fn ipv4_add<'x>(
            &self,
            name: impl IntoFqdn<'x>,
            value: Vec<Ipv4Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv4
                .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
        }

        pub fn ipv6_add<'x>(
            &self,
            name: impl IntoFqdn<'x>,
            value: Vec<Ipv6Addr>,
            valid_until: std::time::Instant,
        ) {
            self.ipv6
                .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
        }

        pub fn ptr_add(&self, name: IpAddr, value: Vec<String>, valid_until: std::time::Instant) {
            self.ptr.insert(name, Arc::new(value), valid_until);
        }

        pub fn mx_add<'x>(
            &self,
            name: impl IntoFqdn<'x>,
            value: Vec<MX>,
            valid_until: std::time::Instant,
        ) {
            self.mx
                .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
        }

        #[allow(clippy::type_complexity)]
        pub fn parameters<T>(
            &self,
            param: T,
        ) -> Parameters<
            '_,
            T,
            DummyCache<String, Txt>,
            DummyCache<String, Arc<Vec<MX>>>,
            DummyCache<String, Arc<Vec<Ipv4Addr>>>,
            DummyCache<String, Arc<Vec<Ipv6Addr>>>,
            DummyCache<IpAddr, Arc<Vec<String>>>,
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
