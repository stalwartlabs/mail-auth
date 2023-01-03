/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{borrow::Borrow, hash::Hash, time::Instant};

use parking_lot::Mutex;

pub type LruCache<K, V> = Mutex<lru_cache::LruCache<K, LruItem<V>, ahash::RandomState>>;

#[derive(Debug, Clone)]
pub struct LruItem<V> {
    item: V,
    valid_until: Instant,
}

pub trait DnsCache<K, V>: Sized {
    fn with_capacity(capacity: usize) -> Self;
    fn get<Q: ?Sized>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq;
    fn insert(&self, name: K, value: V, valid_until: Instant) -> V;
}

impl<K: Hash + Eq, V: Clone> DnsCache<K, V> for LruCache<K, V> {
    fn with_capacity(capacity: usize) -> Self {
        Mutex::new(lru_cache::LruCache::with_hasher(
            capacity,
            ahash::RandomState::new(),
        ))
    }

    fn get<Q: ?Sized>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let mut cache = self.lock();
        let entry = cache.get_mut(name)?;
        if entry.valid_until >= Instant::now() {
            entry.item.clone().into()
        } else {
            cache.remove(name);
            None
        }
    }

    fn insert(&self, name: K, item: V, valid_until: Instant) -> V {
        self.lock().insert(
            name,
            LruItem {
                item: item.clone(),
                valid_until,
            },
        );
        item
    }
}
