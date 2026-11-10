use libp2p::PeerId;
use libp2p::kad::store::{Error, MemoryStore, MemoryStoreConfig, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreSource {
    Ip(IpAddr),
}

pub const PER_SOURCE: usize = 64;
pub const FOREIGN_RECORDS: usize = 8192;
pub const FOREIGN_BYTES: usize = 16 << 20;
pub const FOREIGN_PROVIDERS: usize = 8192;
pub const PROVIDERS_PER_KEY: usize = 64;
const LOCAL_MAX: usize = 4096;

pub struct Store {
    me: PeerId,
    inner: MemoryStore,
    rec_src: HashMap<RecordKey, PeerId>,
    rec_bytes: HashMap<RecordKey, usize>,
    foreign_bytes: usize,
    rec_count: HashMap<PeerId, usize>,
    rec_ips: HashMap<RecordKey, StoreSource>,
    ip_count: HashMap<StoreSource, usize>,
    prov: HashMap<PeerId, HashSet<RecordKey>>,
    prov_ips: HashMap<PeerId, StoreSource>,
    prov_ip_count: HashMap<StoreSource, usize>,
    prov_total: usize,
}

fn random(n: usize) -> usize {
    (RandomState::new().hash_one(0u8) as usize) % n.max(1)
}

impl Store {
    pub fn new(me: PeerId, max_value_bytes: usize) -> Self {
        let cfg = MemoryStoreConfig {
            max_records: LOCAL_MAX + FOREIGN_RECORDS,
            max_value_bytes,
            max_providers_per_key: PROVIDERS_PER_KEY + 1,
            max_provided_keys: LOCAL_MAX + FOREIGN_PROVIDERS,
        };
        Store {
            me,
            inner: MemoryStore::with_config(me, cfg),
            rec_src: HashMap::new(),
            rec_bytes: HashMap::new(),
            foreign_bytes: 0,
            rec_count: HashMap::new(),
            rec_ips: HashMap::new(),
            ip_count: HashMap::new(),
            prov: HashMap::new(),
            prov_ips: HashMap::new(),
            prov_ip_count: HashMap::new(),
            prov_total: 0,
        }
    }

    fn forget_record(&mut self, k: &RecordKey) {
        if let Some(ip) = self.rec_ips.remove(k) {
            if let Some(count) = self.ip_count.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    self.ip_count.remove(&ip);
                }
            }
        }
        self.foreign_bytes = self
            .foreign_bytes
            .saturating_sub(self.rec_bytes.remove(k).unwrap_or(0));
        if let Some(src) = self.rec_src.remove(k) {
            if let Some(n) = self.rec_count.get_mut(&src) {
                *n -= 1;
                if *n == 0 {
                    self.rec_count.remove(&src);
                }
            }
        }
    }

    fn forget_provider(&mut self, k: &RecordKey, p: &PeerId) {
        if let Some(keys) = self.prov.get_mut(p) {
            if keys.remove(k) {
                self.prov_total -= 1;
            }
            if keys.is_empty() {
                self.prov.remove(p);
                if let Some(ip) = self.prov_ips.remove(p) {
                    if let Some(count) = self.prov_ip_count.get_mut(&ip) {
                        *count -= 1;
                        if *count == 0 {
                            self.prov_ip_count.remove(&ip);
                        }
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub fn foreign_records(&self) -> usize {
        self.rec_src.len()
    }

    #[cfg(test)]
    pub fn foreign_providers(&self) -> usize {
        self.prov_total
    }

    #[cfg(test)]
    pub fn put_foreign(&mut self, r: Record, source: PeerId) -> Result<()> {
        self.put_foreign_from(r, source, None)
    }

    pub fn put_foreign_from(
        &mut self,
        r: Record,
        source: PeerId,
        ip: Option<StoreSource>,
    ) -> Result<()> {
        let size = r.value.len();
        let mut old_size = self.rec_bytes.get(&r.key).copied().unwrap_or(0);
        if self
            .foreign_bytes
            .saturating_sub(old_size)
            .saturating_add(size)
            > FOREIGN_BYTES
        {
            self.purge(Instant::now());
            old_size = self.rec_bytes.get(&r.key).copied().unwrap_or(0);
            if self
                .foreign_bytes
                .saturating_sub(old_size)
                .saturating_add(size)
                > FOREIGN_BYTES
            {
                return Err(Error::MaxRecords);
            }
        }
        let existing = self.inner.get(&r.key).is_some();
        if existing && !self.rec_src.contains_key(&r.key) {
            return Err(Error::MaxRecords);
        }
        let same = self.rec_src.get(&r.key) == Some(&source);
        if let Some(ip) = ip {
            if self.rec_ips.get(&r.key) != Some(&ip)
                && self.ip_count.get(&ip).copied().unwrap_or(0) >= PER_SOURCE
            {
                return Err(Error::MaxRecords);
            }
        }
        if !same {
            if self.rec_count.get(&source).copied().unwrap_or(0) >= PER_SOURCE {
                return Err(Error::MaxRecords);
            }
            if !existing && self.rec_src.len() >= FOREIGN_RECORDS {
                self.purge(Instant::now());
                if self.rec_src.len() >= FOREIGN_RECORDS {
                    return Err(Error::MaxRecords);
                }
            }
        }
        let key = r.key.clone();
        self.inner.put(r)?;
        if !same {
            self.forget_record(&key);
            self.rec_src.insert(key.clone(), source);
            *self.rec_count.entry(source).or_insert(0) += 1;
        } else {
            self.foreign_bytes = self.foreign_bytes.saturating_sub(old_size);
        }
        self.foreign_bytes += size;
        if let Some(ip) = ip {
            if self.rec_ips.get(&key) != Some(&ip) {
                if let Some(old) = self.rec_ips.insert(key.clone(), ip) {
                    if let Some(count) = self.ip_count.get_mut(&old) {
                        *count -= 1;
                        if *count == 0 {
                            self.ip_count.remove(&old);
                        }
                    }
                }
                *self.ip_count.entry(ip).or_insert(0) += 1;
            }
        }
        self.rec_bytes.insert(key, size);
        Ok(())
    }

    pub fn add_foreign_provider(&mut self, r: ProviderRecord) -> Result<()> {
        self.add_foreign_provider_from(r, None)
    }

    pub fn add_foreign_provider_from(
        &mut self,
        r: ProviderRecord,
        ip: Option<StoreSource>,
    ) -> Result<()> {
        let p = r.provider;
        let ip = ip.or_else(|| self.prov_ips.get(&p).copied());
        if ip.is_some() && !self.prov_ips.contains_key(&p) && self.prov.contains_key(&p) {
            return Err(Error::MaxProvidedKeys);
        }
        if p == self.me {
            return Err(Error::MaxProvidedKeys);
        }
        let known = self.prov.get(&p).is_some_and(|k| k.contains(&r.key));
        if let Some(ip) = ip {
            if self.prov_ips.get(&p).is_some_and(|old| *old != ip) {
                return Err(Error::MaxProvidedKeys);
            }
            if !known
                && (self.prov_ip_count.get(&ip).copied().unwrap_or(0) >= PER_SOURCE * 4
                    || self
                        .inner
                        .providers(&r.key)
                        .iter()
                        .filter(|record| self.prov_ips.get(&record.provider) == Some(&ip))
                        .count()
                        >= 4)
            {
                return Err(Error::MaxProvidedKeys);
            }
        }
        if !known {
            if self.prov.get(&p).map_or(0, |k| k.len()) >= PER_SOURCE {
                return Err(Error::MaxProvidedKeys);
            }
            if self.prov_total >= FOREIGN_PROVIDERS {
                self.purge(Instant::now());
                if self.prov_total >= FOREIGN_PROVIDERS {
                    return Err(Error::MaxProvidedKeys);
                }
            }
            let foreign: Vec<PeerId> = self
                .inner
                .providers(&r.key)
                .into_iter()
                .map(|x| x.provider)
                .filter(|x| *x != self.me)
                .collect();
            if foreign.len() >= PROVIDERS_PER_KEY {
                let evict = foreign[random(foreign.len())];
                self.inner.remove_provider(&r.key, &evict);
                self.forget_provider(&r.key, &evict);
            }
        }
        let key = r.key.clone();
        self.inner.add_provider(r)?;
        if !known && self.prov.entry(p).or_default().insert(key) {
            self.prov_total += 1;
            if let Some(ip) = ip {
                self.prov_ips.insert(p, ip);
                *self.prov_ip_count.entry(ip).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    pub fn purge(&mut self, now: Instant) {
        let dead: Vec<RecordKey> = self
            .rec_src
            .keys()
            .filter(|k| self.inner.get(k).is_none_or(|r| r.is_expired(now)))
            .cloned()
            .collect();
        for k in dead {
            self.inner.remove(&k);
            self.forget_record(&k);
        }
        let mut gone = Vec::new();
        for (p, keys) in &self.prov {
            for k in keys {
                let alive = self
                    .inner
                    .providers(k)
                    .iter()
                    .any(|x| x.provider == *p && !x.is_expired(now));
                if !alive {
                    gone.push((k.clone(), *p));
                }
            }
        }
        for (k, p) in gone {
            self.inner.remove_provider(&k, &p);
            self.forget_provider(&k, &p);
        }
    }
}

impl RecordStore for Store {
    type RecordsIter<'a> = <MemoryStore as RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <MemoryStore as RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &RecordKey) -> Option<Cow<'_, Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: Record) -> Result<()> {
        if r.publisher.is_some_and(|p| p != self.me) {
            return Err(Error::MaxRecords);
        }
        let key = r.key.clone();
        self.inner.put(r)?;
        self.forget_record(&key);
        Ok(())
    }

    fn remove(&mut self, k: &RecordKey) {
        self.inner.remove(k);
        self.forget_record(k);
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, r: ProviderRecord) -> Result<()> {
        if r.provider != self.me {
            return self.add_foreign_provider(r);
        }
        self.inner.add_provider(r)
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, k: &RecordKey, p: &PeerId) {
        self.inner.remove_provider(k, p);
        self.forget_provider(k, p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn prov(key: &RecordKey, p: PeerId) -> ProviderRecord {
        ProviderRecord::new(key.clone(), p, vec![])
    }

    fn key(i: usize) -> RecordKey {
        RecordKey::new(&i.to_be_bytes())
    }

    #[test]
    fn rotating_peer_ids_cannot_bypass_source_ip_record_quota() {
        let mut store = Store::new(PeerId::random(), 1 << 16);
        let ip = "8.8.8.8".parse().unwrap();
        for i in 0..PER_SOURCE {
            store
                .put_foreign_from(
                    Record {
                        key: key(i),
                        value: vec![1],
                        publisher: None,
                        expires: None,
                    },
                    PeerId::random(),
                    Some(StoreSource::Ip(ip)),
                )
                .unwrap();
        }
        assert!(
            store
                .put_foreign_from(
                    Record {
                        key: key(PER_SOURCE),
                        value: vec![1],
                        publisher: None,
                        expires: None
                    },
                    PeerId::random(),
                    Some(StoreSource::Ip(ip))
                )
                .is_err()
        );
        store.remove(&key(0));
        assert!(
            store
                .put_foreign_from(
                    Record {
                        key: key(PER_SOURCE),
                        value: vec![1],
                        publisher: None,
                        expires: None
                    },
                    PeerId::random(),
                    Some(StoreSource::Ip(ip))
                )
                .is_ok()
        );
    }

    #[test]
    fn provider_sybils_share_per_topic_ip_quota() {
        let mut store = Store::new(PeerId::random(), 1 << 16);
        let ip = "8.8.8.8".parse().unwrap();
        for _ in 0..4 {
            store
                .add_foreign_provider_from(
                    prov(&key(1), PeerId::random()),
                    Some(StoreSource::Ip(ip)),
                )
                .unwrap();
        }
        assert!(
            store
                .add_foreign_provider_from(
                    prov(&key(1), PeerId::random()),
                    Some(StoreSource::Ip(ip))
                )
                .is_err()
        );
        assert!(
            store
                .add_foreign_provider_from(
                    prov(&key(1), PeerId::random()),
                    Some(StoreSource::Ip("9.9.9.9".parse().unwrap()))
                )
                .is_ok()
        );
    }

    #[test]
    fn one_source_cannot_fill_the_store_or_block_local() {
        let me = PeerId::random();
        let mut s = Store::new(me, 1 << 16);
        let evil = PeerId::random();
        let ok = (0..2000)
            .filter(|i| s.add_foreign_provider(prov(&key(*i), evil)).is_ok())
            .count();
        assert_eq!(ok, PER_SOURCE);
        let rec_ok = (0..2000)
            .filter(|i| {
                s.put_foreign(
                    Record {
                        key: key(100_000 + i),
                        value: vec![1],
                        publisher: None,
                        expires: None,
                    },
                    evil,
                )
                .is_ok()
            })
            .count();
        assert_eq!(rec_ok, PER_SOURCE);
        let honest = PeerId::random();
        assert!(s.add_foreign_provider(prov(&key(5000), honest)).is_ok());
        for i in 0..2000 {
            s.add_provider(prov(&key(9000 + i), me)).unwrap();
        }
        assert!(
            s.put(Record {
                key: key(1),
                value: vec![2],
                publisher: Some(me),
                expires: None
            })
            .is_ok()
        );
    }

    #[test]
    fn sybils_cannot_pin_a_key_and_expired_entries_are_purged() {
        let me = PeerId::random();
        let mut s = Store::new(me, 1 << 16);
        let k = key(7);
        for _ in 0..(PROVIDERS_PER_KEY * 3) {
            s.add_foreign_provider(prov(&k, PeerId::random())).unwrap();
        }
        let honest = PeerId::random();
        s.add_foreign_provider(prov(&k, honest)).unwrap();
        assert!(s.providers(&k).iter().any(|p| p.provider == honest));
        assert!(s.providers(&k).len() <= PROVIDERS_PER_KEY);
        let past = Instant::now() - Duration::from_secs(1);
        let mut old = prov(&key(8), PeerId::random());
        old.expires = Some(past);
        s.add_foreign_provider(old).unwrap();
        s.put_foreign(
            Record {
                key: key(9),
                value: vec![1],
                publisher: None,
                expires: Some(past),
            },
            PeerId::random(),
        )
        .unwrap();
        s.purge(Instant::now());
        assert!(s.providers(&key(8)).is_empty());
        assert!(s.get(&key(9)).is_none());
        assert_eq!(s.foreign_records(), 0);
        assert_eq!(s.foreign_providers(), s.providers(&k).len());
    }
}
