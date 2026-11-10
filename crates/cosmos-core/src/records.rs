//! Async plane: signed records for data that need not be in sync (notes on
//! the floor, ghosts, profiles, leaderboards-lite, lobby adverts).
//!
//! - A record lives under `(game namespace, kind, key)`, one per publisher.
//!   The DHT/gossip topic is `topic_for(namespace, "rec/{kind}/{key}")`;
//!   namespace and kind are restricted to `[A-Za-z0-9_.-]`, so no two
//!   triples share a topic and every accepted record is checked against the
//!   exact topic it was asked for (and the topic is inside the signature).
//! - Records are signed by the publisher (`cosmos_net::Record`); tampered
//!   data or a swapped key fail verification.
//! - TTL is clamped to `MAX_TTL`; expired records are never returned.
//! - Caps: record size, puts per window, records/bytes per query result and
//!   per subscription buffer (oldest dropped first).
//! - A bounded cache keeps recently seen records, optionally on disk (one
//!   file of signed bytes per record); unreadable or invalid files are
//!   ignored and removed.

use cosmos_net::{MAX_TTL, Node, PeerId, Record, now_secs};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const NAME_MAX: usize = 64;
const KEY_MAX: usize = 256;
/// Signed-record overhead on top of the data: key, topic, expiry, signature.
const OVERHEAD: usize = 1024;

#[derive(Clone, Debug)]
pub struct RecordsConfig {
    /// Game namespace; records of other namespaces never surface.
    pub namespace: String,
    /// Largest accepted record payload, sent or received.
    pub max_record_bytes: usize,
    /// At most `put_rate` puts per `put_window`.
    pub put_rate: usize,
    pub put_window: Duration,
    /// Caps on one query result.
    pub query_max_records: usize,
    pub query_max_bytes: usize,
    pub query_deadline: Duration,
    /// Caps on what one subscription buffers before it is read.
    pub sub_max_records: usize,
    pub sub_max_bytes: usize,
    /// Keep recently seen records here across restarts.
    pub cache_dir: Option<PathBuf>,
    pub cache_max_records: usize,
}

impl RecordsConfig {
    pub fn new(namespace: &str) -> Self {
        RecordsConfig {
            namespace: namespace.to_string(),
            max_record_bytes: 4096,
            put_rate: 10,
            put_window: Duration::from_secs(10),
            query_max_records: 64,
            query_max_bytes: 256 << 10,
            query_deadline: Duration::from_secs(10),
            sub_max_records: 64,
            sub_max_bytes: 256 << 10,
            cache_dir: None,
            cache_max_records: 256,
        }
    }
}

#[derive(Debug)]
pub enum RecordError {
    BadName,
    BadTtl,
    TooLarge,
    RateLimited,
    Net(anyhow::Error),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::BadName => f.write_str("invalid namespace, kind or key"),
            RecordError::BadTtl => f.write_str("ttl must be at least one second"),
            RecordError::TooLarge => f.write_str("record too large"),
            RecordError::RateLimited => f.write_str("put rate limit reached"),
            RecordError::Net(e) => write!(f, "network: {e}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// One verified, unexpired record of this namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: String,
    pub key: String,
    pub publisher: PeerId,
    pub data: Vec<u8>,
    /// Unix seconds.
    pub expires: u64,
}

fn name_ok(s: &str) -> bool {
    (1..=NAME_MAX).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn key_ok(s: &str) -> bool {
    (1..=KEY_MAX).contains(&s.len()) && !s.chars().any(char::is_control)
}

fn prefix(ns: &str) -> String {
    cosmos_net::topic_for(ns, "rec/")
}

/// Topic of `(ns, kind, key)`, or `BadName`.
pub fn topic(ns: &str, kind: &str, key: &str) -> Result<String, RecordError> {
    if !name_ok(ns) || !name_ok(kind) || !key_ok(key) {
        return Err(RecordError::BadName);
    }
    Ok(cosmos_net::topic_for(ns, &format!("rec/{kind}/{key}")))
}

/// Accept a verified record if it belongs to `ns`, fits `max` and is alive.
fn admit(ns: &str, rec: &Record, max: usize, now: u64) -> Option<Entry> {
    let rest = rec.topic.strip_prefix(&prefix(ns))?;
    let (kind, key) = rest.split_once('/')?;
    if !name_ok(kind) || !key_ok(key) || rec.data.len() > max || rec.expires <= now {
        return None;
    }
    Some(Entry {
        kind: kind.to_string(),
        key: key.to_string(),
        publisher: rec.publisher,
        data: rec.data.clone(),
        expires: rec.expires,
    })
}

/// Verify signed bytes and admit them.
#[cfg(test)]
fn decode(ns: &str, bytes: &[u8], max: usize, now: u64) -> Option<(Record, Entry)> {
    let rec = Record::verify(bytes)?;
    let e = admit(ns, &rec, max, now)?;
    Some((rec, e))
}

fn file_name(topic: &str, publisher: &PeerId) -> String {
    let mut h = Sha256::new();
    h.update((topic.len() as u32).to_be_bytes());
    h.update(topic.as_bytes());
    h.update(publisher.to_bytes());
    let d = h.finalize();
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.rec")
}

/// Recently seen records of one namespace, bounded, optionally on disk.
struct Cache {
    ns: String,
    max_bytes: usize,
    max_records: usize,
    dir: Option<PathBuf>,
    map: HashMap<(String, PeerId), (Entry, Vec<u8>)>,
}

impl Cache {
    fn open(ns: &str, max_bytes: usize, max_records: usize, dir: Option<PathBuf>) -> Cache {
        let mut c = Cache { ns: ns.to_string(), max_bytes, max_records, dir, map: HashMap::new() };
        c.load(now_secs());
        c
    }

    fn load(&mut self, now: u64) {
        let Some(dir) = self.dir.clone() else { return };
        let _ = std::fs::create_dir_all(&dir);
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        let limit = (self.max_bytes + OVERHEAD) as u64;
        for ent in rd.flatten().take(self.max_records.saturating_mul(4)) {
            let path = ent.path();
            if path.extension().is_none_or(|x| x != "rec") {
                continue;
            }
            let bytes = match ent.metadata() {
                Ok(m) if m.is_file() && m.len() <= limit => std::fs::read(&path).ok(),
                _ => None,
            };
            let rec = bytes.as_deref().and_then(Record::verify);
            match rec {
                // Another game's record sharing the dir: leave it alone.
                Some(r) if !r.topic.starts_with(&prefix(&self.ns)) && r.expires > now => continue,
                Some(r) if path.file_name().and_then(|n| n.to_str()) == Some(&file_name(&r.topic, &r.publisher)) => {
                    match admit(&self.ns, &r, self.max_bytes, now) {
                        Some(e) => {
                            self.insert_mem(r, e, now, false);
                        }
                        None => {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    /// Keep `(rec, e)` if newer than what we have; evict to stay bounded.
    /// Returns the evicted entries' file names.
    /// `force` replaces even a longer-lived copy (our own fresh put).
    fn insert_mem(&mut self, rec: Record, e: Entry, now: u64, force: bool) -> Vec<String> {
        let id = (rec.topic.clone(), rec.publisher);
        if !force && self.map.get(&id).is_some_and(|(old, _)| old.expires >= e.expires) {
            return vec![];
        }
        self.map.insert(id, (e, rec.signed));
        let mut gone = Vec::new();
        if self.map.len() > self.max_records {
            self.map.retain(|(t, p), (e, _)| {
                let alive = e.expires > now;
                if !alive {
                    gone.push(file_name(t, p));
                }
                alive
            });
        }
        while self.map.len() > self.max_records {
            let oldest = self.map.iter().min_by_key(|(_, (e, _))| e.expires).map(|(k, _)| k.clone()).unwrap();
            gone.push(file_name(&oldest.0, &oldest.1));
            self.map.remove(&oldest);
        }
        gone
    }

    fn insert(&mut self, rec: &Record, e: &Entry, force: bool) {
        let id = (rec.topic.clone(), rec.publisher);
        let now = now_secs();
        let gone = self.insert_mem(rec.clone(), e.clone(), now, force);
        let Some(dir) = &self.dir else { return };
        for f in gone {
            let _ = std::fs::remove_file(dir.join(f));
        }
        if self.map.get(&id).is_some_and(|(kept, _)| kept == e) {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(dir.join(file_name(&rec.topic, &rec.publisher)), &rec.signed);
        }
    }

    fn get(&self, topic: &str, now: u64) -> Vec<Entry> {
        self.map
            .iter()
            .filter(|((t, _), (e, _))| t == topic && e.expires > now)
            .map(|(_, (e, _))| e.clone())
            .collect()
    }
}

/// Sliding window: at most `rate` events per `window`.
struct Rate {
    rate: usize,
    window: Duration,
    times: VecDeque<Instant>,
}

impl Rate {
    fn allow(&mut self, now: Instant) -> bool {
        while self.times.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            self.times.pop_front();
        }
        if self.times.len() >= self.rate {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

/// Freshest first, then cut at `max_records` / `max_bytes`.
fn cap(mut v: Vec<Entry>, max_records: usize, max_bytes: usize) -> Vec<Entry> {
    v.sort_by(|a, b| b.expires.cmp(&a.expires));
    let mut bytes = 0usize;
    let mut out = Vec::new();
    for e in v {
        if out.len() >= max_records || bytes + e.data.len() > max_bytes {
            break;
        }
        bytes += e.data.len();
        out.push(e);
    }
    out
}

pub struct Records {
    node: Node,
    cfg: RecordsConfig,
    rate: Mutex<Rate>,
    cache: Arc<Mutex<Cache>>,
}

impl Records {
    pub fn new(node: Node, cfg: RecordsConfig) -> Result<Records, RecordError> {
        if !name_ok(&cfg.namespace) {
            return Err(RecordError::BadName);
        }
        let cache = Cache::open(&cfg.namespace, cfg.max_record_bytes, cfg.cache_max_records, cfg.cache_dir.clone());
        Ok(Records {
            node,
            rate: Mutex::new(Rate { rate: cfg.put_rate, window: cfg.put_window, times: VecDeque::new() }),
            cache: Arc::new(Mutex::new(cache)),
            cfg,
        })
    }

    /// Sign and publish `data` under `(kind, key)` for `ttl` (clamped to
    /// `MAX_TTL`). Replaces this node's previous record there.
    pub async fn put(&self, kind: &str, key: &str, data: Vec<u8>, ttl: Duration) -> Result<(), RecordError> {
        let topic = topic(&self.cfg.namespace, kind, key)?;
        if ttl < Duration::from_secs(1) {
            return Err(RecordError::BadTtl);
        }
        if data.len() > self.cfg.max_record_bytes {
            return Err(RecordError::TooLarge);
        }
        if !self.rate.lock().unwrap().allow(Instant::now()) {
            return Err(RecordError::RateLimited);
        }
        let rec = self.node.publish_ttl(&topic, data, ttl.min(MAX_TTL)).await.map_err(RecordError::Net)?;
        if let Some(e) = admit(&self.cfg.namespace, &rec, self.cfg.max_record_bytes, now_secs()) {
            self.cache.lock().unwrap().insert(&rec, &e, true);
        }
        Ok(())
    }

    /// Records under `(kind, key)` from the network and the cache, one per
    /// publisher, freshest first, within the query caps.
    pub async fn query(&self, kind: &str, key: &str) -> Result<Vec<Entry>, RecordError> {
        let topic = topic(&self.cfg.namespace, kind, key)?;
        let found = self.node.find_within(&topic, self.cfg.query_deadline).await.map_err(RecordError::Net)?;
        let mut best: HashMap<PeerId, Entry> = HashMap::new();
        let mut keep = |e: Entry| {
            if best.get(&e.publisher).is_none_or(|old| old.expires < e.expires) {
                best.insert(e.publisher, e);
            }
        };
        let now = now_secs();
        let mut net = Vec::new();
        for rec in found.into_iter().filter(|r| r.topic == topic) {
            if let Some(e) = admit(&self.cfg.namespace, &rec, self.cfg.max_record_bytes, now) {
                net.push((rec, e.clone()));
                keep(e);
            }
        }
        for e in self.cache.lock().unwrap().get(&topic, now) {
            keep(e);
        }
        let out = cap(best.into_values().collect(), self.cfg.query_max_records, self.cfg.query_max_bytes);
        let mut cache = self.cache.lock().unwrap();
        for (rec, e) in net {
            if out.contains(&e) {
                cache.insert(&rec, &e, false);
            }
        }
        Ok(out)
    }

    /// Cached records under `(kind, key)` without touching the network.
    pub fn cached(&self, kind: &str, key: &str) -> Vec<Entry> {
        let Ok(topic) = topic(&self.cfg.namespace, kind, key) else { return vec![] };
        let v = self.cache.lock().unwrap().get(&topic, now_secs());
        cap(v, self.cfg.query_max_records, self.cfg.query_max_bytes)
    }

    /// New records under `(kind, key)` as they are gossiped.
    pub fn subscribe(&self, kind: &str, key: &str) -> Result<Subscription, RecordError> {
        let topic = topic(&self.cfg.namespace, kind, key)?;
        let buf = Arc::new(Mutex::new(Buf {
            q: VecDeque::new(),
            bytes: 0,
            max_records: self.cfg.sub_max_records,
            max_bytes: self.cfg.sub_max_bytes,
            closed: false,
        }));
        let notify = Arc::new(Notify::new());
        let stream = self.node.subscribe(&topic);
        let (ns, max, cache) = (self.cfg.namespace.clone(), self.cfg.max_record_bytes, self.cache.clone());
        let (b, n) = (buf.clone(), notify.clone());
        let task = tokio::spawn(async move {
            let mut stream = Box::pin(stream);
            while let Some(rec) = stream.next().await {
                if rec.topic != topic {
                    continue;
                }
                if let Some(e) = admit(&ns, &rec, max, now_secs()) {
                    cache.lock().unwrap().insert(&rec, &e, false);
                    b.lock().unwrap().push(e);
                    n.notify_one();
                }
            }
            b.lock().unwrap().closed = true;
            n.notify_one();
        });
        Ok(Subscription { buf, notify, task })
    }
}

struct Buf {
    q: VecDeque<Entry>,
    bytes: usize,
    max_records: usize,
    max_bytes: usize,
    closed: bool,
}

impl Buf {
    /// Append, dropping the oldest entries to stay within the caps.
    fn push(&mut self, e: Entry) {
        if e.data.len() > self.max_bytes || self.max_records == 0 {
            return;
        }
        while self.q.len() >= self.max_records || self.bytes + e.data.len() > self.max_bytes {
            let old = self.q.pop_front().unwrap();
            self.bytes -= old.data.len();
        }
        self.bytes += e.data.len();
        self.q.push_back(e);
    }

    fn pop(&mut self) -> Option<Entry> {
        let e = self.q.pop_front()?;
        self.bytes -= e.data.len();
        Some(e)
    }
}

pub struct Subscription {
    buf: Arc<Mutex<Buf>>,
    notify: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Subscription {
    /// Next buffered record; `None` once the node stopped.
    pub async fn next(&mut self) -> Option<Entry> {
        loop {
            {
                let mut b = self.buf.lock().unwrap();
                let now = now_secs();
                while let Some(e) = b.pop() {
                    if e.expires > now {
                        return Some(e);
                    }
                }
                if b.closed {
                    return None;
                }
            }
            self.notify.notified().await;
        }
    }

    /// Next buffered record without waiting.
    pub fn try_next(&mut self) -> Option<Entry> {
        let mut b = self.buf.lock().unwrap();
        let now = now_secs();
        std::iter::from_fn(|| b.pop()).find(|e| e.expires > now)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmos_net::Keypair;

    fn signed(k: &Keypair, ns: &str, kind: &str, key: &str, data: &[u8], ttl: u64) -> Record {
        let t = topic(ns, kind, key).unwrap();
        Record::verify(&Record::sign(k, &t, data.to_vec(), Duration::from_secs(ttl)).unwrap()).unwrap()
    }

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Dir {
            let p = std::env::temp_dir().join(format!("cosmos-rec-unit-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn names_cannot_alias_across_namespaces() {
        assert!(topic("game", "note", "a:b/c d").is_ok());
        for (ns, kind, key) in [("a:b", "k", "x"), ("a", "k/x", "y"), ("", "k", "x"), ("a", "k", ""), ("a", "k", "x\n")] {
            assert!(matches!(topic(ns, kind, key), Err(RecordError::BadName)), "{ns:?} {kind:?} {key:?}");
        }
        let k = Keypair::generate_ed25519();
        let rec = signed(&k, "game-a", "note", "room", b"hi", 60);
        assert!(admit("game-a", &rec, 64, now_secs()).is_some());
        assert!(admit("game-b", &rec, 64, now_secs()).is_none());
        assert!(admit("game", &rec, 64, now_secs()).is_none(), "prefix namespace matched");
        // A record under the join-code topic space is not a record entry.
        let join = Record::verify(&Record::sign(&k, &cosmos_net::topic_for("game-a", "join/ab"), vec![1], Duration::from_secs(60)).unwrap()).unwrap();
        assert!(admit("game-a", &join, 64, now_secs()).is_none());
    }

    #[test]
    fn tampered_or_forged_records_rejected() {
        let k = Keypair::generate_ed25519();
        let good = signed(&k, "game", "note", "room", b"hello", 60).signed;
        assert!(decode("game", &good, 64, now_secs()).is_some());
        let mut bad = good.clone();
        let at = bad.windows(5).position(|w| w == b"hello").unwrap();
        bad[at] ^= 1;
        assert!(decode("game", &bad, 64, now_secs()).is_none(), "modified data accepted");
        let victim = Keypair::generate_ed25519().public().encode_protobuf();
        let mut forged = good.clone();
        forged[4..4 + victim.len()].copy_from_slice(&victim);
        assert!(decode("game", &forged, 64, now_secs()).is_none(), "forged publisher accepted");
    }

    #[test]
    fn expiry_and_size_enforced_on_receive() {
        let k = Keypair::generate_ed25519();
        let rec = signed(&k, "game", "ghost", "k", &[7; 32], 10);
        let now = now_secs();
        assert!(admit("game", &rec, 32, now).is_some());
        assert!(admit("game", &rec, 31, now).is_none(), "oversized accepted");
        assert!(admit("game", &rec, 32, rec.expires).is_none(), "expired accepted");
    }

    #[test]
    fn caps_on_query_subscription_and_rate() {
        let e = |n: u8, exp: u64| Entry { kind: "k".into(), key: "x".into(), publisher: PeerId::random(), data: vec![n; 10], expires: exp };
        let v = vec![e(1, 10), e(2, 30), e(3, 20)];
        let out = cap(v.clone(), 2, 1000);
        assert_eq!(out.iter().map(|e| e.expires).collect::<Vec<_>>(), [30, 20]);
        assert_eq!(cap(v, 10, 25).len(), 2);

        let mut b = Buf { q: VecDeque::new(), bytes: 0, max_records: 3, max_bytes: 25, closed: false };
        for i in 0..5 {
            b.push(e(i, 99));
        }
        assert!(b.q.len() <= 3 && b.bytes <= 25);
        assert_eq!(b.q.back().unwrap().data[0], 4, "newest dropped");
        b.push(Entry { data: vec![0; 26], ..e(9, 99) });
        assert_eq!(b.q.back().unwrap().data[0], 4, "oversized buffered");

        let mut r = Rate { rate: 2, window: Duration::from_secs(10), times: VecDeque::new() };
        let t = Instant::now();
        assert!(r.allow(t) && r.allow(t) && !r.allow(t));
        assert!(r.allow(t + Duration::from_secs(10)));
    }

    #[test]
    fn disk_cache_reloads_bounded_and_ignores_corrupt_files() {
        let dir = Dir::new("cache");
        let k = Keypair::generate_ed25519();
        let mut c = Cache::open("game", 64, 3, Some(dir.0.clone()));
        let put = |c: &mut Cache, key: &str, ttl: u64| {
            let r = signed(&k, "game", "note", key, key.as_bytes(), ttl);
            let e = admit("game", &r, 64, now_secs()).unwrap();
            c.insert(&r, &e, false);
        };
        for (i, key) in ["a", "b", "c", "d"].iter().enumerate() {
            put(&mut c, key, 100 + i as u64 * 10);
        }
        assert!(c.get(&topic("game", "note", "a").unwrap(), now_secs()).is_empty(), "shortest-lived not evicted");
        let files = || std::fs::read_dir(&dir.0).unwrap().count();
        assert_eq!(files(), 3, "evicted file left on disk");

        // Corrupt, truncated, tampered and misnamed files, plus another game's record.
        let real = std::fs::read_dir(&dir.0).unwrap().next().unwrap().unwrap().path();
        let bytes = std::fs::read(&real).unwrap();
        let mut tampered = bytes.clone();
        let n = tampered.len();
        tampered[n - 70] ^= 1;
        std::fs::write(dir.0.join("garbage.rec"), b"junk").unwrap();
        std::fs::write(dir.0.join("trunc.rec"), &bytes[..bytes.len() / 2]).unwrap();
        std::fs::write(dir.0.join("tampered.rec"), &tampered).unwrap();
        std::fs::write(dir.0.join("copy.rec"), &bytes).unwrap();
        let other = signed(&k, "other", "note", "b", b"b", 100);
        let other_name = file_name(&other.topic, &other.publisher);
        std::fs::write(dir.0.join(&other_name), &other.signed).unwrap();
        std::fs::write(dir.0.join("big.rec"), vec![0u8; 64 + OVERHEAD + 1]).unwrap();

        let c2 = Cache::open("game", 64, 3, Some(dir.0.clone()));
        assert_eq!(c2.map.len(), 3);
        for key in ["b", "c", "d"] {
            let got = c2.get(&topic("game", "note", key).unwrap(), now_secs());
            assert_eq!(got.len(), 1, "{key} not reloaded");
            assert_eq!(got[0].data, key.as_bytes());
        }
        assert!(c2.get(&other.topic, now_secs()).is_empty(), "other game's record surfaced");
        assert!(Cache::open("other", 64, 3, Some(dir.0.clone())).get(&other.topic, now_secs()).len() == 1);
        assert_eq!(files(), 4, "bad files not cleaned up: 3 records + other game's");
    }
}
