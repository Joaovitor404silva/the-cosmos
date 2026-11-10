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
//! - The newest record of a publisher wins, by its signed issue time (not
//!   its expiry), so an update with a shorter TTL still replaces the old one
//!   and a replayed older record never does.
//! - A bounded cache keeps recently seen records, optionally on disk under
//!   `cache_dir/<namespace>/` (one file of signed bytes per record, written
//!   by a background thread). A flood on one topic evicts from that topic
//!   first; our own records are evicted last. Invalid files in that folder
//!   are removed; nothing outside it is touched.

use cosmos_net::{MAX_TTL, Node, PeerId, Record, now_secs};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
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
    /// Keep recently seen records across restarts, in `cache_dir/<namespace>`.
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
    /// Unix milliseconds when the publisher signed it (newer = larger).
    pub issued: u64,
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
        issued: rec.issued,
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

fn is_cache_name(n: &str) -> bool {
    n.len() == 36 && n.ends_with(".rec") && n[..32].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

enum DiskOp {
    Write(String, Vec<u8>),
    Remove(String),
    #[cfg(test)]
    Flush(std::sync::mpsc::Sender<()>),
}

/// Applies disk ops off the async runtime, coalescing bursts per file.
fn disk_writer(dir: PathBuf, rx: Receiver<DiskOp>) {
    while let Ok(op) = rx.recv() {
        let mut batch: HashMap<String, Option<Vec<u8>>> = HashMap::new();
        #[allow(unused_mut)]
        let mut flushed: Vec<std::sync::mpsc::Sender<()>> = Vec::new();
        for op in std::iter::once(op).chain(rx.try_iter()) {
            match op {
                DiskOp::Write(n, b) => drop(batch.insert(n, Some(b))),
                DiskOp::Remove(n) => drop(batch.insert(n, None)),
                #[cfg(test)]
                DiskOp::Flush(tx) => flushed.push(tx),
            }
        }
        for (n, b) in batch {
            let _ = match b {
                Some(b) => std::fs::write(dir.join(n), b),
                None => std::fs::remove_file(dir.join(n)),
            };
        }
        for tx in flushed.drain(..) {
            let _ = tx.send(());
        }
    }
}

/// Recently seen records of one namespace, bounded, optionally on disk.
struct Cache {
    ns: String,
    me: PeerId,
    max_bytes: usize,
    max_records: usize,
    disk: Option<SyncSender<DiskOp>>,
    writer: Option<std::thread::JoinHandle<()>>,
    map: HashMap<(String, PeerId), (Entry, Vec<u8>)>,
}

impl Cache {
    fn open(ns: &str, me: PeerId, max_bytes: usize, max_records: usize, dir: Option<PathBuf>) -> Cache {
        let mut c = Cache { ns: ns.to_string(), me, max_bytes, max_records, disk: None, writer: None, map: HashMap::new() };
        if let Some(dir) = dir.map(|d| d.join(ns))
            && std::fs::create_dir_all(&dir).is_ok()
        {
            c.load(&dir, now_secs());
            let (tx, rx) = sync_channel(4096);
            let d = dir.clone();
            if let Ok(w) = std::thread::Builder::new().name("cosmos-rec-disk".into()).spawn(move || disk_writer(d, rx)) {
                c.disk = Some(tx);
                c.writer = Some(w);
            }
        }
        c
    }

    /// Load `dir` (ours alone). Files that don't hold a live record of this
    /// namespace under their own name are removed; other names are left.
    fn load(&mut self, dir: &std::path::Path, now: u64) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let limit = (self.max_bytes + OVERHEAD) as u64;
        let ours = rd
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(is_cache_name))
            .take(self.max_records.saturating_mul(4).max(16));
        for ent in ours {
            let path = ent.path();
            let bytes = match ent.metadata() {
                Ok(m) if m.is_file() && m.len() <= limit => std::fs::read(&path).ok(),
                _ => None,
            };
            let named = |r: &Record| ent.file_name().to_str() == Some(&file_name(&r.topic, &r.publisher));
            let ok = bytes
                .as_deref()
                .and_then(Record::verify)
                .filter(named)
                .and_then(|r| admit(&self.ns, &r, self.max_bytes, now).map(|e| (r, e)));
            match ok {
                Some((r, e)) => {
                    for f in self.insert_mem(r, e, now) {
                        let _ = std::fs::remove_file(dir.join(f));
                    }
                }
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    /// Keep `(rec, e)` if newer than what we have from that publisher;
    /// evict to stay bounded. Returns the evicted entries' file names.
    fn insert_mem(&mut self, rec: Record, e: Entry, now: u64) -> Vec<String> {
        let id = (rec.topic.clone(), rec.publisher);
        if self.map.get(&id).is_some_and(|(old, _)| old.issued >= e.issued) {
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
            let k = self.victim();
            gone.push(file_name(&k.0, &k.1));
            self.map.remove(&k);
        }
        gone
    }

    /// Oldest foreign record of the topic holding the most foreign records
    /// (so a flood on one topic pays for itself); our own only when nothing
    /// else is left.
    fn victim(&self) -> (String, PeerId) {
        let mut per: HashMap<&str, usize> = HashMap::new();
        for (t, p) in self.map.keys() {
            if *p != self.me {
                *per.entry(t).or_default() += 1;
            }
        }
        // Ties between topics go to the oldest record among them.
        let top = per.values().copied().max();
        self.map
            .iter()
            .filter(|((t, p), _)| top.is_none_or(|n| *p != self.me && per[t.as_str()] == n))
            .min_by_key(|(k, (e, _))| (e.issued, k.1))
            .map(|(k, _)| k.clone())
            .unwrap()
    }

    fn send(&self, op: DiskOp) {
        if let Some(tx) = &self.disk
            && let Err(TrySendError::Full(_)) = tx.try_send(op)
        {
            tracing::debug!("record cache disk queue full; op dropped");
        }
    }

    fn insert(&mut self, rec: &Record, e: &Entry) {
        let id = (rec.topic.clone(), rec.publisher);
        let gone = self.insert_mem(rec.clone(), e.clone(), now_secs());
        if self.disk.is_none() {
            return;
        }
        for f in gone {
            self.send(DiskOp::Remove(f));
        }
        if self.map.get(&id).is_some_and(|(kept, _)| kept == e) {
            self.send(DiskOp::Write(file_name(&rec.topic, &rec.publisher), rec.signed.clone()));
        }
    }

    #[cfg(test)]
    fn flush(&self) {
        if let Some(tx) = &self.disk {
            let (ftx, frx) = std::sync::mpsc::channel();
            tx.send(DiskOp::Flush(ftx)).unwrap();
            frx.recv().unwrap();
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

impl Drop for Cache {
    /// Finish queued disk writes, so a reopened cache sees them.
    fn drop(&mut self) {
        self.disk = None;
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
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
/// Issue times past now (clock skew) rank as now.
fn cap(mut v: Vec<Entry>, max_records: usize, max_bytes: usize) -> Vec<Entry> {
    let now = cosmos_net::now_ms();
    v.sort_by(|a, b| b.issued.min(now).cmp(&a.issued.min(now)));
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
        let cache = Cache::open(&cfg.namespace, node.peer_id(), cfg.max_record_bytes, cfg.cache_max_records, cfg.cache_dir.clone());
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
            self.cache.lock().unwrap().insert(&rec, &e);
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
            if best.get(&e.publisher).is_none_or(|old| old.issued < e.issued) {
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
                cache.insert(&rec, &e);
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
                    cache.lock().unwrap().insert(&rec, &e);
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
        let e = |n: u8, iss: u64| Entry { kind: "k".into(), key: "x".into(), publisher: PeerId::random(), data: vec![n; 10], issued: iss, expires: 99 };
        let v = vec![e(1, 10), e(2, 30), e(3, 20)];
        let out = cap(v.clone(), 2, 1000);
        assert_eq!(out.iter().map(|e| e.issued).collect::<Vec<_>>(), [30, 20]);
        // A future issue time does not outrank a record issued now.
        let now = cosmos_net::now_ms();
        let out = cap(vec![e(1, now + 100_000), e(2, now)], 2, 1000);
        assert_eq!(out.len(), 2);
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

    fn put_in(c: &mut Cache, k: &Keypair, kind: &str, key: &str, ttl: u64) -> Record {
        let r = signed(k, "game", kind, key, key.as_bytes(), ttl);
        let e = admit("game", &r, 64, now_secs()).unwrap();
        c.insert(&r, &e);
        r
    }

    #[test]
    fn disk_cache_reloads_bounded_and_ignores_corrupt_files() {
        let dir = Dir::new("cache");
        let ours = dir.0.join("game");
        let k = Keypair::generate_ed25519();
        let me = PeerId::random();
        let mut c = Cache::open("game", me, 64, 3, Some(dir.0.clone()));
        for (i, key) in ["a", "b", "c", "d"].iter().enumerate() {
            put_in(&mut c, &k, "note", key, 100 + i as u64 * 10);
        }
        assert!(c.get(&topic("game", "note", "a").unwrap(), now_secs()).is_empty(), "oldest not evicted");
        c.flush();
        let files = |d: &PathBuf| std::fs::read_dir(d).unwrap().count();
        assert_eq!(files(&ours), 3, "evicted file left on disk");

        // Corrupt, truncated, tampered and misnamed files in our folder;
        // unrelated files next to it and in it must survive.
        let real = std::fs::read_dir(&ours).unwrap().next().unwrap().unwrap().path();
        let bytes = std::fs::read(&real).unwrap();
        let mut tampered = bytes.clone();
        let n = tampered.len();
        tampered[n - 70] ^= 1;
        let fake = |c: char| format!("{}.rec", c.to_string().repeat(32));
        std::fs::write(ours.join(fake('0')), b"junk").unwrap();
        std::fs::write(ours.join(fake('1')), &bytes[..bytes.len() / 2]).unwrap();
        std::fs::write(ours.join(fake('2')), &tampered).unwrap();
        std::fs::write(ours.join(fake('3')), &bytes).unwrap();
        std::fs::write(ours.join(fake('4')), vec![0u8; 64 + OVERHEAD + 1]).unwrap();
        let other = signed(&k, "other", "note", "b", b"b", 100);
        std::fs::write(ours.join(file_name(&other.topic, &other.publisher)), &other.signed).unwrap();
        std::fs::write(ours.join("notes.txt"), b"user file").unwrap();
        std::fs::write(dir.0.join("someone-else.rec"), b"not ours").unwrap();
        drop(c);

        let c2 = Cache::open("game", me, 64, 3, Some(dir.0.clone()));
        assert_eq!(c2.map.len(), 3);
        for key in ["b", "c", "d"] {
            let got = c2.get(&topic("game", "note", key).unwrap(), now_secs());
            assert_eq!(got.len(), 1, "{key} not reloaded");
            assert_eq!(got[0].data, key.as_bytes());
        }
        assert!(c2.get(&other.topic, now_secs()).is_empty(), "other game's record surfaced");
        assert_eq!(files(&ours), 4, "bad files not cleaned up: 3 records + notes.txt");
        assert!(dir.0.join("someone-else.rec").exists(), "deleted a file outside our folder");
    }

    #[test]
    fn load_evicts_extra_files_and_is_not_starved_by_junk() {
        let dir = Dir::new("load");
        let k = Keypair::generate_ed25519();
        let me = PeerId::random();
        let ours = dir.0.join("game");
        std::fs::create_dir_all(&ours).unwrap();
        for i in 0..40 {
            std::fs::write(ours.join(format!("junk{i:02}.bin")), b"x").unwrap();
        }
        // More valid records on disk than the cache holds.
        for key in ["a", "b", "c", "d", "e"] {
            let r = signed(&k, "game", "note", key, key.as_bytes(), 100);
            std::fs::write(ours.join(file_name(&r.topic, &r.publisher)), &r.signed).unwrap();
        }
        let c = Cache::open("game", me, 64, 3, Some(dir.0.clone()));
        assert_eq!(c.map.len(), 3, "records not loaded past junk");
        let recs = std::fs::read_dir(&ours).unwrap().flatten().filter(|e| e.file_name().to_str().is_some_and(is_cache_name)).count();
        assert_eq!(recs, 3, "files evicted during load left on disk");
    }

    #[test]
    fn flood_on_one_topic_spares_other_topics_and_our_own() {
        let me = Keypair::generate_ed25519();
        let mut c = Cache::open("game", me.public().to_peer_id(), 64, 8, None);
        put_in(&mut c, &me, "note", "mine", 60);
        let honest = Keypair::generate_ed25519();
        put_in(&mut c, &honest, "note", "lobby", 60);
        // Sybils with the longest TTL and freshest issue flood one key.
        for _ in 0..50 {
            put_in(&mut c, &Keypair::generate_ed25519(), "note", "spam", 1800);
        }
        let now = now_secs();
        assert_eq!(c.map.len(), 8);
        assert_eq!(c.get(&topic("game", "note", "mine").unwrap(), now).len(), 1, "own record evicted");
        assert_eq!(c.get(&topic("game", "note", "lobby").unwrap(), now).len(), 1, "other topic evicted by flood");
    }

    #[test]
    fn newer_issue_replaces_longer_lived_record() {
        let k = Keypair::generate_ed25519();
        let mut c = Cache::open("game", PeerId::random(), 64, 8, None);
        let t = topic("game", "note", "x").unwrap();
        let old = signed(&k, "game", "note", "x", b"v1", 1800);
        let new = signed(&k, "game", "note", "x", b"v2", 60);
        c.insert(&new, &admit("game", &new, 64, now_secs()).unwrap());
        // A replay of the older, longer-lived record loses.
        c.insert(&old, &admit("game", &old, 64, now_secs()).unwrap());
        assert_eq!(c.get(&t, now_secs())[0].data, b"v2");
    }
}
