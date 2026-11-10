//! Async plane over real loopback nodes: namespace isolation, TTL expiry,
//! size/rate/receive caps, subscribe delivery and disk cache reload.

use cosmos_core::records::{RecordError, Records, RecordsConfig};
use cosmos_net::{Config, MAX_TTL, Multiaddr, Node};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::timeout;

fn base() -> Config {
    Config {
        listen: vec![
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        ],
        mdns: false,
        upnp: false,
        ..Config::default()
    }
}

async fn server(n: &Node) -> Multiaddr {
    let addrs = n.listen_addrs().await;
    for a in &addrs {
        n.add_external_addr(a.clone());
    }
    addrs.into_iter().find(|a| a.to_string().contains("/tcp/")).unwrap()
}

async fn join(c: &Node) -> Node {
    let boot = server(c).await;
    let n = Node::start(Config { bootstrap: vec![boot], ..base() }).await.unwrap();
    let start = Instant::now();
    while n.connections(c.peer_id()).await.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(10), "bootstrap timeout");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    server(&n).await;
    n
}

async fn mesh3() -> (Node, Node, Node) {
    let c = Node::start(base()).await.unwrap();
    let a = join(&c).await;
    let b = join(&c).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (c, a, b)
}

fn cfg(ns: &str) -> RecordsConfig {
    RecordsConfig { put_rate: 1000, query_deadline: Duration::from_secs(5), ..RecordsConfig::new(ns) }
}

async fn put(r: &Records, kind: &str, key: &str, data: &[u8], ttl: Duration) {
    let start = Instant::now();
    loop {
        match r.put(kind, key, data.to_vec(), ttl).await {
            Ok(()) => return,
            Err(e) if start.elapsed() < Duration::from_secs(20) => {
                eprintln!("put retry: {e}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!("put failed: {e}"),
        }
    }
}

async fn query_until(r: &Records, kind: &str, key: &str, n: usize) -> Vec<cosmos_core::records::Entry> {
    let start = Instant::now();
    loop {
        let got = r.query(kind, key).await.unwrap();
        if got.len() >= n || start.elapsed() > Duration::from_secs(30) {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Temp dir removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("cosmos-rec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namespace_isolation() {
    let (_c, a, b) = mesh3().await;
    let dir = TempDir::new("ns");
    let ra = Records::new(a.clone(), RecordsConfig { cache_dir: Some(dir.0.clone()), ..cfg("game-a") }).unwrap();
    let rb_same = Records::new(b.clone(), cfg("game-a")).unwrap();
    let rb_other = Records::new(b.clone(), cfg("game-b")).unwrap();

    put(&ra, "note", "room1", b"hello from a", Duration::from_secs(60)).await;
    let got = query_until(&rb_same, "note", "room1", 1).await;
    assert_eq!(got.len(), 1, "same namespace must see the record");
    assert_eq!(got[0].publisher, a.peer_id());
    assert_eq!(got[0].data, b"hello from a");
    assert_eq!((got[0].kind.as_str(), got[0].key.as_str()), ("note", "room1"));

    assert!(rb_other.query("note", "room1").await.unwrap().is_empty(), "leaked across namespaces");
    // Same disk cache, other game: nothing surfaces either.
    let rc = Records::new(b.clone(), RecordsConfig { cache_dir: Some(dir.0.clone()), ..cfg("game-b") }).unwrap();
    assert!(rc.cached("note", "room1").is_empty());
    // Names that could alias another namespace's topics are refused.
    assert!(matches!(Records::new(b.clone(), cfg("game-a:rec")), Err(RecordError::BadName)));
    assert!(matches!(rb_other.put("no/te", "k", vec![1], Duration::from_secs(5)).await, Err(RecordError::BadName)));
    assert!(matches!(rb_other.query("", "k").await, Err(RecordError::BadName)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ttl_expiry_and_clamp() {
    let (_c, a, b) = mesh3().await;
    let ra = Records::new(a.clone(), cfg("game")).unwrap();
    let rb = Records::new(b.clone(), cfg("game")).unwrap();
    assert!(matches!(ra.put("ghost", "k", vec![1], Duration::ZERO).await, Err(RecordError::BadTtl)));

    put(&ra, "ghost", "k", b"short", Duration::from_secs(3)).await;
    let got = query_until(&rb, "ghost", "k", 1).await;
    assert_eq!(got.len(), 1);
    let expires = got[0].expires;
    while cosmos_net::now_secs() < expires {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rb.query("ghost", "k").await.unwrap().is_empty(), "expired record served by query");
    assert!(ra.cached("ghost", "k").is_empty(), "expired record served from cache");

    put(&ra, "ghost", "long", b"x", Duration::from_secs(100 * 86400)).await;
    let e = &ra.cached("ghost", "long")[0];
    assert!(e.expires <= cosmos_net::now_secs() + MAX_TTL.as_secs(), "ttl not clamped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn size_rate_and_receive_caps() {
    let (c, a, b) = mesh3().await;
    let small = RecordsConfig { max_record_bytes: 16, ..cfg("game") };
    let ra = Records::new(a.clone(), small.clone()).unwrap();
    assert!(matches!(ra.put("n", "k", vec![0; 17], Duration::from_secs(60)).await, Err(RecordError::TooLarge)));

    let limited = Records::new(a.clone(), RecordsConfig { put_rate: 3, put_window: Duration::from_secs(60), ..cfg("game") }).unwrap();
    for i in 0..3 {
        let r = limited.put("n", &format!("r{i}"), vec![1], Duration::from_secs(60)).await;
        assert!(!matches!(r, Err(RecordError::RateLimited)), "put {i} limited early");
    }
    assert!(matches!(limited.put("n", "r3", vec![1], Duration::from_secs(60)).await, Err(RecordError::RateLimited)));

    let rb = Records::new(b.clone(), cfg("game")).unwrap();
    put(&ra, "n", "shared", b"from-a-8", Duration::from_secs(60)).await;
    put(&rb, "n", "shared", b"from-b-8", Duration::from_secs(60)).await;
    let all = Records::new(c.clone(), cfg("game")).unwrap();
    assert_eq!(query_until(&all, "n", "shared", 2).await.len(), 2);
    let few = Records::new(c.clone(), RecordsConfig { query_max_records: 1, ..cfg("game") }).unwrap();
    assert_eq!(few.query("n", "shared").await.unwrap().len(), 1);
    let thin = Records::new(c.clone(), RecordsConfig { query_max_bytes: 10, ..cfg("game") }).unwrap();
    assert_eq!(thin.query("n", "shared").await.unwrap().len(), 1);
    let tiny = Records::new(c.clone(), RecordsConfig { max_record_bytes: 4, ..cfg("game") }).unwrap();
    assert!(tiny.query("n", "shared").await.unwrap().is_empty(), "oversized record accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_delivers_record_from_other_node() {
    let (_c, a, b) = mesh3().await;
    let ra = Records::new(a.clone(), cfg("game")).unwrap();
    let rb = Records::new(b.clone(), cfg("game")).unwrap();
    let rb_other = Records::new(b.clone(), cfg("other")).unwrap();
    let mut sub = rb.subscribe("ghost", "lvl1").unwrap();
    let mut other = rb_other.subscribe("ghost", "lvl1").unwrap();
    a.connect(b.peer_id()).await.unwrap();
    let start = Instant::now();
    let got = loop {
        let _ = ra.put("ghost", "lvl1", b"run-42".to_vec(), Duration::from_secs(60)).await;
        if let Ok(Some(e)) = timeout(Duration::from_millis(500), sub.next()).await {
            break e;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no record delivered");
    };
    assert_eq!(got.publisher, a.peer_id());
    assert_eq!(got.data, b"run-42");
    assert_eq!((got.kind.as_str(), got.key.as_str()), ("ghost", "lvl1"));
    assert!(other.try_next().is_none(), "other namespace subscription got a record");
    assert_eq!(rb.cached("ghost", "lvl1").len(), 1, "subscription did not cache");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disk_cache_survives_restart() {
    let (_c, a, _b) = mesh3().await;
    let dir = TempDir::new("disk");
    let with_dir = || RecordsConfig { cache_dir: Some(dir.0.clone()), ..cfg("game") };
    {
        let ra = Records::new(a.clone(), with_dir()).unwrap();
        put(&ra, "profile", "me", b"level 12", Duration::from_secs(600)).await;
    }
    std::fs::write(dir.0.join("garbage.rec"), b"not a record").unwrap();
    std::fs::write(dir.0.join("0000.rec"), []).unwrap();
    let lone = Node::start(base()).await.unwrap();
    let r = Records::new(lone, with_dir()).unwrap();
    let got = r.cached("profile", "me");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].publisher, a.peer_id());
    assert_eq!(got[0].data, b"level 12");
}
