//! Peer -> SteamID discovery through the DHT record.

use cosmos_net::{Config, Node, PeerId};
use cosmos_steam::{DhtDirectory, SteamDirectory, publish_steam_id};
use std::time::{Duration, Instant};

const KEY: [u8; 32] = [1; 32];

fn base() -> Config {
    Config {
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        mdns: false,
        upnp: false,
        ..Config::default()
    }
}

async fn start(boot: Option<&Node>) -> Node {
    let mut cfg = base();
    if let Some(b) = boot {
        cfg.bootstrap = b.listen_addrs().await;
    }
    let n = Node::start(cfg).await.unwrap();
    if let Some(b) = boot {
        let end = Instant::now() + Duration::from_secs(10);
        while n.connections(b.peer_id()).await.is_empty() {
            assert!(Instant::now() < end, "bootstrap");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    for a in n.listen_addrs().await {
        n.add_external_addr(a);
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn steam_id_record_found_by_peer() {
    let c = start(None).await;
    let a = start(Some(&c)).await;
    let b = start(Some(&c)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let end = Instant::now() + Duration::from_secs(20);
    while let Err(e) = publish_steam_id(&a, &KEY, 76561198000000001).await {
        assert!(Instant::now() < end, "publish: {e}");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let dir = DhtDirectory::new(b);
    // No session key yet: nothing to find.
    assert_eq!(dir.lookup(a.peer_id()).await, None);
    dir.set_key(KEY);
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(s) = dir.lookup(a.peer_id()).await {
            assert_eq!(s, 76561198000000001);
            break;
        }
        assert!(Instant::now() < end, "lookup never found the record");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(dir.lookup(PeerId::random()).await, None);
    // Another session's key finds nothing.
    let other = DhtDirectory::new(c);
    other.set_key([2; 32]);
    assert_eq!(other.lookup(a.peer_id()).await, None);
}
