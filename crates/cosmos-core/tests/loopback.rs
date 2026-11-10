//! Four real libp2p nodes on loopback: join by code, full mesh, 1000 reliable
//! messages between every pair, unreliable sanity, 5th peer rejected.

use cosmos_core::code::{self, Advert};
use cosmos_core::{Delivery, JoinError, NetTransport, Session, SessionConfig, SessionEvent};
use cosmos_net::{Config, Multiaddr, Node, PeerId};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const NS: &str = "cosmos-test";
const RELIABLE: u32 = 1000;
const UNRELIABLE: u32 = 100;

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

async fn retry<T, E: std::fmt::Display, F: std::future::Future<Output = Result<T, E>>>(
    what: &str,
    mut f: impl FnMut() -> F,
) -> T {
    let start = Instant::now();
    loop {
        match f().await {
            Ok(v) => return v,
            Err(e) if start.elapsed() < Duration::from_secs(30) => {
                eprintln!("{what} retry: {e}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!("{what} failed: {e}"),
        }
    }
}

async fn advertise_self(n: &Node) -> Vec<Multiaddr> {
    let addrs = n.listen_addrs().await;
    for a in &addrs {
        n.add_external_addr(a.clone());
    }
    addrs
}

async fn start(boot: Option<Multiaddr>) -> Node {
    let n = Node::start(Config { bootstrap: boot.into_iter().collect(), ..base() }).await.unwrap();
    advertise_self(&n).await;
    n
}

fn transport(n: &Node, _cfg: &SessionConfig) -> std::sync::Arc<NetTransport> {
    NetTransport::new(n.clone()).unwrap()
}

async fn joined(s: &mut Session, n: usize) {
    let mut seen = 0;
    while seen < n {
        match timeout(Duration::from_secs(20), s.next_event()).await.expect("membership timeout") {
            Some(SessionEvent::Joined(_)) => seen += 1,
            e => panic!("unexpected {e:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_peers_join_by_code_and_exchange_1k_in_order() {
    let cfg = SessionConfig::default();
    let host_node = start(None).await;
    let boot = host_node
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();
    let mut nodes = vec![];
    for _ in 0..4 {
        nodes.push(start(Some(boot.clone())).await);
    }
    for n in &nodes {
        let h = host_node.peer_id();
        retry("bootstrap", || async {
            if n.connections(h).await.is_empty() { Err("not yet") } else { Ok(()) }
        })
        .await;
    }
    let fifth = nodes.pop().unwrap();

    let addrs = host_node.listen_addrs().await;
    let adv = retry("advertise", || code::advertise(&host_node, NS, addrs.clone())).await;
    let code = code::pretty(&adv.code);
    // Host admits only code holders; joiners derive the secret from the code.
    assert_eq!(adv.secret, code::join_secret(NS, &adv.code));
    let cfg = SessionConfig { join_secret: Some(adv.secret), ..cfg };
    let mut host = Session::host(transport(&host_node, &cfg), cfg.clone()).await.unwrap();

    // The 5th node also publishes a forged advert under the same topic: it
    // copies the host id and real salt but points at its own addresses.
    let host_advert = code::pick(&host_node.find(&code::topic(NS, &adv.code)).await.unwrap(), NS, &adv.code, now())
        .expect("host advert visible");
    let forged = Advert { host: host_node.peer_id(), addrs: fifth.listen_addrs().await, salt: host_advert.salt };
    let topic = code::topic(NS, &adv.code);
    retry("forge", || fifth.publish(&topic, forged.encode(NS))).await;

    let mut members = vec![];
    for n in &nodes {
        let found = retry("resolve", || code::resolve(n, NS, &code)).await;
        assert_eq!(found.host, host_node.peer_id(), "resolved to a forged advert");
        assert_eq!(found.addrs, addrs, "resolved to forged addresses");
        let s = Session::join(transport(n, &cfg), cfg.clone(), found.host, found.addrs)
            .await
            .expect("join");
        members.push(s);
    }
    joined(&mut host, 3).await;
    for m in members.iter_mut() {
        joined(m, 3).await;
    }

    // Members are connected to each other, not only to the host.
    for a in &nodes {
        for b in &nodes {
            if a.peer_id() != b.peer_id() {
                assert!(!a.connections(b.peer_id()).await.is_empty(), "no direct link");
            }
        }
    }

    let found = code::resolve(&fifth, NS, &code).await.unwrap();
    let r = Session::join(transport(&fifth, &cfg), cfg.clone(), found.host, found.addrs).await;
    assert!(matches!(r, Err(JoinError::Full)), "5th peer was not rejected");

    members.push(host);
    let tasks: Vec<_> = members.into_iter().map(|s| tokio::spawn(exchange(s))).collect();
    for t in tasks {
        timeout(Duration::from_secs(90), t).await.expect("exchange timeout").unwrap();
    }
}

/// Send 1000 reliable + 100 unreliable to every other member, then check
/// what arrived: reliable complete and in order, unreliable increasing.
async fn exchange(mut s: Session) {
    let peers = s.members();
    assert_eq!(peers.len(), 3);
    for i in 0..RELIABLE {
        for p in &peers {
            s.send(*p, 1, &i.to_be_bytes(), Delivery::Reliable).unwrap();
        }
    }
    for i in 0..UNRELIABLE {
        for p in &peers {
            s.send(*p, 2, &i.to_be_bytes(), Delivery::Unreliable).unwrap();
        }
    }
    let mut rel: HashMap<PeerId, u32> = HashMap::new();
    let mut unrel: HashMap<PeerId, Vec<u32>> = HashMap::new();
    let done = |rel: &HashMap<PeerId, u32>, unrel: &HashMap<PeerId, Vec<u32>>| {
        peers.iter().all(|p| rel.get(p) == Some(&RELIABLE))
            && peers.iter().all(|p| unrel.get(p).is_some_and(|v| v.last() == Some(&(UNRELIABLE - 1))))
    };
    while !done(&rel, &unrel) {
        let Ok(Some(e)) = timeout(Duration::from_secs(10), s.next_event()).await else {
            break;
        };
        let SessionEvent::Message { from, channel, data, .. } = e else {
            panic!("unexpected {e:?}");
        };
        let n = u32::from_be_bytes(data.try_into().unwrap());
        if channel == 1 {
            let next = rel.entry(from).or_default();
            assert_eq!(n, *next, "reliable out of order from {from}");
            *next += 1;
        } else {
            unrel.entry(from).or_default().push(n);
        }
    }
    for p in &peers {
        assert_eq!(rel.get(p), Some(&RELIABLE), "reliable incomplete from {p}");
        let u = unrel.get(p).expect("no unreliable at all");
        assert!(u.windows(2).all(|w| w[0] < w[1]), "unreliable out of order");
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
