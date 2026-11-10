//! DHT-signaled hole punch: no relay anywhere.
//!
//! A and B run with `nat_sim`: like a NAT, they refuse inbound connections
//! from any socket they did not dial first. A direct dial A->B is refused,
//! so the only way in is both sides dialing each other, which needs B to
//! learn about A through the DHT punch request.

use futures::StreamExt;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::swarm::SwarmEvent;
use libp2p::{StreamProtocol, Swarm, noise, tcp, yamux};
use cosmos_net::{
    ADDR_TOPIC, Config, ConnectError, Event, Keypair, Multiaddr, Node, PeerId, Record, encode_addrs,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn base() -> Config {
    Config {
        listen: vec![
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        ],
        mdns: false,
        upnp: false,
        punch_poll: Duration::from_millis(300),
        punch_window: Duration::from_secs(6),
        connect_timeout: Duration::from_secs(15),
        ..Config::default()
    }
}

fn natted() -> Config {
    Config {
        nat_sim: true,
        ..base()
    }
}

async fn server(n: &Node) -> Multiaddr {
    let addrs = n.listen_addrs().await;
    for a in &addrs {
        n.add_external_addr(a.clone());
    }
    addrs
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .expect("tcp listen addr")
}

async fn wait_for<F, Fut>(what: &str, secs: u64, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = Instant::now();
    while !f().await {
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn join(c: &Node, cfg: Config) -> Node {
    let boot = server(c).await;
    let n = Node::start(Config {
        bootstrap: vec![boot],
        ..cfg
    })
    .await
    .unwrap();
    wait_for("bootstrap connection", 10, || async {
        !n.connections(c.peer_id()).await.is_empty()
    })
    .await;
    server(&n).await;
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_punch_via_dht_connects_without_relay() {
    let c = Node::start(base()).await.unwrap();
    let a = join(&c, natted()).await;
    let b = join(&c, natted()).await;
    wait_for("B address record in the DHT", 20, || async {
        a.peer_addrs(b.peer_id()).await.is_ok_and(|v| !v.is_empty())
    })
    .await;

    assert!(
        a.try_connect(b.peer_id()).await.is_err() || a.connections(b.peer_id()).await.is_empty(),
        "simulated NAT let a plain direct dial through"
    );

    let mut ev = Box::pin(a.events());
    let t0 = Instant::now();
    timeout(Duration::from_secs(20), a.connect(b.peer_id()))
        .await
        .expect("connect hung")
        .expect("punch via DHT failed");
    println!("punched in {:?}", t0.elapsed());
    assert!(!a.connections(b.peer_id()).await.is_empty());
    let punched = timeout(Duration::from_secs(5), async {
        while let Some(e) = ev.next().await {
            if let Event::HolePunch { peer, ok: true } = e {
                if peer == b.peer_id() {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(punched, "no HolePunch ok event");
    let mut rx = b.rpc_requests().unwrap();
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            let _ = r.reply.send(r.data);
        }
    });
    let echo = timeout(Duration::from_secs(10), a.request(b.peer_id(), b"ping".to_vec()))
        .await
        .expect("rpc hung")
        .expect("rpc over the punched link");
    assert_eq!(echo, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_disabled_nat_pair_has_no_path() {
    let c = Node::start(base()).await.unwrap();
    let off = Config {
        hole_punch: false,
        connect_timeout: Duration::from_secs(6),
        ..natted()
    };
    let a = join(&c, off.clone()).await;
    let b = join(&c, off).await;
    wait_for("B address record in the DHT", 20, || async {
        a.peer_addrs(b.peer_id()).await.is_ok_and(|v| !v.is_empty())
    })
    .await;
    let err = timeout(Duration::from_secs(10), a.connect(b.peer_id()))
        .await
        .expect("connect hung")
        .expect_err("NATed pair connected without a punch");
    assert_eq!(
        err.downcast_ref::<ConnectError>(),
        Some(&ConnectError::NoPath { peer: b.peer_id() })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_peer_yields_no_path_within_timeout() {
    let c = Node::start(base()).await.unwrap();
    let cfg = Config {
        connect_timeout: Duration::from_secs(5),
        ..natted()
    };
    let a = join(&c, cfg.clone()).await;
    let b = join(&c, cfg).await;
    wait_for("B address record in the DHT", 20, || async {
        a.peer_addrs(b.peer_id()).await.is_ok_and(|v| !v.is_empty())
    })
    .await;
    a.block_direct(b.peer_id(), true);
    b.block_direct(a.peer_id(), true);
    let t0 = Instant::now();
    let err = timeout(Duration::from_secs(9), a.connect(b.peer_id()))
        .await
        .expect("connect hung past its timeout")
        .expect_err("blocked peer connected");
    assert_eq!(
        err.downcast_ref::<ConnectError>(),
        Some(&ConnectError::NoPath { peer: b.peer_id() }),
        "{err}"
    );
    assert!(t0.elapsed() < Duration::from_secs(8), "{:?}", t0.elapsed());

    let ghost = PeerId::random();
    let t0 = Instant::now();
    let err = timeout(Duration::from_secs(9), a.connect(ghost))
        .await
        .expect("connect to unknown peer hung")
        .expect_err("unknown peer connected");
    assert_eq!(
        err.downcast_ref::<ConnectError>(),
        Some(&ConnectError::NoPath { peer: ghost })
    );
    assert!(t0.elapsed() < Duration::from_secs(8), "{:?}", t0.elapsed());
}

fn record_key(topic: &str, publisher: &PeerId) -> kad::RecordKey {
    let mut k = Sha256::digest(topic.as_bytes()).to_vec();
    k.extend_from_slice(&publisher.to_bytes());
    kad::RecordKey::new(&k)
}

fn raw_kad() -> Swarm<kad::Behaviour<MemoryStore>> {
    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .unwrap()
        .with_behaviour(|k| {
            let id = k.public().to_peer_id();
            let mut b = kad::Behaviour::with_config(
                id,
                MemoryStore::new(id),
                kad::Config::new(StreamProtocol::new("/cosmos/kad/1.0.0")),
            );
            b.set_mode(Some(kad::Mode::Client));
            b
        })
        .unwrap()
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_addr_record_is_rejected() {
    let c = Node::start(base()).await.unwrap();
    let c_addr = server(&c).await;
    let a = join(&c, base()).await;
    let victim = PeerId::random();
    let attacker = Keypair::generate_ed25519();
    let bogus: Multiaddr = "/ip4/6.6.6.6/tcp/1".parse().unwrap();
    let forged = Record::sign(
        &attacker,
        ADDR_TOPIC,
        encode_addrs(std::slice::from_ref(&bogus)),
        Duration::from_secs(60),
    )
    .unwrap();

    let mut sw = raw_kad();
    sw.behaviour_mut().add_address(&c.peer_id(), c_addr);
    let unsigned = encode_addrs(std::slice::from_ref(&bogus));
    for value in [forged, unsigned] {
        let rec = kad::Record {
            key: record_key(ADDR_TOPIC, &victim),
            value,
            publisher: None,
            expires: None,
        };
        sw.behaviour_mut().put_record(rec, kad::Quorum::One).unwrap();
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::PutRecord(_),
                    ..
                }) = sw.select_next_some().await
                {
                    break;
                }
            }
        })
        .await;
    }
    tokio::spawn(async move {
        loop {
            sw.select_next_some().await;
        }
    });

    let got = a.peer_addrs(victim).await;
    assert!(got.is_err(), "forged address record accepted: {got:?}");
    let err = timeout(Duration::from_secs(25), a.connect(victim))
        .await
        .expect("connect hung")
        .expect_err("connected to a forged address");
    assert!(err.downcast_ref::<ConnectError>().is_some(), "{err}");
}

/// Default punch timing (3s poll, 6s window, 20s budget): the requester and
/// the target must still overlap their dial windows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_connects_with_default_timing() {
    let d = Config::default();
    let cfg = Config {
        punch_poll: d.punch_poll,
        punch_window: d.punch_window,
        connect_timeout: d.connect_timeout,
        ..natted()
    };
    let c = Node::start(base()).await.unwrap();
    let a = join(&c, cfg.clone()).await;
    let b = join(&c, cfg).await;
    wait_for("B address record in the DHT", 20, || async {
        a.peer_addrs(b.peer_id()).await.is_ok_and(|v| !v.is_empty())
    })
    .await;
    let t0 = Instant::now();
    timeout(Duration::from_secs(25), a.connect(b.peer_id()))
        .await
        .expect("connect hung")
        .expect("punch with default timing failed");
    println!("punched (default timing) in {:?}", t0.elapsed());
}

async fn echo_server() -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn echo_ok(sock: &UdpSocket, port: std::net::SocketAddr) -> bool {
    if sock.send_to(b"ping", port).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    matches!(
        timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await,
        Ok(Ok((4, _)))
    )
}

/// A tunnel between two NATed peers must come back after the connection
/// drops, which needs the punch again (the simulated NAT holes are closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn natted_tunnel_recovers_after_drop() {
    let c = Node::start(base()).await.unwrap();
    let a = join(&c, natted()).await;
    let b = join(&c, natted()).await;
    wait_for("B address record in the DHT", 20, || async {
        a.peer_addrs(b.peer_id()).await.is_ok_and(|v| !v.is_empty())
    })
    .await;
    b.set_tunnel_target(echo_server().await);
    b.allow_peer(a.peer_id());
    a.allow_peer(b.peer_id());
    let port = timeout(Duration::from_secs(25), a.open_tunnel(b.peer_id()))
        .await
        .expect("open_tunnel hung")
        .expect("open_tunnel over the punch");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(echo_ok(&sock, port).await, "tunnel echo before drop");

    // Let the simulated NAT holes expire (10s), then drop the link.
    tokio::time::sleep(Duration::from_secs(11)).await;
    a.disconnect(b.peer_id());
    b.disconnect(a.peer_id());
    wait_for("A-B disconnected", 10, || async {
        a.connections(b.peer_id()).await.is_empty()
    })
    .await;
    let start = Instant::now();
    while !echo_ok(&sock, port).await {
        assert!(
            start.elapsed() < Duration::from_secs(28),
            "tunnel did not recover after drop"
        );
    }
    println!("tunnel recovered in {:?}", start.elapsed());
}
