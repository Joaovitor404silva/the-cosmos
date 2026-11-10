use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, ping, relay, tcp, yamux};
use cosmos_net::{Config, Event, Multiaddr, Node, PeerId, RpcLimits, is_relayed};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
        auto_relay: false,
        ..Config::default()
    }
}

async fn tcp_addr(n: &Node) -> Multiaddr {
    n.listen_addrs()
        .await
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/") && !is_relayed(a))
        .expect("tcp listen addr")
}

async fn relayed_addr(n: &Node) -> Option<Multiaddr> {
    n.listen_addrs().await.into_iter().find(is_relayed)
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
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn echo_rpc(n: &Node) {
    let mut rx = n.rpc_requests().expect("rpc receiver");
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            let _ = r.reply.send(r.data);
        }
    });
}

async fn counting_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((n, from)) = s.recv_from(&mut buf).await {
                h.fetch_add(1, Ordering::SeqCst);
                let _ = s.send_to(&buf[..n], from).await;
            }
        }
    });
    (addr, hits)
}

#[derive(NetworkBehaviour)]
struct Kubo {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

async fn kubo_like_relay() -> (PeerId, Multiaddr) {
    let mut sw = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|k| {
            let id = k.public().to_peer_id();
            let cfg = relay::Config {
                max_circuit_duration: Duration::from_secs(120),
                max_circuit_bytes: 128 << 10,
                ..Default::default()
            };
            Kubo {
                relay: relay::Behaviour::new(id, cfg),
                identify: identify::Behaviour::new(identify::Config::new(
                    "ipfs/0.1.0".into(),
                    k.public(),
                )),
                ping: ping::Behaviour::default(),
            }
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    sw.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = sw.select_next_some().await {
            break address;
        }
    };
    sw.add_external_address(addr.clone());
    let id = *sw.local_peer_id();
    tokio::spawn(async move {
        loop {
            sw.select_next_some().await;
        }
    });
    (id, addr.with(libp2p::multiaddr::Protocol::P2p(id)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_flood_of_header_only_streams_stays_bounded() {
    let limits = RpcLimits {
        read_timeout: Duration::from_secs(1),
        ..RpcLimits::default()
    };
    let c = Node::start(Config {
        rpc: limits.clone(),
        ..base()
    })
    .await
    .unwrap();
    echo_rpc(&c);
    let c_addr = tcp_addr(&c).await;
    let header = (limits.max_request as u32).to_be_bytes();

    let mut attackers = Vec::new();
    for _ in 0..6 {
        let n = Node::start(base()).await.unwrap();
        n.dial(c_addr.clone()).await.unwrap();
        attackers.push(n);
    }
    for n in &attackers {
        wait_for("attacker connected", 10, || async {
            !n.connections(c.peer_id()).await.is_empty()
        })
        .await;
    }

    let peak_seen = Arc::new(AtomicUsize::new(0));
    let watch = {
        let (c, peak) = (c.clone(), peak_seen.clone());
        tokio::spawn(async move {
            loop {
                peak.fetch_max(c.rpc_stats().in_flight, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };

    let mut tasks = Vec::new();
    for n in attackers.clone() {
        let target = c.peer_id();
        tasks.push(tokio::spawn(async move {
            let opens = (0..100).map(|_| async {
                let mut s = n.open_rpc_stream(target).await.ok()?;
                let _ = s.write_all(&header).await;
                let _ = s.flush().await;
                Some(s)
            });
            let streams: Vec<_> = futures::future::join_all(opens)
                .await
                .into_iter()
                .flatten()
                .collect();
            let opened = streams.len();
            let mut dropped = 0;
            for mut s in streams {
                let mut b = [0u8; 1];
                if let Ok(r) = timeout(Duration::from_secs(5), s.read(&mut b)).await {
                    if !matches!(r, Ok(n) if n > 0) {
                        dropped += 1;
                    }
                }
            }
            (opened, dropped)
        }));
    }
    let mut opened = 0;
    let mut dropped = 0;
    for t in tasks {
        let (o, d) = t.await.unwrap();
        opened += o;
        dropped += d;
    }
    wait_for("in-flight back to 0", 10, || async {
        c.rpc_stats().in_flight == 0
    })
    .await;
    watch.abort();
    let s = c.rpc_stats();
    println!(
        "flood: opened={opened} dropped_by_server={dropped} peak_polled={} stats={s:?}",
        peak_seen.load(Ordering::SeqCst)
    );
    assert_eq!(
        opened,
        attackers.len() * 100,
        "unexpected number of client streams opened"
    );
    assert_eq!(
        dropped, opened,
        "every stalled stream must be closed by the server"
    );
    assert!(
        s.peak_in_flight <= limits.max_in_flight,
        "global cap exceeded: {s:?}"
    );
    assert!(peak_seen.load(Ordering::SeqCst) <= limits.max_in_flight);
    assert!(
        s.peak_in_flight_per_peer <= limits.max_in_flight_per_peer,
        "per-peer cap exceeded: {s:?}"
    );
    assert!(
        s.accepted >= 1
            && s.accepted <= attackers.len() as u64 * limits.max_in_flight_per_peer as u64
    );
    assert!(
        s.rejected_busy + s.rejected_rate >= opened as u64 - s.accepted,
        "{s:?}"
    );
    assert_eq!(
        s.timed_out, s.accepted,
        "admitted header-only streams must time out: {s:?}"
    );
    assert_eq!(s.served, 0);
    assert!(
        s.peak_buffered <= limits.max_in_flight * limits.max_request,
        "{s:?}"
    );
    assert_eq!(
        s.peak_buffered, 0,
        "nothing beyond the header was sent, nothing may be buffered: {s:?}"
    );

    let good = Node::start(base()).await.unwrap();
    good.dial(c_addr.clone()).await.unwrap();
    let out = timeout(
        Duration::from_secs(10),
        good.request(c.peer_id(), b"still alive".to_vec()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out, b"still alive");
    assert_eq!(c.rpc_stats().served, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_per_peer_rate_limit_rejects_burst() {
    let limits = RpcLimits {
        burst: 5,
        per_peer_per_sec: 1,
        ..RpcLimits::default()
    };
    let c = Node::start(Config {
        rpc: limits,
        ..base()
    })
    .await
    .unwrap();
    echo_rpc(&c);
    let c_addr = tcp_addr(&c).await;
    let a = Node::start(base()).await.unwrap();
    let b = Node::start(base()).await.unwrap();
    a.dial(c_addr.clone()).await.unwrap();
    b.dial(c_addr.clone()).await.unwrap();
    wait_for("a connected", 10, || async {
        !a.connections(c.peer_id()).await.is_empty()
    })
    .await;
    wait_for("b connected", 10, || async {
        !b.connections(c.peer_id()).await.is_empty()
    })
    .await;

    let burst = (0..20).map(|i| a.request(c.peer_id(), format!("req-{i}").into_bytes()));
    let results = futures::future::join_all(burst).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    let s = c.rpc_stats();
    println!("burst of 20: ok={ok} stats={s:?}");
    assert!(
        (5..=6).contains(&ok),
        "expected about burst=5 successes, got {ok}"
    );
    assert!(s.rejected_rate >= 14, "{s:?}");

    let out = b
        .request(c.peer_id(), b"other peer".to_vec())
        .await
        .unwrap();
    assert_eq!(out, b"other peer");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let out = a
        .request(c.peer_id(), b"after refill".to_vec())
        .await
        .unwrap();
    assert_eq!(out, b"after refill");
}

async fn reserve_on(n: &Node, relay: &Multiaddr) -> Multiaddr {
    n.dial(relay.clone()).await.unwrap();
    wait_for("public relay reservation", 20, || async {
        relayed_addr(n).await.is_some()
    })
    .await;
    relayed_addr(n).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nat_to_nat_hole_punch_runs_tunnel_direct() {
    let (r_id, r_addr) = kubo_like_relay().await;
    let (echo, hits) = counting_echo().await;
    let cfg = Config {
        relays: vec![r_addr.clone()],
        public_relays: 0,
        ..base()
    };
    let a = Node::start(cfg.clone()).await.unwrap();
    let b = Node::start(Config {
        tunnel_target: Some(echo),
        ..cfg
    })
    .await
    .unwrap();
    for addr in a
        .listen_addrs()
        .await
        .into_iter()
        .filter(|addr| !is_relayed(addr))
    {
        a.add_external_addr(addr);
    }
    for addr in b
        .listen_addrs()
        .await
        .into_iter()
        .filter(|addr| !is_relayed(addr))
    {
        b.add_external_addr(addr);
    }
    let mut a_ev = Box::pin(a.events());
    let mut b_ev = Box::pin(b.events());
    let circuit = reserve_on(&b, &r_addr).await;
    assert!(
        circuit.to_string().contains(&r_id.to_string()),
        "circuit {circuit} not via R"
    );
    b.allow_peer(a.peer_id());
    a.allow_peer(b.peer_id());
    a.dial(circuit.clone()).await.unwrap();
    wait_for("relayed A->B", 20, || async {
        !a.connections(b.peer_id()).await.is_empty()
    })
    .await;

    let port = timeout(Duration::from_secs(30), a.open_tunnel(b.peer_id()))
        .await
        .expect("open_tunnel hung")
        .expect("open_tunnel");
    let t = a.tunnels().await;
    assert!(
        t.len() == 1 && !t[0].relayed,
        "tunnel must run direct: {t:?}"
    );
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 2048];
    for i in 0..50u32 {
        let msg = format!("game-{i}").into_bytes();
        sock.send_to(&msg, port).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&buf[..n], &msg[..]);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 50);

    let mut punched = false;
    let mut seen = Vec::new();
    for ev in [&mut a_ev, &mut b_ev] {
        while let Ok(Some(e)) = timeout(Duration::from_millis(200), ev.next()).await {
            if let Event::HolePunch { .. } = e {
                punched = true;
            }
            seen.push(format!("{e:?}"));
        }
    }
    assert!(punched, "dcutr never ran: {seen:#?}");
    assert!(
        a.connections(b.peer_id())
            .await
            .iter()
            .any(|address| !is_relayed(address))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nat_to_nat_without_direct_reports_no_direct_and_keeps_rpc() {
    let (_r_id, r_addr) = kubo_like_relay().await;
    let (echo, hits) = counting_echo().await;
    let cfg = Config {
        listen: vec![],
        public_relays: 1,
        direct_grace: Duration::from_secs(6),
        ..base()
    };
    let a = Node::start(cfg.clone()).await.unwrap();
    let b = Node::start(Config {
        tunnel_target: Some(echo),
        ..cfg
    })
    .await
    .unwrap();
    echo_rpc(&b);
    let mut a_ev = Box::pin(a.events());
    let circuit = reserve_on(&b, &r_addr).await;
    b.allow_peer(a.peer_id());
    a.allow_peer(b.peer_id());
    a.dial(circuit.clone()).await.unwrap();
    wait_for("relayed A->B", 20, || async {
        !a.connections(b.peer_id()).await.is_empty()
    })
    .await;

    let t0 = Instant::now();
    let r = timeout(Duration::from_secs(30), a.open_tunnel(b.peer_id()))
        .await
        .expect("open_tunnel hung");
    let err = r.expect_err("tunnel must not run over a public relay");
    println!("open_tunnel after {:?}: {err}", t0.elapsed());
    assert!(err.to_string().contains("no direct path"), "{err}");
    let no_direct = timeout(Duration::from_secs(5), async {
        while let Some(e) = a_ev.next().await {
            if let Event::TunnelNoDirect { peer, .. } = e {
                return peer;
            }
        }
        unreachable!()
    })
    .await
    .expect("no TunnelNoDirect event");
    assert_eq!(no_direct, b.peer_id());
    assert!(a.tunnels().await.is_empty() && b.tunnels().await.is_empty());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "game bytes crossed the public relay"
    );
    let cs = a.connections(b.peer_id()).await;
    assert!(!cs.is_empty() && cs.iter().all(is_relayed), "{cs:?}");

    let out = timeout(
        Duration::from_secs(10),
        a.request(b.peer_id(), b"control".to_vec()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out, b"control");
}
