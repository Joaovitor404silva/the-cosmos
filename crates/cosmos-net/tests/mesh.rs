use futures::StreamExt;
use cosmos_net::{Config, ConnLimits, Event, Keypair, Multiaddr, Node, PeerId};
use std::future::Future;
use std::net::SocketAddr;
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
        ..Config::default()
    }
}

async fn tcp_addr(n: &Node) -> Multiaddr {
    n.listen_addrs()
        .await
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .expect("tcp listen addr")
}

async fn server(n: &Node) -> Multiaddr {
    let a = tcp_addr(n).await;
    for addr in n
        .listen_addrs()
        .await
        .into_iter()
    {
        n.add_external_addr(addr);
    }
    a
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

async fn tagged_echo(tag: &'static [u8]) -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((n, from)) = s.recv_from(&mut buf).await {
                let mut out = tag.to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = s.send_to(&out, from).await;
            }
        }
    });
    addr
}

async fn echo_server() -> SocketAddr {
    tagged_echo(b"").await
}

async fn ask(sock: &UdpSocket, port: SocketAddr, msg: &[u8]) -> Vec<u8> {
    sock.send_to(msg, port).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    buf[..n].to_vec()
}

async fn open_with_retry(a: &Node, b: PeerId) -> SocketAddr {
    a.allow_peer(b);
    let start = Instant::now();
    loop {
        match a.open_tunnel(b).await {
            Ok(p) => return p,
            Err(e) if start.elapsed() < Duration::from_secs(30) => {
                eprintln!("open_tunnel retry: {e}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!("open_tunnel failed: {e}"),
        }
    }
}

async fn echo_rounds(port: SocketAddr, n: usize) -> Vec<Duration> {
    echo_rounds_paced(port, n, Duration::ZERO).await
}

async fn echo_rounds_paced(port: SocketAddr, n: usize, gap: Duration) -> Vec<Duration> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut rtts = Vec::with_capacity(n);
    let mut buf = vec![0u8; 65535];
    for i in 0..n {
        let mut msg = format!("dgram-{i}-").into_bytes();
        msg.extend((0..(i * 13) % 1200).map(|j| (i + j) as u8));
        let t = Instant::now();
        s.send_to(&msg, port).await.unwrap();
        let (got, _) = timeout(Duration::from_secs(5), s.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("echo {i} timed out"))
            .unwrap();
        rtts.push(t.elapsed());
        assert_eq!(&buf[..got], &msg[..], "echo {i} corrupted");
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }
    rtts
}

fn report(label: &str, mut rtts: Vec<Duration>) {
    rtts.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let avg = rtts.iter().map(|d| us(*d)).sum::<f64>() / rtts.len() as f64;
    println!(
        "RTT {label}: n={} min={:.0}us median={:.0}us avg={:.0}us p95={:.0}us max={:.0}us",
        rtts.len(),
        us(rtts[0]),
        us(rtts[rtts.len() / 2]),
        avg,
        us(rtts[rtts.len() * 95 / 100]),
        us(*rtts.last().unwrap())
    );
}

async fn next_closed(
    ev: &mut (impl futures::Stream<Item = Event> + Unpin),
    peer: PeerId,
) -> String {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(Event::TunnelClosed {
                peer: p, reason, ..
            }) = ev.next().await
            {
                if p == peer {
                    return reason;
                }
            }
        }
    })
    .await
    .expect("no TunnelClosed event")
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    server(&n).await;
    n
}

async fn mesh3() -> (Node, Node, Node) {
    let c = Node::start(base()).await.unwrap();
    let a = join(&c, base()).await;
    let b = join(&c, base()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (c, a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_published_by_a_is_found_by_b_via_c() {
    let (_c, a, b) = mesh3().await;
    let topic = cosmos_net::topic_for("demo", "lobby");

    let start = Instant::now();
    loop {
        match a.publish(&topic, b"lobby-advert:player-a".to_vec()).await {
            Ok(()) => break,
            Err(e) if start.elapsed() < Duration::from_secs(20) => {
                eprintln!("publish retry: {e}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!("publish failed: {e}"),
        }
    }

    let found = timeout(Duration::from_secs(30), b.find(&topic))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.len(), 1, "found {found:?}");
    assert_eq!(found[0].publisher, a.peer_id());
    assert_eq!(found[0].data, b"lobby-advert:player-a");
    assert_eq!(found[0].topic, topic);
    assert!(b.find("demo:other").await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_echo_through_direct_tunnel() {
    let echo = echo_server().await;
    report("baseline (no tunnel)", echo_rounds(echo, 100).await);

    let (_c, a, b) = mesh3().await;
    b.set_tunnel_target(echo);
    b.allow_peer(a.peer_id());

    let port = open_with_retry(&a, b.peer_id()).await;
    assert_eq!(port.ip().to_string(), "127.0.0.1");
    let rtts = echo_rounds(port, 100).await;
    assert_eq!(rtts.len(), 100);
    let conns = a.connections(b.peer_id()).await;
    println!("A->B connections: {conns:?}");
    assert!(!conns.is_empty(), "expected a direct connection");
    report("direct tunnel", rtts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_subscribe_receives_signed_record() {
    let (_c, a, b) = mesh3().await;
    let topic = cosmos_net::topic_for("demo", "chat");
    let _a_sub = a.subscribe(&topic);
    let mut sub = Box::pin(b.subscribe(&topic));
    a.connect(b.peer_id()).await.unwrap();
    let start = Instant::now();
    let got = loop {
        let _ = a.publish(&topic, b"room-advert".to_vec()).await;
        if let Ok(Some(r)) = timeout(Duration::from_millis(500), sub.next()).await {
            break r;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "no gossip record arrived"
        );
    };
    assert_eq!(got.publisher, a.peer_id());
    assert_eq!(got.data, b"room-advert");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_is_live_and_missing_target_rejects() {
    let one = tagged_echo(b"1:").await;
    let two = tagged_echo(b"2:").await;
    let (_c, a, b) = mesh3().await;
    b.allow_peer(a.peer_id());
    a.connect(b.peer_id()).await.unwrap();
    a.allow_peer(b.peer_id());
    let err = a.open_tunnel(b.peer_id()).await;
    assert!(
        err.is_err(),
        "open_tunnel without target should fail, got {err:?}"
    );
    assert!(a.tunnels().await.is_empty());
    assert!(b.tunnels().await.is_empty());

    b.set_tunnel_target(one);
    let port = a.open_tunnel(b.peer_id()).await.unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(ask(&s, port, b"x").await, b"1:x");
    b.set_tunnel_target(two);
    assert_eq!(ask(&s, port, b"y").await, b"2:y");
    b.set_peer_target(a.peer_id(), Some(one));
    assert_eq!(ask(&s, port, b"z").await, b"1:z");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tunnel_per_pair_and_close_notifies_both() {
    let echo = echo_server().await;
    let (_c, a, b) = mesh3().await;
    let app_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.set_tunnel_target(app_a.local_addr().unwrap());
    b.set_tunnel_target(echo);
    a.allow_peer(b.peer_id());
    b.allow_peer(a.peer_id());
    let pa = open_with_retry(&a, b.peer_id()).await;
    let pb = b.open_tunnel(a.peer_id()).await.unwrap();
    let ta = a.tunnels().await;
    let tb = b.tunnels().await;
    assert_eq!(ta.len(), 1, "{ta:?}");
    assert_eq!(tb.len(), 1, "{tb:?}");
    assert_eq!(
        tb[0].local, pb,
        "B's open_tunnel must reuse the accepted tunnel"
    );
    assert_eq!(ta[0].local, pa);
    assert_eq!(ask(&app_a, pa, b"ping").await, b"ping");
    assert_eq!(ta[0].streams, 1);

    let mut ev_b = Box::pin(b.events());
    let mut ev_a = Box::pin(a.events());
    a.close_tunnel(b.peer_id());
    assert_eq!(next_closed(&mut ev_a, b.peer_id()).await, "closed locally");
    assert_eq!(next_closed(&mut ev_b, a.peer_id()).await, "closed by peer");
    assert!(a.tunnels().await.is_empty());
    assert!(b.tunnels().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_reconnects_on_same_port_after_drop() {
    let echo = echo_server().await;
    let (_c, a, b) = mesh3().await;
    b.set_tunnel_target(echo);
    b.allow_peer(a.peer_id());
    let port = open_with_retry(&a, b.peer_id()).await;
    echo_rounds(port, 10).await;
    for _ in 0..3 {
        a.disconnect(b.peer_id());
        tokio::time::sleep(Duration::from_millis(100)).await;
        echo_rounds(port, 20).await;
        let t = a.tunnels().await;
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].local, port, "port changed on reconnect");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_rejected_caps_enforced_and_stray_sources_dropped() {
    let echo = echo_server().await;
    let c = Node::start(base()).await.unwrap();
    let b = join(
        &c,
        Config {
            tunnel_target: Some(echo),
            max_tunnels: 1,
            ..base()
        },
    )
    .await;
    let a1 = join(&c, base()).await;
    let a2 = join(&c, base()).await;
    a1.allow_peer(b.peer_id());
    a2.allow_peer(b.peer_id());
    a1.connect(b.peer_id()).await.unwrap();
    assert!(
        a1.open_tunnel(b.peer_id()).await.is_err(),
        "unauthorized peer got a tunnel"
    );
    assert!(b.tunnels().await.is_empty());

    b.allow_peer(a1.peer_id());
    b.allow_peer(a2.peer_id());
    let p1 = a1.open_tunnel(b.peer_id()).await.unwrap();
    a2.connect(b.peer_id()).await.unwrap();
    assert!(
        a2.open_tunnel(b.peer_id()).await.is_err(),
        "tunnel cap not enforced"
    );

    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(ask(&app, p1, b"hello").await, b"hello");
    let b_side = b.tunnels().await[0].local;
    let stray = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stray.send_to(b"evil", b_side).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        timeout(Duration::from_millis(700), app.recv_from(&mut buf))
            .await
            .is_err(),
        "datagram from a non-target source crossed the tunnel"
    );
    assert_eq!(ask(&app, p1, b"still-ok").await, b"still-ok");

    let mut ev = Box::pin(a1.events());
    b.deny_peer(a1.peer_id());
    assert_eq!(next_closed(&mut ev, b.peer_id()).await, "closed by peer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_peer_targets_route_each_peer_to_its_own_socket() {
    let t1 = tagged_echo(b"one:").await;
    let t2 = tagged_echo(b"two:").await;
    let c = Node::start(base()).await.unwrap();
    let b = join(&c, base()).await;
    let a1 = join(&c, base()).await;
    let a2 = join(&c, base()).await;
    b.allow_peer(a1.peer_id());
    b.allow_peer(a2.peer_id());
    b.set_peer_target(a1.peer_id(), Some(t1));
    b.set_peer_target(a2.peer_id(), Some(t2));
    let p1 = open_with_retry(&a1, b.peer_id()).await;
    let p2 = open_with_retry(&a2, b.peer_id()).await;
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(ask(&s, p1, b"x").await, b"one:x");
    let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(ask(&s2, p2, b"y").await, b"two:y");
    let tb = b.tunnels().await;
    assert_eq!(tb.len(), 2);
    assert_ne!(tb[0].local, tb[1].local);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_side_dial_does_not_fail_pending_connect() {
    let (_c, a, b) = mesh3().await;
    let bogus: Multiaddr = format!("/memory/4242/p2p/{}", b.peer_id()).parse().unwrap();
    a.disconnect(b.peer_id());
    wait_for("A-B disconnected", 10, || async {
        a.connections(b.peer_id()).await.is_empty()
    })
    .await;
    let (main, side) = tokio::join!(a.try_connect(b.peer_id()), a.dial(bogus));
    println!("side dial result: {side:?}");
    if let Err(e) = main {
        assert!(
            cfg!(windows) && e.to_string().contains("10048"),
            "pending connect failed: {e}"
        );
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match a.try_connect(b.peer_id()).await {
                Ok(()) => break,
                Err(e) => assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "pending connect failed: {e}"
                ),
            }
        }
    }
    assert!(!a.connections(b.peer_id()).await.is_empty());
}

async fn next_event<T>(
    ev: &mut (impl futures::Stream<Item = Event> + Unpin),
    secs: u64,
    mut f: impl FnMut(Event) -> Option<T>,
) -> Option<T> {
    timeout(Duration::from_secs(secs), async {
        while let Some(e) = ev.next().await {
            if let Some(t) = f(e) {
                return Some(t);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_cache_reconnects_after_restart_without_bootstrap() {
    let c = Node::start(base()).await.unwrap();
    let mut rx = c.rpc_requests().unwrap();
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            let _ = r.reply.send(r.data);
        }
    });
    let boot = server(&c).await;
    let key = Keypair::generate_ed25519();
    let path = std::env::temp_dir().join(format!("cosmos-cache-{}.peers", PeerId::random()));
    let a = Node::start(Config {
        keypair: Some(key.clone()),
        bootstrap: vec![boot],
        peer_cache: Some(path.clone()),
        ..base()
    })
    .await
    .unwrap();
    wait_for("bootstrap connection", 10, || async {
        !a.connections(c.peer_id()).await.is_empty()
    })
    .await;
    assert_eq!(
        a.request(c.peer_id(), b"cache".to_vec()).await.unwrap(),
        b"cache"
    );
    let cid = c.peer_id().to_string();
    wait_for("cache file with C", 10, || async {
        std::fs::read_to_string(&path).is_ok_and(|s| s.contains(&cid))
    })
    .await;
    drop(a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a2 = Node::start(Config {
        keypair: Some(key),
        peer_cache: Some(path.clone()),
        ..base()
    })
    .await
    .unwrap();
    let mut ev = Box::pin(a2.events());
    wait_for("reconnect via cache", 10, || async {
        !a2.connections(c.peer_id()).await.is_empty()
    })
    .await;
    let via = next_event(&mut ev, 5, |e| match e {
        Event::Discovered { peer, via } if peer == c.peer_id() => Some(via),
        _ => None,
    })
    .await;
    println!(
        "cache file: {}",
        std::fs::read_to_string(&path).unwrap().trim()
    );
    assert_eq!(via, Some("cache"));
    let _ = std::fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_cap_per_ip_rejects_extra_connection() {
    let c = Node::start(Config {
        limits: ConnLimits {
            max_inbound_per_ip: 2,
            ..ConnLimits::default()
        },
        ..base()
    })
    .await
    .unwrap();
    let target = tcp_addr(&c).await;
    let mut nodes = Vec::new();
    for _ in 0..3 {
        nodes.push(
            Node::start(Config {
                listen: vec![],
                ..base()
            })
            .await
            .unwrap(),
        );
    }
    for n in &nodes[..2] {
        n.dial(target.clone()).await.unwrap();
        wait_for("allowed inbound", 10, || async {
            !n.connections(c.peer_id()).await.is_empty()
        })
        .await;
    }
    nodes[2].dial(target.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        nodes[2].connections(c.peer_id()).await.is_empty(),
        "third inbound from 127.0.0.1 was accepted"
    );
    assert!(
        !nodes[0].connections(c.peer_id()).await.is_empty()
            && !nodes[1].connections(c.peer_id()).await.is_empty()
    );
    let first = nodes.remove(0);
    drop(first);
    tokio::time::sleep(Duration::from_millis(500)).await;
    nodes[1].dial(target.clone()).await.unwrap();
    wait_for("slot freed after disconnect", 10, || async {
        !nodes[1].connections(c.peer_id()).await.is_empty()
    })
    .await;
}

async fn serve_list(body: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/peers.txt", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_list_used_when_ipfs_disabled_or_failing() {
    let c = Node::start(base()).await.unwrap();
    let boot = server(&c).await;
    let url = serve_list(format!(
        "# cosmos bootstrap list\n\n{boot}\n/ip4/127.0.0.1/tcp/9\n"
    ))
    .await;
    let dead: Multiaddr = format!("/ip4/127.0.0.1/tcp/1/p2p/{}", PeerId::random())
        .parse()
        .unwrap();
    let start = Instant::now();
    let a = Node::start(Config {
        bootstrap_url: Some(url.clone()),
        ..base()
    })
    .await
    .unwrap();
    let b = Node::start(Config {
        ipfs: true,
        ipfs_bootstrap: vec![dead],
        ipfs_topics: vec!["test".into()],
        bootstrap_url: Some(url),
        bootstrap_url_after: Duration::from_secs(2),
        ..base()
    })
    .await
    .unwrap();
    let mut eb = Box::pin(b.events());
    wait_for("A joins via fallback list", 10, || async {
        !a.connections(c.peer_id()).await.is_empty()
    })
    .await;
    println!(
        "ipfs disabled: connected via list after {:?}",
        start.elapsed()
    );
    let n = next_event(&mut eb, 15, |e| match e {
        Event::FallbackList { addrs, error } => Some((addrs, error)),
        _ => None,
    })
    .await;
    assert_eq!(n, Some((1, None)), "fallback list not fetched");
    wait_for("B joins via fallback list", 10, || async {
        !b.connections(c.peer_id()).await.is_empty()
    })
    .await;
    println!(
        "ipfs failing: connected via list after {:?}",
        start.elapsed()
    );
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "B fetched before the IPFS grace period"
    );
}
