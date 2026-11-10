use futures::{AsyncReadExt, AsyncWriteExt};
use cosmos_net::{Config, Multiaddr, Node, RpcLimits};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

async fn tcp_addr(n: &Node) -> Multiaddr {
    n.listen_addrs()
        .await
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

