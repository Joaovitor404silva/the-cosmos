use futures::StreamExt;
use libp2p::kad::{self, store::MemoryStore, store::MemoryStoreConfig};
use libp2p::swarm::SwarmEvent;
use libp2p::{StreamProtocol, Swarm, noise, tcp, yamux};
use cosmos_net::{Config, Multiaddr, Node, PeerId};
use sha2::{Digest, Sha256};
use std::future::Future;
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
        .expect("tcp")
}

async fn server(n: &Node) -> Multiaddr {
    let a = tcp_addr(n).await;
    n.add_external_addr(a.clone());
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

async fn join(c: &Node) -> Node {
    let boot = server(c).await;
    let n = Node::start(Config {
        bootstrap: vec![boot],
        ..base()
    })
    .await
    .unwrap();
    wait_for("bootstrap", 10, || async {
        !n.connections(c.peer_id()).await.is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    server(&n).await;
    n
}

async fn publish(n: &Node, topic: &str) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        match n.publish(topic, b"sign".to_vec()).await {
            Ok(()) => return Ok(()),
            Err(e)
                if start.elapsed() < Duration::from_secs(15)
                    && !format!("{e}").contains("MaxProvidedKeys") =>
            {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

fn topic_key(topic: &str) -> kad::RecordKey {
    kad::RecordKey::new(&Sha256::digest(topic.as_bytes()).to_vec())
}

fn attacker() -> Swarm<kad::Behaviour<MemoryStore>> {
    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|k| {
            let id = k.public().to_peer_id();
            let scfg = MemoryStoreConfig {
                max_provided_keys: 1 << 16,
                max_records: 1 << 16,
                ..Default::default()
            };
            let mut b = kad::Behaviour::with_config(
                id,
                MemoryStore::with_config(id, scfg),
                kad::Config::new(StreamProtocol::new("/cosmos/kad/1.0.0")),
            );
            b.set_mode(Some(kad::Mode::Client));
            b
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build()
}

async fn provide(sw: &mut Swarm<kad::Behaviour<MemoryStore>>, keys: Vec<kad::RecordKey>) -> usize {
    let mut ok = 0;
    for batch in keys.chunks(64) {
        let mut left = 0;
        for k in batch {
            sw.behaviour_mut().start_providing(k.clone()).unwrap();
            left += 1;
        }
        let _ = timeout(Duration::from_secs(30), async {
            while left > 0 {
                if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::StartProviding(r),
                    step,
                    ..
                }) = sw.select_next_some().await
                {
                    if step.last {
                        left -= 1;
                        ok += r.is_ok() as usize;
                    }
                }
            }
        })
        .await;
    }
    ok
}

fn spawn_idle(mut sw: Swarm<kad::Behaviour<MemoryStore>>) {
    tokio::spawn(async move {
        loop {
            sw.select_next_some().await;
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_fake_provider_without_record_breaks_find_complete() {
    let c = Node::start(base()).await.unwrap();
    let a = join(&c).await;
    let b = join(&c).await;
    let topic = cosmos_net::topic_for("audit", "one");
    publish(&a, &topic).await.expect("honest publish");
    let honest = timeout(
        Duration::from_secs(25),
        b.find_complete(&topic, Duration::from_secs(20)),
    )
    .await
    .unwrap();
    assert_eq!(honest.expect("control find_complete").len(), 1);

    let mut evil = attacker();
    evil.add_external_address("/ip4/8.8.8.8/tcp/4001".parse().unwrap());
    let c_addr = tcp_addr(&c).await;
    evil.behaviour_mut().add_address(&c.peer_id(), c_addr);
    let n = provide(&mut evil, vec![topic_key(&topic)]).await;
    assert_eq!(n, 1, "attacker provider record not accepted");
    spawn_idle(evil);

    let after = timeout(
        Duration::from_secs(25),
        b.find_complete(&topic, Duration::from_secs(20)),
    )
    .await
    .unwrap();
    assert!(
        after.is_ok(),
        "one provider record with no signed record makes find_complete fail for every finder: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_provider_keys_exhaust_store_and_block_victim_publish() {
    let c = Node::start(base()).await.unwrap();
    let _a = join(&c).await;
    publish(&c, &cosmos_net::topic_for("audit", "one"))
        .await
        .expect("control publish");

    let mut evil = attacker();
    let c_addr = tcp_addr(&c).await;
    evil.behaviour_mut().add_address(&c.peer_id(), c_addr);
    let keys: Vec<kad::RecordKey> = (0..1100)
        .map(|_| kad::RecordKey::new(&PeerId::random().to_bytes()))
        .collect();
    let n = provide(&mut evil, keys).await;
    eprintln!("attacker provider queries ok: {n}");
    spawn_idle(evil);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let r = publish(&c, &cosmos_net::topic_for("audit", "two")).await;
    assert!(
        r.is_ok(),
        "victim cannot publish after 1100 junk AddProvider from one remote peer: {r:?}"
    );
}
