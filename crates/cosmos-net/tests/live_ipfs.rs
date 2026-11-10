use futures::StreamExt;
use cosmos_net::{Config, Event, Node};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn live_two_nodes_meet_through_public_ipfs_dht() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let topic = format!("livetest-{}", std::process::id());
    let cfg = || Config {
        ipfs: true,
        ipfs_topics: vec![topic.clone()],
        ipfs_announce_lan: std::env::var("BB_IPFS_LAN").is_ok(),
        mdns: false,
        ..Config::default()
    };
    let t0 = Instant::now();
    let a = Node::start(cfg()).await.unwrap();
    let b = Node::start(cfg()).await.unwrap();
    for (name, n) in [("a", a.clone()), ("b", b.clone())] {
        let mut ev = Box::pin(n.events());
        tokio::spawn(async move {
            while let Some(e) = ev.next().await {
                match e {
                    Event::Connected { .. } | Event::Disconnected { .. } | Event::Listening(_) => {}
                    e => println!("[{:.1}s] {name}: {e:?}", t0.elapsed().as_secs_f32()),
                }
            }
        });
    }
    let deadline = t0 + Duration::from_secs(120);
    while Instant::now() < deadline {
        if !a.connections(b.peer_id()).await.is_empty() {
            println!("[{:.1}s] a<->b connected: {:?}", t0.elapsed().as_secs_f32(), a.connections(b.peer_id()).await);
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("a and b did not meet within 120 s");
}
