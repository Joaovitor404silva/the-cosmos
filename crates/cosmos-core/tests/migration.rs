//! M2: path migration. A "relay" `MemNet` stands in for the Steam relay and a
//! second `MemNet` is the direct path.

use cosmos_core::{
    Delivery, MemNet, PathConfig, PathSet, PeerId, Session, SessionConfig, SessionEvent, Transport, TransportError,
    TransportEvent,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};

fn cfg() -> PathConfig {
    PathConfig {
        probe: Duration::from_millis(100),
        retry_base: Duration::from_millis(30),
        retry_max: Duration::from_secs(1),
        connect_timeout: Duration::from_millis(200),
        rto: Duration::from_millis(300),
        resend_cap: 1 << 20,
    }
}

fn node(direct: &Arc<MemNet>, relay: &Arc<MemNet>) -> Arc<PathSet> {
    let id = PeerId::random();
    let d: Arc<dyn Transport> = direct.transport_as(id);
    let r: Arc<dyn Transport> = relay.transport_as(id);
    PathSet::new(vec![("direct".into(), d), ("relay".into(), r)], cfg()).unwrap()
}

#[derive(Default)]
struct Seen {
    rel: Vec<u32>,
    unrel: Vec<u32>,
    switches: Vec<(String, String)>,
}

fn drain(s: &mut Session, seen: &mut Seen) {
    while let Some(e) = s.try_event() {
        match e {
            SessionEvent::Message { channel: 1, data, .. } => seen.rel.push(u32::from_be_bytes(data.try_into().unwrap())),
            SessionEvent::Message { channel: 2, data, .. } => {
                seen.unrel.push(u32::from_be_bytes(data.try_into().unwrap()))
            }
            SessionEvent::PathSwitch { from, to, .. } => seen.switches.push((from, to)),
            e => panic!("unexpected {e:?}"),
        }
    }
}

struct Pair {
    host: Session,
    hps: Arc<PathSet>,
    mem: Session,
    mps: Arc<PathSet>,
    hs: Seen,
    ms: Seen,
}

impl Pair {
    async fn new(direct: &Arc<MemNet>, relay: &Arc<MemNet>) -> Pair {
        let (hps, mps) = (node(direct, relay), node(direct, relay));
        let mut host = Session::host(hps.clone(), SessionConfig::default()).await.unwrap();
        let mut mem = Session::join(mps.clone(), SessionConfig::default(), host.me(), vec![]).await.unwrap();
        let j = timeout(Duration::from_secs(5), host.next_event()).await.unwrap();
        assert_eq!(j, Some(SessionEvent::Joined(mem.me())));
        assert_eq!(mem.try_event(), Some(SessionEvent::Joined(host.me())));
        Pair { host, hps, mem, mps, hs: Seen::default(), ms: Seen::default() }
    }

    fn drain(&mut self) {
        drain(&mut self.host, &mut self.hs);
        drain(&mut self.mem, &mut self.ms);
    }

    fn on(&self, path: &str) -> bool {
        self.hps.active_path(self.mem.me()).as_deref() == Some(path)
            && self.mps.active_path(self.host.me()).as_deref() == Some(path)
    }

    async fn wait(&mut self, what: &str, f: impl Fn(&Pair) -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !f(self) {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            sleep(Duration::from_millis(5)).await;
            self.drain();
        }
    }

    fn send(&self, i: u32) {
        let m = self.mem.me();
        self.host.send(m, 1, &i.to_be_bytes(), Delivery::Reliable).unwrap();
        self.host.send(m, 2, &i.to_be_bytes(), Delivery::Unreliable).unwrap();
    }
}

fn sw(a: &str, b: &str) -> (String, String) {
    (a.into(), b.into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_to_direct_and_back_loses_nothing() {
    let (direct, relay) = (MemNet::new(), MemNet::new());
    direct.cut();
    let mut p = Pair::new(&direct, &relay).await;
    let m = p.mem.me();
    assert!(p.on("relay"), "did not start on the relay");

    for i in 0..1000u32 {
        p.send(i);
        if i == 200 {
            direct.restore();
        }
        if i == 500 {
            p.wait("migration to direct", |p| p.on("direct")).await;
            assert_eq!(p.hps.live_paths(m), vec!["direct".to_string()], "relay not dropped");
            assert_eq!(p.mps.live_paths(p.host.me()), vec!["direct".to_string()], "relay not dropped");
        }
        if i == 700 {
            // Frames sent until the next yield are lost on the wire.
            direct.cut();
        }
        if i % 10 == 9 {
            sleep(Duration::from_millis(2)).await;
            p.drain();
        }
    }
    p.wait("all reliable messages", |p| p.ms.rel.len() >= 1000).await;
    assert!(p.on("relay"), "did not fall back to the relay");
    sleep(Duration::from_millis(500)).await;
    p.drain();

    assert_eq!(p.ms.rel, (0..1000).collect::<Vec<_>>(), "reliable lost, duplicated or reordered");
    let want = vec![sw("relay", "direct"), sw("direct", "relay")];
    assert_eq!(p.hs.switches, want);
    assert_eq!(p.ms.switches, want);
    assert!(p.ms.unrel.len() > 500, "unreliable stalled: {}", p.ms.unrel.len());
    assert!(p.ms.unrel.windows(2).all(|w| w[0] < w[1]), "unreliable out of order");
    assert_eq!(p.hps.unacked_bytes(m), 0, "resend buffer not drained by acks");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flapping_direct_does_not_cause_a_switch_storm() {
    let (direct, relay) = (MemNet::new(), MemNet::new());
    direct.cut();
    let mut p = Pair::new(&direct, &relay).await;

    // Up for 20 ms, down for 20 ms: shorter than the probe period.
    let d = direct.clone();
    let flap = tokio::spawn(async move {
        for _ in 0..40 {
            d.restore();
            sleep(Duration::from_millis(20)).await;
            d.cut();
            sleep(Duration::from_millis(20)).await;
        }
    });
    let mut i = 0;
    while !flap.is_finished() {
        p.send(i);
        i += 1;
        sleep(Duration::from_millis(2)).await;
        p.drain();
    }
    assert!(p.hs.switches.is_empty() && p.ms.switches.is_empty(), "switched while flapping: {:?}", p.hs.switches);
    assert!(p.on("relay"));

    direct.restore();
    p.wait("migration to direct", |p| p.on("direct")).await;
    p.wait("all reliable messages", |p| p.ms.rel.len() >= i as usize).await;
    assert_eq!(p.ms.rel, (0..i).collect::<Vec<_>>());
    // The switch event trails the path state; wait for it, then for extras.
    p.wait("switch events", |p| !p.hs.switches.is_empty() && !p.ms.switches.is_empty()).await;
    sleep(Duration::from_millis(300)).await;
    p.drain();
    assert_eq!(p.hs.switches, vec![sw("relay", "direct")]);
    assert_eq!(p.ms.switches, vec![sw("relay", "direct")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resend_cap_overflow_drops_the_peer() {
    let relay = MemNet::new();
    let r: Arc<dyn Transport> = relay.transport();
    let a = PathSet::new(vec![("relay".into(), r)], PathConfig { resend_cap: 16 << 10, ..cfg() }).unwrap();
    let mut events = a.take_events().unwrap();
    // A peer that never acks.
    let b = relay.transport();
    let _held = b.take_events();
    let bp = b.local_peer();
    a.connect(bp, vec![]).await.unwrap();

    let mut sent = 0;
    loop {
        match a.send(bp, vec![0; 1024], true) {
            Ok(()) => sent += 1,
            Err(TransportError::Backlog) => break,
            Err(e) => panic!("{e}"),
        }
        assert!(sent < 100, "resend buffer unbounded");
    }
    assert!(sent >= 14, "cap hit too early: {sent}");
    let ev = timeout(Duration::from_secs(2), events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, TransportEvent::Overflow { peer } if peer == bp), "{ev:?}");
    assert!(a.live_paths(bp).is_empty());
    assert_eq!(a.unacked_bytes(bp), 0);
    assert_eq!(a.send(bp, vec![1], true), Err(TransportError::Closed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackholed_direct_falls_back_to_relay() {
    let (direct, relay) = (MemNet::new(), MemNet::new());
    let mut p = Pair::new(&direct, &relay).await;
    assert!(p.on("direct"), "did not start on direct");
    // No Down from the transport: only missing acks reveal it.
    direct.set_blackhole(true);
    for i in 0..300u32 {
        p.send(i);
        if i % 10 == 9 {
            sleep(Duration::from_millis(5)).await;
            p.drain();
        }
    }
    p.wait("fallback to the relay", |p| p.on("relay")).await;
    p.wait("all reliable messages", |p| p.ms.rel.len() >= 300).await;
    assert_eq!(p.ms.rel, (0..300).collect::<Vec<_>>(), "reliable lost, duplicated or reordered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackholed_direct_is_never_adopted() {
    let (direct, relay) = (MemNet::new(), MemNet::new());
    direct.cut();
    let mut p = Pair::new(&direct, &relay).await;
    assert!(p.on("relay"));
    // Connects succeed but nothing gets through: probing must notice.
    direct.restore();
    direct.set_blackhole(true);
    for i in 0..200u32 {
        p.send(i);
        sleep(Duration::from_millis(5)).await;
        p.drain();
    }
    p.wait("all reliable messages", |p| p.ms.rel.len() >= 200).await;
    assert!(p.on("relay"), "moved to a path that carries nothing");
    assert!(p.hs.switches.is_empty() && p.ms.switches.is_empty(), "switched: {:?}", p.hs.switches);
    assert_eq!(p.ms.rel, (0..200).collect::<Vec<_>>());
}

fn single(net: &Arc<MemNet>, c: PathConfig) -> Arc<PathSet> {
    let t: Arc<dyn Transport> = net.transport();
    PathSet::new(vec![("relay".into(), t)], c).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgotten_peer_resets_the_sender() {
    let net = MemNet::new();
    let (a, b) = (single(&net, cfg()), single(&net, cfg()));
    let (mut ae, mut be) = (a.take_events().unwrap(), b.take_events().unwrap());
    let (ap, bp) = (a.local_peer(), b.local_peer());
    a.connect(bp, vec![]).await.unwrap();
    a.send(bp, b"x".to_vec(), true).unwrap();
    let ev = timeout(Duration::from_secs(2), be.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, TransportEvent::Frame { .. }), "{ev:?}");
    let end = Instant::now() + Duration::from_secs(2);
    while a.unacked_bytes(bp) > 0 {
        assert!(Instant::now() < end, "never acked");
        sleep(Duration::from_millis(5)).await;
    }
    // b drops a (say its side gave up); a still thinks the link is fine.
    b.disconnect(ap);
    a.send(bp, b"y".to_vec(), true).unwrap();
    let down = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(TransportEvent::Down { peer }) = ae.recv().await {
                return peer;
            }
        }
    })
    .await
    .expect("sender never learned the receiver forgot it");
    assert_eq!(down, bp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_hold_bounded_state() {
    let net = MemNet::new();
    let a = single(&net, cfg());
    let _ae = a.take_events().unwrap();
    let mut held = vec![];
    for _ in 0..40 {
        let t = net.transport();
        let _ = t.take_events();
        let mut f = vec![1u8];
        f.extend_from_slice(&7u32.to_be_bytes());
        f.extend_from_slice(&0u64.to_be_bytes());
        f.extend_from_slice(b"hi");
        t.send(a.local_peer(), f, true).unwrap();
        held.push(t);
    }
    sleep(Duration::from_millis(200)).await;
    let known = held.iter().filter(|t| !a.live_paths(t.local_peer()).is_empty()).count();
    assert!(known <= 8, "state kept for {known} strangers");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resend_backs_off_and_is_windowed() {
    let net = MemNet::new();
    let a = single(&net, PathConfig { rto: Duration::from_millis(100), ..cfg() });
    let _ae = a.take_events().unwrap();
    // A peer that never acks.
    let b = net.transport();
    let mut be = b.take_events().unwrap();
    let bp = b.local_peer();
    a.connect(bp, vec![]).await.unwrap();
    for _ in 0..200 {
        a.send(bp, vec![0; 10], true).unwrap();
    }
    sleep(Duration::from_millis(1500)).await;
    let mut n = 0;
    while be.try_recv().is_ok() {
        n += 1;
    }
    // Without backoff or a window: ~15 rounds x 200 frames.
    assert!(n < 1000, "resend storm: {n} frames in 1.5 s");
}
