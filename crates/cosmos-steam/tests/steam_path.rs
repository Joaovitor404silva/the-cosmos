//! M3: the Steam relay path over an in-process fake Steam.

use cosmos_core::{MemNet, PathConfig, PathSet, PeerId, Transport, TransportError, TransportEvent};
use cosmos_net::Keypair;
use cosmos_steam::{
    FakeSteam, FakeSteamNet, SteamApi, SteamBackend, SteamConfig, SteamEvent, SteamTransport, SteamTransportConfig,
    StaticDirectory, Unavailable, bind,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

const SA: u64 = 76561198000000001;
const SB: u64 = 76561198000000002;
const SX: u64 = 76561198000000666;
const SESSION: [u8; 32] = [9; 32];

fn tcfg() -> SteamTransportConfig {
    SteamTransportConfig {
        handshake_timeout: Duration::from_millis(800),
        hello_every: Duration::from_millis(50),
        ..Default::default()
    }
}

struct Node {
    key: Keypair,
    t: Arc<SteamTransport>,
}

impl Node {
    fn id(&self) -> PeerId {
        self.key.public().to_peer_id()
    }
}

fn node(net: &Arc<FakeSteamNet>, steam: u64, dir: &Arc<StaticDirectory>) -> Node {
    let key = Keypair::generate_ed25519();
    let t = SteamTransport::new(net.backend(steam), key.clone(), dir.clone(), tcfg());
    t.set_session_key(SESSION);
    Node { key, t }
}

async fn frame(rx: &mut mpsc::Receiver<TransportEvent>) -> (PeerId, Vec<u8>) {
    loop {
        match timeout(Duration::from_secs(5), rx.recv()).await.expect("frame timeout").expect("events closed") {
            TransportEvent::Frame { peer, data } => return (peer, data),
            _ => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_binds_and_frames_roundtrip() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = (node(&net, SA, &dir), node(&net, SB, &dir));
    dir.insert(b.id(), SB);
    let mut brx = b.t.take_events().unwrap();
    let mut arx = a.t.take_events().unwrap();

    a.t.connect(b.id(), vec![]).await.unwrap();
    assert_eq!(a.t.bound_steam_id(b.id()), Some(SB));

    a.t.send(b.id(), b"rel".to_vec(), true).unwrap();
    a.t.send(b.id(), b"unrel".to_vec(), false).unwrap();
    assert_eq!(frame(&mut brx).await, (a.id(), b"rel".to_vec()));
    assert_eq!(frame(&mut brx).await, (a.id(), b"unrel".to_vec()));
    // B learned A from the handshake A started; it can answer without a lookup.
    assert_eq!(b.t.bound_steam_id(a.id()), Some(SA));
    b.t.send(a.id(), b"back".to_vec(), true).unwrap();
    assert_eq!(frame(&mut arx).await, (b.id(), b"back".to_vec()));

    // Over one Steam message: split and rebuilt; over FRAME_MAX: refused.
    let big: Vec<u8> = (0..cosmos_core::transport::FRAME_MAX).map(|i| i as u8).collect();
    a.t.send(b.id(), big.clone(), true).unwrap();
    assert_eq!(frame(&mut brx).await.1, big);
    let over = vec![0u8; cosmos_core::transport::FRAME_MAX + 1];
    assert_eq!(a.t.send(b.id(), over, true), Err(TransportError::Backlog));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreliable_loss_is_silent() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = (node(&net, SA, &dir), node(&net, SB, &dir));
    dir.insert(b.id(), SB);
    let mut brx = b.t.take_events().unwrap();
    a.t.connect(b.id(), vec![]).await.unwrap();
    net.drop_unreliable(true);
    a.t.send(b.id(), b"lost".to_vec(), false).unwrap();
    a.t.send(b.id(), b"kept".to_vec(), true).unwrap();
    assert_eq!(frame(&mut brx).await.1, b"kept");
}

/// Attacker X answers A's hello. Its own key is the wrong peer; the victim's
/// proof relayed from X names the wrong SteamID; frames from an unbound
/// SteamID never reach the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_or_relayed_proofs_are_rejected() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let a = node(&net, SA, &dir);
    let mut arx = a.t.take_events().unwrap();
    let victim = Keypair::generate_ed25519();
    let attacker = Keypair::generate_ed25519();
    let x: Arc<FakeSteam> = net.backend(SX);
    // A was told (say by a bad lobby) that the victim is at SteamID X.
    dir.insert(victim.public().to_peer_id(), SX);

    let xb = x.clone();
    let (vk, ak) = (victim.clone(), attacker.clone());
    let answer = tokio::spawn(async move {
        let mut seen = 0;
        let end = Instant::now() + Duration::from_millis(700);
        while Instant::now() < end {
            let mut evs = vec![];
            xb.poll(&mut evs);
            for e in evs {
                let SteamEvent::Message { data, .. } = e else { continue };
                let Some(n) = bind::parse_hello(&data) else { continue };
                seen += 1;
                // Own key, honest SteamIDs: valid proof, but not the victim.
                xb.send(SA, &bind::proof(&ak, SX, SA, &n), true).unwrap();
                // Victim's key, but signed for the victim's own SteamID.
                xb.send(SA, &bind::proof(&vk, SB, SA, &n), true).unwrap();
                // Victim's key aimed at another receiver.
                xb.send(SA, &bind::proof(&vk, SX, SB, &n), true).unwrap();
                // Wrong nonce.
                xb.send(SA, &bind::proof(&vk, SX, SA, &bind::new_nonce()), true).unwrap();
                xb.send(SA, b"\x03injected", false).unwrap();
            }
            sleep(Duration::from_millis(5)).await;
        }
        seen
    });
    let r = a.t.connect(victim.public().to_peer_id(), vec![]).await;
    assert!(r.is_err(), "bound a forged identity");
    assert!(answer.await.unwrap() > 0, "attacker never saw a hello");
    assert_eq!(a.t.bound_steam_id(victim.public().to_peer_id()), None);
    assert_eq!(a.t.bound_steam_id(attacker.public().to_peer_id()), None);
    assert!(timeout(Duration::from_millis(100), arx.recv()).await.is_err(), "unbound frame delivered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn steam_unavailable_is_clean() {
    let cfg = SteamConfig { app_id: 480, dll: Some("Z:/no/such/steam_api64.dll".into()) };
    assert!(matches!(SteamApi::load(&cfg), Err(Unavailable::DllMissing(_))));
    let dir: Arc<StaticDirectory> = Arc::new(StaticDirectory::default());
    assert!(cosmos_steam::steam_path(&cfg, Keypair::generate_ed25519(), dir).is_none());

    // Steam down / peer unknown: connect fails, send says Closed, no panic.
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = (node(&net, SA, &dir), node(&net, SB, &dir));
    assert!(a.t.connect(b.id(), vec![]).await.is_err(), "no SteamID known");
    dir.insert(b.id(), SB);
    net.cut();
    assert!(a.t.connect(b.id(), vec![]).await.is_err());
    assert_eq!(a.t.send(b.id(), vec![1], true), Err(TransportError::Closed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_failure_reports_down_and_rebinds() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = (node(&net, SA, &dir), node(&net, SB, &dir));
    dir.insert(b.id(), SB);
    let mut arx = a.t.take_events().unwrap();
    a.t.connect(b.id(), vec![]).await.unwrap();
    net.cut();
    loop {
        match timeout(Duration::from_secs(5), arx.recv()).await.unwrap().unwrap() {
            TransportEvent::Down { peer } => {
                assert_eq!(peer, b.id());
                break;
            }
            _ => continue,
        }
    }
    assert_eq!(a.t.bound_steam_id(b.id()), None);
    net.restore();
    a.t.connect(b.id(), vec![]).await.unwrap();
    assert_eq!(a.t.bound_steam_id(b.id()), Some(SB));
}

fn pcfg() -> PathConfig {
    PathConfig {
        probe: Duration::from_millis(100),
        retry_base: Duration::from_millis(30),
        retry_max: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(300),
        rto: Duration::from_millis(200),
        resend_cap: 1 << 20,
    }
}

/// `[direct(MemNet), steam(fake)]`: starts on Steam while direct is down,
/// migrates to direct, falls back to Steam when direct dies; reliable frames
/// arrive once, in order, across both switches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pathset_migrates_off_steam_and_falls_back() {
    let direct = MemNet::new();
    let steam = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let mk = |sid: u64| {
        let key = Keypair::generate_ed25519();
        let id = key.public().to_peer_id();
        let d: Arc<dyn Transport> = direct.transport_as(id);
        let st = SteamTransport::new(steam.backend(sid), key, dir.clone(), tcfg());
        st.set_session_key(SESSION);
        let s: Arc<dyn Transport> = st;
        dir.insert(id, sid);
        (id, PathSet::new(vec![("direct".into(), d), ("steam".into(), s)], pcfg()).unwrap())
    };
    let (aid, a) = mk(SA);
    let (bid, b) = mk(SB);
    let mut brx = b.take_events().unwrap();
    let _arx = a.take_events().unwrap();

    direct.cut();
    a.connect(bid, vec![]).await.unwrap();
    assert_eq!(a.active_path(bid).as_deref(), Some("steam"));

    let mut next = 0u32;
    let mut got = vec![];
    let send_some = |n: u32, next: &mut u32| {
        for _ in 0..n {
            a.send(bid, next.to_be_bytes().to_vec(), true).unwrap();
            *next += 1;
        }
    };
    async fn collect(rx: &mut mpsc::Receiver<TransportEvent>, got: &mut Vec<u32>, until: u32, from: PeerId) {
        while got.len() < until as usize {
            let (p, d) = frame(rx).await;
            assert_eq!(p, from);
            got.push(u32::from_be_bytes(d.try_into().unwrap()));
        }
    }

    send_some(50, &mut next);
    collect(&mut brx, &mut got, next, aid).await;
    sleep(Duration::from_millis(400)).await;
    assert_eq!(a.active_path(bid).as_deref(), Some("steam"), "left steam while direct is down");

    direct.restore();
    let end = Instant::now() + Duration::from_secs(5);
    while a.active_path(bid).as_deref() != Some("direct") {
        assert!(Instant::now() < end, "never migrated to direct");
        send_some(1, &mut next);
        sleep(Duration::from_millis(20)).await;
    }
    send_some(50, &mut next);
    collect(&mut brx, &mut got, next, aid).await;

    direct.cut();
    let end = Instant::now() + Duration::from_secs(5);
    while a.active_path(bid).as_deref() != Some("steam") {
        assert!(Instant::now() < end, "never fell back to steam");
        sleep(Duration::from_millis(20)).await;
    }
    send_some(50, &mut next);
    collect(&mut brx, &mut got, next, aid).await;
    assert_eq!(got, (0..next).collect::<Vec<_>>(), "lost, duplicated or reordered frames");
}

async fn bound_pair(net: &Arc<FakeSteamNet>, dir: &Arc<StaticDirectory>) -> (Node, Node) {
    let (a, b) = (node(net, SA, dir), node(net, SB, dir));
    dir.insert(b.id(), SB);
    a.t.connect(b.id(), vec![]).await.unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    while b.t.bound_steam_id(a.id()).is_none() {
        assert!(Instant::now() < end, "b never bound a");
        sleep(Duration::from_millis(5)).await;
    }
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_fragment_never_corrupts_the_next_frame() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = bound_pair(&net, &dir).await;
    let mut brx = b.t.take_events().unwrap();
    let big = vec![9u8; cosmos_steam::MAX_FRAME * 2];
    // First piece goes out, second is refused: the frame is not sent.
    net.full_after(1);
    assert_eq!(a.t.send(b.id(), big.clone(), true), Err(TransportError::Backlog));
    a.t.send(b.id(), b"small".to_vec(), true).unwrap();
    assert_eq!(frame(&mut brx).await, (a.id(), b"small".to_vec()));
    a.t.send(b.id(), big.clone(), true).unwrap();
    assert_eq!(frame(&mut brx).await.1, big);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_sided_binding_is_repaired() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = bound_pair(&net, &dir).await;
    let mut brx = b.t.take_events().unwrap();
    // Only b loses the session; a stays bound and keeps sending.
    net.fail_session(SB, SA);
    let end = Instant::now() + Duration::from_secs(3);
    while b.t.bound_steam_id(a.id()).is_some() {
        assert!(Instant::now() < end, "b never unbound");
        sleep(Duration::from_millis(5)).await;
    }
    let got = timeout(Duration::from_secs(3), async {
        loop {
            let _ = a.t.send(b.id(), b"hi".to_vec(), true);
            if let Ok(Some(TransportEvent::Frame { peer, data })) = timeout(Duration::from_millis(50), brx.recv()).await {
                return (peer, data);
            }
        }
    })
    .await
    .expect("b never accepted a's frames again");
    assert_eq!(got, (a.id(), b"hi".to_vec()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rekeyed_peer_on_same_steam_id_rebinds() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = bound_pair(&net, &dir).await;
    let mut brx = b.t.take_events().unwrap();
    let old = a.id();
    drop(a);
    sleep(Duration::from_millis(50)).await;
    // Same Steam account, new Cosmos key.
    let a2 = node(&net, SA, &dir);
    a2.t.connect_steam(SB, Some(b.id())).await.unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    while b.t.bound_steam_id(a2.id()) != Some(SA) {
        assert!(Instant::now() < end, "b still binds SA to the old key");
        sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(b.t.bound_steam_id(old), None);
    let down = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(TransportEvent::Down { peer }) = brx.recv().await {
                return peer;
            }
        }
    })
    .await
    .expect("no Down for the old key");
    assert_eq!(down, old);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stranger_hellos_cannot_block_our_connects() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let (a, b) = (node(&net, SA, &dir), node(&net, SB, &dir));
    for i in 0..200u64 {
        net.inject(SX + i, SA, bind::hello(&bind::new_nonce()));
    }
    sleep(Duration::from_millis(100)).await;
    dir.insert(b.id(), SB);
    a.t.connect(b.id(), vec![]).await.expect("strangers starved our handshake");
}

/// Audit finding 3: a stranger messaging our SteamID must not learn our
/// Cosmos key (PeerId -> DHT addr record -> IP). Only hellos tagged with the
/// session key, or from SteamIDs we asked for, get a proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strangers_get_no_proof() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let a = node(&net, SA, &dir);
    let x: Arc<FakeSteam> = net.backend(SX);
    let replies = |n: &bind::Nonce| {
        let x = x.clone();
        let n = *n;
        async move {
            let mut proofs = vec![];
            let end = Instant::now() + Duration::from_millis(300);
            while Instant::now() < end {
                let mut evs = vec![];
                x.poll(&mut evs);
                for e in evs {
                    if let SteamEvent::Message { data, .. } = e
                        && let Some(p) = bind::verify_proof(&data, SA, SX, &n)
                    {
                        proofs.push(p);
                    }
                }
                sleep(Duration::from_millis(5)).await;
            }
            proofs
        }
    };
    // Untagged, and tagged with another session's key: silence.
    let n = bind::new_nonce();
    x.send(SA, &bind::hello(&n), true).unwrap();
    assert!(replies(&n).await.is_empty(), "stranger got our key");
    let n = bind::new_nonce();
    x.send(SA, &bind::hello_tagged(bind::HELLO, &n, Some(&[1; 32]), SX, SA), true).unwrap();
    assert!(replies(&n).await.is_empty(), "wrong session key got our key");
    // A member (same session key) gets the proof.
    let n = bind::new_nonce();
    x.send(SA, &bind::hello_tagged(bind::HELLO, &n, Some(&SESSION), SX, SA), true).unwrap();
    assert_eq!(replies(&n).await, vec![a.id()]);
}

/// Review finding 3: data from a SteamID we never knew gets no reply, so
/// strangers can't probe whether we run Cosmos.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stranger_data_gets_silence() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let _a = node(&net, SA, &dir);
    let x: Arc<FakeSteam> = net.backend(SX);
    x.send(SA, &[bind::DATA, 1, 2, 3], true).unwrap();
    let end = Instant::now() + Duration::from_millis(400);
    while Instant::now() < end {
        let mut evs = vec![];
        x.poll(&mut evs);
        for e in evs {
            if let SteamEvent::Message { data, .. } = e {
                panic!("stranger got a reply: kind {}", data[0]);
            }
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// Review: a member whose handshake with us never finished (its proof
/// dropped) still gets re-asked when its frames arrive later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_finished_handshake_is_repaired() {
    let net = FakeSteamNet::new();
    let dir = Arc::new(StaticDirectory::default());
    let _a = node(&net, SA, &dir);
    let x: Arc<FakeSteam> = net.backend(SX);
    let n = bind::new_nonce();
    x.send(SA, &bind::hello_tagged(bind::HELLO, &n, Some(&SESSION), SX, SA), true).unwrap();
    // X never answers; A's pending entry expires (2 x handshake timeout).
    sleep(Duration::from_millis(3000)).await;
    let mut evs = vec![];
    x.poll(&mut evs);
    x.send(SA, &[bind::DATA, 1, 2, 3], true).unwrap();
    let end = Instant::now() + Duration::from_secs(1);
    while Instant::now() < end {
        evs.clear();
        x.poll(&mut evs);
        if evs.iter().any(|e| matches!(e, SteamEvent::Message { data, .. } if data[0] == bind::HELLO)) {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!("A never re-asked a member it had started a handshake with");
}
