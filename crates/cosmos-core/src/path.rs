//! Multi-path delivery: ranked paths per peer, acks with resend, migration.
//!
//! `PathSet` is a `Transport` over several ranked transports (best first,
//! e.g. `[direct, relay]`). Per peer it sends on the best live path. While
//! that is not the best path, it keeps retrying the better ones with backoff;
//! one that connects, answers a ping and survives `probe` becomes active and
//! the worse ones are dropped. If the active path dies it falls back to
//! another live path, or reconnects one (best other path first), and only
//! reports `Down` when none works.
//!
//! A path is dead when its transport says so (`Down`, or a `Closed` send) or
//! when `DEAD_RTOS` resend timeouts pass without an ack (a silently broken
//! path). The receiver follows: new data arriving on another path while its
//! active one has gone quiet moves it there too.
//!
//! Reliable frames carry `[epoch][seq]` and stay in a per-peer resend buffer
//! until the peer acks them (cumulative). Every switch resends the buffer on
//! the new path, and the receiver drops anything but the next expected frame,
//! so a path change loses and duplicates nothing. A receiver that does not
//! know the sender's epoch mid-stream answers `RESET`, and the sender drops
//! the peer (`Down`) instead of resending into the void. The buffer is
//! capped; a peer that passes the cap is dropped with `Overflow`.
//!
//! Peers first heard from (not connected or sent to by us) are unconfirmed:
//! at most `MAX_UNCONFIRMED` are kept, for `UNCONFIRMED_TTL`, and get no
//! background tasks.

use crate::transport::{FRAME_MAX, Transport, TransportError, TransportEvent};
use cosmos_net::{Multiaddr, PeerId};
use futures::future::BoxFuture;
use futures::{FutureExt, future::join_all};
use std::collections::hash_map::RandomState;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct PathConfig {
    /// A better path must answer a ping and stay up this long before traffic
    /// moves to it.
    pub probe: Duration,
    /// Retry delay for better paths; doubles on each failure.
    pub retry_base: Duration,
    pub retry_max: Duration,
    /// Per-path connect limit (the worst path gets no limit on first connect).
    pub connect_timeout: Duration,
    /// Resend unacked frames when no ack progress for this long; doubles on
    /// each timeout up to 8x.
    pub rto: Duration,
    /// Unacked reliable bytes per peer before the peer is dropped.
    pub resend_cap: usize,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            probe: Duration::from_secs(3),
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(5),
            rto: Duration::from_secs(1),
            resend_cap: 4 << 20,
        }
    }
}

const L_REL: u8 = 1;
const L_UNREL: u8 = 2;
const L_ACK: u8 = 3;
const L_PING: u8 = 4;
const L_PONG: u8 = 5;
const L_RESET: u8 = 6;
/// `[kind][epoch u32][seq u64]`; acks, pings and resets are just this header.
const HDR: usize = 13;
const QUEUE: usize = 1024;
const BATCH: usize = 256;
const TICK: Duration = Duration::from_millis(50);
/// Resend timeouts without ack progress before the active path is dead.
const DEAD_RTOS: u32 = 3;
const RTO_MAX_FACTOR: u32 = 8;
/// Frames resent per timeout or switch, oldest first.
const RESEND_WINDOW: usize = 64;
const MAX_UNCONFIRMED: usize = 8;
const UNCONFIRMED_TTL: Duration = Duration::from_secs(30);
/// Old sender epochs remembered, so their stale frames can't restart a lane.
const OLD_EPOCHS: usize = 4;

fn header(kind: u8, epoch: u32, seq: u64) -> Vec<u8> {
    let mut f = Vec::with_capacity(HDR);
    f.push(kind);
    f.extend_from_slice(&epoch.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f
}

fn parse(b: &[u8]) -> Option<(u32, u64)> {
    (b.len() >= HDR).then(|| {
        (u32::from_be_bytes(b[1..5].try_into().unwrap()), u64::from_be_bytes(b[5..HDR].try_into().unwrap()))
    })
}

fn random() -> u64 {
    RandomState::new().build_hasher().finish()
}

struct Peer {
    /// Identity of this state; background tasks for an older one stop.
    inc: u64,
    /// We connected or sent to it (not just heard from it).
    confirmed: bool,
    created: Instant,
    addrs: Vec<Multiaddr>,
    live: Vec<bool>,
    /// Last frame of any kind received per path.
    last_rx: Vec<Instant>,
    active: Option<usize>,
    active_since: Instant,
    /// A better path that connected and is waiting out `probe`.
    probing: Option<usize>,
    probe_nonce: u64,
    probe_ok: bool,
    upgrading: bool,
    backoff: Duration,
    /// Random per sender state, so a restarted sender is not taken for
    /// duplicates of the old one.
    epoch: u32,
    tx_seq: u64,
    unacked: VecDeque<(u64, Vec<u8>)>,
    unacked_bytes: usize,
    /// Timer base for resends: last ack progress or resend.
    last_progress: Instant,
    rto: Duration,
    timeouts: u32,
    /// A fresh send was refused; hold new frames until a resend, so the
    /// path never carries a gap.
    gap: bool,
    rx_epoch: Option<u32>,
    rx_old: VecDeque<u32>,
    rx_next: u64,
    ack_due: bool,
}

impl Peer {
    fn new(paths: usize, cfg: &PathConfig, inc: u64) -> Peer {
        let now = Instant::now();
        Peer {
            inc,
            confirmed: false,
            created: now,
            addrs: vec![],
            live: vec![false; paths],
            last_rx: vec![now; paths],
            active: None,
            active_since: now,
            probing: None,
            probe_nonce: 0,
            probe_ok: false,
            upgrading: false,
            backoff: cfg.retry_base,
            epoch: random() as u32,
            tx_seq: 0,
            unacked: VecDeque::new(),
            unacked_bytes: 0,
            last_progress: now,
            rto: cfg.rto,
            timeouts: 0,
            gap: false,
            rx_epoch: None,
            rx_old: VecDeque::new(),
            rx_next: 0,
            ack_due: false,
        }
    }
}

struct Shared {
    paths: Vec<(String, Arc<dyn Transport>)>,
    cfg: PathConfig,
    peers: Mutex<HashMap<PeerId, Peer>>,
    next_gen: AtomicU64,
    /// Events raised outside the receive loop (switches, overflow, down).
    notes: mpsc::UnboundedSender<TransportEvent>,
    /// Paths found dead by a `Closed` send, handled by the run loop.
    dead: mpsc::UnboundedSender<(PeerId, usize)>,
}

impl Shared {
    fn grow(&self, b: Duration) -> Duration {
        (b * 2).min(self.cfg.retry_max)
    }

    fn new_peer(&self) -> Peer {
        Peer::new(self.paths.len(), &self.cfg, self.next_gen.fetch_add(1, Ordering::Relaxed))
    }

    /// Send on one path; a closed path is reported dead.
    fn tx(&self, peer: PeerId, path: usize, f: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        let r = self.paths[path].1.send(peer, f, reliable);
        if r == Err(TransportError::Closed) {
            let _ = self.dead.send((peer, path));
        }
        r
    }

    /// Resend the oldest unacked frames on the active path.
    fn resend(&self, peer: PeerId, p: &mut Peer) {
        p.last_progress = Instant::now();
        p.gap = false;
        let Some(a) = p.active else { return };
        for (_, f) in p.unacked.iter().take(RESEND_WINDOW) {
            if self.tx(peer, a, f.clone(), true).is_err() {
                p.gap = true;
                return;
            }
        }
        // Frames past the window go out with the next resend.
        p.gap = p.unacked.len() > RESEND_WINDOW;
    }

    /// Make `to` the active path, resend everything unacked on it.
    fn switch(self: &Arc<Self>, peer: PeerId, p: &mut Peer, from: usize, to: usize) {
        p.active = Some(to);
        p.active_since = Instant::now();
        p.timeouts = 0;
        p.rto = self.cfg.rto;
        self.resend(peer, p);
        if from != to {
            let _ = self.notes.send(TransportEvent::PathSwitch {
                peer,
                from: self.paths[from].0.clone(),
                to: self.paths[to].0.clone(),
            });
        }
        self.ensure_upgrade(peer, p);
    }

    fn ensure_upgrade(self: &Arc<Self>, peer: PeerId, p: &mut Peer) {
        if p.confirmed && !p.upgrading && p.active.is_some_and(|a| a > 0) {
            p.upgrading = true;
            tokio::spawn(upgrade(Arc::downgrade(self), peer, p.inc));
        }
    }

    fn confirm(self: &Arc<Self>, peer: PeerId, p: &mut Peer) {
        if !p.confirmed {
            p.confirmed = true;
            self.ensure_upgrade(peer, p);
        }
    }

    fn drop_peer(&self, peer: PeerId, peers: &mut HashMap<PeerId, Peer>) {
        peers.remove(&peer);
        for (_, t) in &self.paths {
            t.disconnect(peer);
        }
    }

    /// Room for one more unconfirmed peer: evict the oldest if full.
    fn admit_stranger(&self, peers: &mut HashMap<PeerId, Peer>) {
        let mut un: Vec<_> = peers.iter().filter(|(_, p)| !p.confirmed).map(|(id, p)| (p.created, *id)).collect();
        if un.len() < MAX_UNCONFIRMED {
            return;
        }
        un.sort();
        let old = un[0].1;
        self.drop_peer(old, peers);
        let _ = self.notes.send(TransportEvent::Down { peer: old });
    }

    fn on_event(self: &Arc<Self>, peers: &mut HashMap<PeerId, Peer>, path: usize, ev: TransportEvent, up: &mut Vec<TransportEvent>) {
        let (peer, data) = match ev {
            TransportEvent::Frame { peer, data } => (peer, data),
            TransportEvent::Down { peer } => return self.on_down(peers, peer, path),
            _ => return,
        };
        let Some(&kind) = data.first() else { return };
        let hdr = parse(&data);
        if !peers.contains_key(&peer) {
            // Stateless answers; only a stream start or datagram makes state.
            match (kind, hdr) {
                (L_PING, Some((e, n))) => {
                    let _ = self.tx(peer, path, header(L_PONG, e, n), true);
                    return;
                }
                (L_REL, Some((e, seq))) if seq != 0 => {
                    let _ = self.tx(peer, path, header(L_RESET, e, 0), true);
                    return;
                }
                (L_REL, Some(_)) | (L_UNREL, _) => {}
                _ => return,
            }
            self.admit_stranger(peers);
        }
        let p = match peers.entry(peer) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                // First contact: the path it came on is live.
                let p = e.insert(self.new_peer());
                p.live[path] = true;
                p.active = Some(path);
                p
            }
        };
        p.last_rx[path] = Instant::now();
        // Did this frame prove the sender is using `path` now?
        let mut moved = false;
        match kind {
            L_UNREL => up.push(TransportEvent::Frame { peer, data: data[1..].to_vec() }),
            L_ACK => {
                let Some((epoch, next)) = hdr else { return };
                if epoch != p.epoch {
                    return;
                }
                while p.unacked.front().is_some_and(|(s, _)| *s < next) {
                    let (_, f) = p.unacked.pop_front().unwrap();
                    p.unacked_bytes -= f.len();
                    moved = true;
                }
                if moved {
                    p.last_progress = Instant::now();
                    p.rto = self.cfg.rto;
                    p.timeouts = 0;
                    if p.gap {
                        self.resend(peer, p);
                    }
                }
            }
            L_REL => {
                let Some((epoch, seq)) = hdr else { return };
                if p.rx_epoch != Some(epoch) {
                    if p.rx_old.contains(&epoch) {
                        return; // stale frame of a previous sender incarnation
                    }
                    if seq != 0 {
                        let _ = self.tx(peer, path, header(L_RESET, epoch, 0), true);
                        return;
                    }
                    if let Some(old) = p.rx_epoch.replace(epoch) {
                        p.rx_old.push_back(old);
                        if p.rx_old.len() > OLD_EPOCHS {
                            p.rx_old.pop_front();
                        }
                    }
                    p.rx_next = 0;
                }
                p.ack_due = true;
                if seq == p.rx_next {
                    p.rx_next += 1;
                    moved = true;
                    up.push(TransportEvent::Frame { peer, data: data[HDR..].to_vec() });
                }
            }
            L_PING => {
                if let Some((e, n)) = hdr {
                    let _ = self.tx(peer, path, header(L_PONG, e, n), true);
                }
            }
            L_PONG => {
                if p.probing == Some(path) && hdr == Some((p.epoch, p.probe_nonce)) {
                    p.probe_ok = true;
                }
            }
            L_RESET => {
                if hdr.is_some_and(|(e, _)| e == p.epoch) {
                    self.drop_peer(peer, peers);
                    let _ = self.notes.send(TransportEvent::Down { peer });
                }
                return;
            }
            _ => {}
        }
        // Follow the sender: new data on another path while ours is quiet.
        if moved
            && let Some(a) = p.active
            && a != path
            && p.last_rx[a].elapsed() >= self.cfg.rto
        {
            for k in 0..self.paths.len() {
                if k != path && p.live[k] {
                    p.live[k] = false;
                    self.paths[k].1.disconnect(peer);
                }
            }
            p.live[path] = true;
            p.probing = None;
            self.switch(peer, p, a, path);
        }
    }

    fn on_down(self: &Arc<Self>, peers: &mut HashMap<PeerId, Peer>, peer: PeerId, path: usize) {
        let Some(p) = peers.get_mut(&peer) else { return };
        if !p.live[path] {
            return;
        }
        p.live[path] = false;
        if p.probing == Some(path) {
            p.probing = None;
        }
        if p.active != Some(path) {
            return;
        }
        // A path that dies soon after taking over backs off its next retry.
        p.backoff = if p.active_since.elapsed() >= self.cfg.probe * 10 {
            self.cfg.retry_base
        } else {
            self.grow(p.backoff)
        };
        p.active = None;
        match (0..self.paths.len()).find(|&j| p.live[j]) {
            Some(j) => self.switch(peer, p, path, j),
            None => {
                tokio::spawn(reconnect(Arc::downgrade(self), peer, path, p.inc));
            }
        }
    }

    fn flush_acks(&self, peers: &mut HashMap<PeerId, Peer>) {
        for (peer, p) in peers.iter_mut() {
            if !std::mem::take(&mut p.ack_due) {
                continue;
            }
            if let (Some(a), Some(e)) = (p.active, p.rx_epoch) {
                let _ = self.tx(*peer, a, header(L_ACK, e, p.rx_next), true);
            }
        }
    }

    fn on_tick(self: &Arc<Self>) {
        let mut peers = self.peers.lock().unwrap();
        let mut dead = vec![];
        let mut expired = vec![];
        for (peer, p) in peers.iter_mut() {
            if !p.confirmed && p.created.elapsed() >= UNCONFIRMED_TTL {
                expired.push(*peer);
                continue;
            }
            if p.unacked.is_empty() || p.last_progress.elapsed() < p.rto {
                continue;
            }
            p.timeouts += 1;
            p.rto = (p.rto * 2).min(self.cfg.rto * RTO_MAX_FACTOR);
            match p.active {
                Some(a) if p.timeouts >= DEAD_RTOS => {
                    p.last_progress = Instant::now();
                    dead.push((*peer, a));
                }
                _ => self.resend(*peer, p),
            }
        }
        for peer in expired {
            self.drop_peer(peer, &mut peers);
            let _ = self.notes.send(TransportEvent::Down { peer });
        }
        for (peer, a) in dead {
            tracing::debug!(%peer, path = %self.paths[a].0, "no acks: path dead");
            self.on_down(&mut peers, peer, a);
        }
    }
}

async fn connect_on(t: Arc<dyn Transport>, peer: PeerId, addrs: Vec<Multiaddr>, limit: Option<Duration>) -> anyhow::Result<()> {
    let c = t.connect(peer, addrs);
    match limit {
        Some(l) => tokio::time::timeout(l, c)
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("connect timed out"))),
        None => c.await,
    }
}

/// Run `f` on this generation of `peer`'s state, if both still exist.
fn with_peer<T>(w: &Weak<Shared>, peer: PeerId, inc: u64, f: impl FnOnce(&Arc<Shared>, &mut Peer) -> T) -> Option<T> {
    let s = w.upgrade()?;
    let mut peers = s.peers.lock().unwrap();
    let p = peers.get_mut(&peer).filter(|p| p.inc == inc)?;
    Some(f(&s, p))
}

enum Step {
    Wait,
    Done,
    Try(Vec<Multiaddr>, Vec<Arc<dyn Transport>>, Duration),
}

/// Background retry of better paths while a worse one is active. Holds only
/// a weak reference across awaits.
async fn upgrade(w: Weak<Shared>, peer: PeerId, inc: u64) {
    loop {
        let Some(backoff) = with_peer(&w, peer, inc, |_, p| p.backoff) else { return };
        tokio::time::sleep(backoff).await;
        let step = with_peer(&w, peer, inc, |s, p| match p.active {
            None => Step::Wait, // reconnecting
            Some(0) => {
                p.upgrading = false;
                Step::Done
            }
            Some(a) => Step::Try(
                p.addrs.clone(),
                s.paths[..a].iter().map(|(_, t)| t.clone()).collect(),
                s.cfg.connect_timeout,
            ),
        });
        let (addrs, better, limit) = match step {
            None | Some(Step::Done) => return,
            Some(Step::Wait) => continue,
            Some(Step::Try(addrs, better, limit)) => (addrs, better, limit),
        };
        let mut got = None;
        for (j, t) in better.into_iter().enumerate() {
            if connect_on(t, peer, addrs.clone(), Some(limit)).await.is_ok() {
                got = Some(j);
                break;
            }
        }
        let started = with_peer(&w, peer, inc, |s, p| {
            let Some(j) = got else {
                p.backoff = s.grow(p.backoff);
                return None;
            };
            p.live[j] = true;
            p.probing = Some(j);
            p.probe_ok = false;
            p.probe_nonce = random();
            Some((j, s.cfg.probe))
        });
        let (j, probe) = match started {
            None => return,
            Some(None) => continue,
            Some(Some(x)) => x,
        };
        // Two pings, so one lost to a racing connect doesn't fail the probe.
        for _ in 0..2 {
            let ping = with_peer(&w, peer, inc, |s, p| {
                let _ = s.tx(peer, j, header(L_PING, p.epoch, p.probe_nonce), true);
            });
            if ping.is_none() {
                return;
            }
            tokio::time::sleep(probe / 2).await;
        }
        let Some(s) = w.upgrade() else { return };
        let mut peers = s.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&peer).filter(|p| p.inc == inc) else { return };
        if p.probing != Some(j) || !p.probe_ok {
            // Down during the probe, or it carries nothing back.
            if p.probing == Some(j) {
                p.probing = None;
                p.live[j] = false;
            }
            p.backoff = s.grow(p.backoff);
            continue;
        }
        p.probing = None;
        if let Some(a) = p.active.filter(|a| j < *a) {
            // Stable: move over and drop the worse paths (the relay).
            for k in j + 1..s.paths.len() {
                if p.live[k] {
                    p.live[k] = false;
                    s.paths[k].1.disconnect(peer);
                }
            }
            // `upgrading` stays set: this task keeps going until path 0.
            s.switch(peer, p, a, j);
        }
    }
}

/// The active path died and no other is live: reconnect one, best other
/// path first, the dead one last.
async fn reconnect(w: Weak<Shared>, peer: PeerId, dead: usize, inc: u64) {
    let Some((addrs, paths, limit)) = with_peer(&w, peer, inc, |s, p| {
        (p.addrs.clone(), s.paths.iter().map(|(_, t)| t.clone()).collect::<Vec<_>>(), s.cfg.connect_timeout)
    }) else {
        return;
    };
    let order: Vec<usize> = (0..paths.len()).filter(|&j| j != dead).chain([dead]).collect();
    for (k, &j) in order.iter().enumerate() {
        // The last try gets no limit (a slow relay still beats dropping).
        let limit = (k + 1 < order.len()).then_some(limit);
        if connect_on(paths[j].clone(), peer, addrs.clone(), limit).await.is_ok() {
            with_peer(&w, peer, inc, |s, p| {
                p.live[j] = true;
                if p.active.is_none() {
                    s.switch(peer, p, dead, j);
                }
            });
            return;
        }
    }
    let Some(s) = w.upgrade() else { return };
    let mut peers = s.peers.lock().unwrap();
    if peers.get(&peer).is_some_and(|p| p.inc == inc && p.active.is_none()) {
        s.drop_peer(peer, &mut peers);
        let _ = s.notes.send(TransportEvent::Down { peer });
    }
}

async fn run(
    s: Arc<Shared>,
    mut merged: mpsc::Receiver<(usize, TransportEvent)>,
    mut notes: mpsc::UnboundedReceiver<TransportEvent>,
    mut dead: mpsc::UnboundedReceiver<(PeerId, usize)>,
    out: mpsc::Sender<TransportEvent>,
) {
    let mut tick = tokio::time::interval(TICK);
    loop {
        let mut up = vec![];
        tokio::select! {
            ev = merged.recv() => {
                let Some((path, ev)) = ev else { return };
                let mut peers = s.peers.lock().unwrap();
                s.on_event(&mut peers, path, ev, &mut up);
                for _ in 0..BATCH {
                    let Ok((path, ev)) = merged.try_recv() else { break };
                    s.on_event(&mut peers, path, ev, &mut up);
                }
                s.flush_acks(&mut peers);
            }
            Some(n) = notes.recv() => up.push(n),
            Some((peer, path)) = dead.recv() => s.on_down(&mut s.peers.lock().unwrap(), peer, path),
            _ = tick.tick() => s.on_tick(),
        }
        for e in up {
            if out.send(e).await.is_err() {
                return;
            }
        }
    }
}

/// Several ranked paths to the same peers, behind one `Transport`.
pub struct PathSet {
    shared: Arc<Shared>,
    rx: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for PathSet {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl PathSet {
    /// `paths` are `(name, transport)`, best first; all must share one
    /// local peer id. Takes every transport's events.
    pub fn new(paths: Vec<(String, Arc<dyn Transport>)>, cfg: PathConfig) -> anyhow::Result<Arc<PathSet>> {
        anyhow::ensure!(!paths.is_empty(), "no paths");
        let me = paths[0].1.local_peer();
        anyhow::ensure!(paths.iter().all(|(_, t)| t.local_peer() == me), "paths disagree on the local peer");
        let (mtx, merged) = mpsc::channel(QUEUE);
        let mut tasks = vec![];
        for (i, (name, t)) in paths.iter().enumerate() {
            let mut rx = t.take_events().ok_or_else(|| anyhow::anyhow!("path {name}: events already taken"))?;
            let mtx = mtx.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    if mtx.send((i, ev)).await.is_err() {
                        return;
                    }
                }
            }));
        }
        let (ntx, notes) = mpsc::unbounded_channel();
        let (dtx, dead) = mpsc::unbounded_channel();
        let (otx, orx) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared {
            paths,
            cfg,
            peers: Mutex::new(HashMap::new()),
            next_gen: AtomicU64::new(0),
            notes: ntx,
            dead: dtx,
        });
        tasks.push(tokio::spawn(run(shared.clone(), merged, notes, dead, otx)));
        Ok(Arc::new(PathSet { shared, rx: Mutex::new(Some(orx)), tasks }))
    }

    /// Name of the path traffic to `peer` currently uses.
    pub fn active_path(&self, peer: PeerId) -> Option<String> {
        let peers = self.shared.peers.lock().unwrap();
        let a = peers.get(&peer)?.active?;
        Some(self.shared.paths[a].0.clone())
    }

    /// Names of the paths up to `peer`, best first.
    pub fn live_paths(&self, peer: PeerId) -> Vec<String> {
        let peers = self.shared.peers.lock().unwrap();
        let Some(p) = peers.get(&peer) else { return vec![] };
        (0..p.live.len()).filter(|&j| p.live[j]).map(|j| self.shared.paths[j].0.clone()).collect()
    }

    /// Reliable bytes sent to `peer` and not yet acknowledged.
    pub fn unacked_bytes(&self, peer: PeerId) -> usize {
        self.shared.peers.lock().unwrap().get(&peer).map_or(0, |p| p.unacked_bytes)
    }
}

impl Transport for PathSet {
    fn local_peer(&self) -> PeerId {
        self.shared.paths[0].1.local_peer()
    }

    fn local_addrs(&self) -> BoxFuture<'_, Vec<Multiaddr>> {
        async move { join_all(self.shared.paths.iter().map(|(_, t)| t.local_addrs())).await.concat() }.boxed()
    }

    fn connect(&self, peer: PeerId, addrs: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            let s = &self.shared;
            if let Some(p) = s.peers.lock().unwrap().get_mut(&peer) {
                if !addrs.is_empty() {
                    p.addrs = addrs.clone();
                }
                if p.active.is_some() {
                    s.confirm(peer, p);
                    return Ok(());
                }
            }
            let n = s.paths.len();
            let mut err = anyhow::anyhow!("no path to {peer}");
            for j in 0..n {
                let limit = (j + 1 < n).then_some(s.cfg.connect_timeout);
                match connect_on(s.paths[j].1.clone(), peer, addrs.clone(), limit).await {
                    Ok(()) => {
                        let mut peers = s.peers.lock().unwrap();
                        let p = peers.entry(peer).or_insert_with(|| s.new_peer());
                        if !addrs.is_empty() {
                            p.addrs = addrs;
                        }
                        p.live[j] = true;
                        if p.active.is_none() {
                            p.active = Some(j);
                            p.active_since = Instant::now();
                            s.resend(peer, p);
                        }
                        p.confirmed = true;
                        s.ensure_upgrade(peer, p);
                        return Ok(());
                    }
                    Err(e) => err = e,
                }
            }
            Err(err)
        }
        .boxed()
    }

    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        let s = &self.shared;
        if HDR + frame.len() > FRAME_MAX {
            return Err(TransportError::Backlog);
        }
        let mut peers = s.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&peer) else { return Err(TransportError::Closed) };
        s.confirm(peer, p);
        if !reliable {
            let Some(a) = p.active else { return Ok(()) };
            let mut f = Vec::with_capacity(1 + frame.len());
            f.push(L_UNREL);
            f.extend_from_slice(&frame);
            return s.tx(peer, a, f, false);
        }
        let mut f = header(L_REL, p.epoch, p.tx_seq);
        f.extend_from_slice(&frame);
        if p.unacked_bytes + f.len() > s.cfg.resend_cap {
            s.drop_peer(peer, &mut peers);
            let _ = s.notes.send(TransportEvent::Overflow { peer });
            return Err(TransportError::Backlog);
        }
        if p.unacked.is_empty() {
            p.last_progress = Instant::now();
        }
        p.unacked_bytes += f.len();
        p.unacked.push_back((p.tx_seq, f.clone()));
        p.tx_seq += 1;
        // Refused or lost here means resent on the next ack, switch or timeout.
        if let Some(a) = p.active
            && !p.gap
            && s.tx(peer, a, f, true).is_err()
        {
            p.gap = true;
        }
        Ok(())
    }

    fn disconnect(&self, peer: PeerId) {
        let s = &self.shared;
        s.drop_peer(peer, &mut s.peers.lock().unwrap());
    }

    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.rx.lock().unwrap().take()
    }
}
