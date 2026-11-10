//! Multi-path delivery: ranked paths per peer, acks with resend, migration.
//!
//! `PathSet` is a `Transport` over several ranked transports (best first,
//! e.g. `[direct, relay]`). Per peer it sends on the best live path. While
//! that is not the best path, it keeps retrying the better ones with backoff;
//! one that connects and survives `probe` becomes active and the worse ones
//! are dropped. If the active path dies it falls back to another live path,
//! or reconnects one (best other path first), and only reports `Down` when
//! none works.
//!
//! Reliable frames carry a link sequence number and stay in a per-peer resend
//! buffer until the peer acks them (cumulative). Every switch resends the
//! buffer on the new path, and the receiver drops anything but the next
//! expected frame, so a path change loses and duplicates nothing. The buffer
//! is capped; a peer that passes the cap is dropped with `Overflow`.

use crate::transport::{Transport, TransportError, TransportEvent};
use cosmos_net::{Multiaddr, PeerId};
use futures::future::BoxFuture;
use futures::{FutureExt, future::join_all};
use std::collections::hash_map::RandomState;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct PathConfig {
    /// A better path must stay up this long before traffic moves to it.
    pub probe: Duration,
    /// Retry delay for better paths; doubles on each failure.
    pub retry_base: Duration,
    pub retry_max: Duration,
    /// Per-path connect limit (the worst path gets no limit on first connect).
    pub connect_timeout: Duration,
    /// Resend the unacked buffer when no ack progress for this long.
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
/// `[kind][epoch u32][seq u64]`; an ack is just this header.
const HDR: usize = 13;
const QUEUE: usize = 1024;
const BATCH: usize = 256;
const TICK: Duration = Duration::from_millis(50);

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

struct Peer {
    addrs: Vec<Multiaddr>,
    live: Vec<bool>,
    active: Option<usize>,
    active_since: Instant,
    /// A better path that connected and is waiting out `probe`.
    probing: Option<usize>,
    upgrading: bool,
    backoff: Duration,
    /// Random per sender state, so a restarted sender is not taken for
    /// duplicates of the old one.
    epoch: u32,
    tx_seq: u64,
    unacked: VecDeque<(u64, Vec<u8>)>,
    unacked_bytes: usize,
    last_progress: Instant,
    rx_epoch: Option<u32>,
    rx_next: u64,
    ack_due: bool,
}

impl Peer {
    fn new(paths: usize, backoff: Duration) -> Peer {
        Peer {
            addrs: vec![],
            live: vec![false; paths],
            active: None,
            active_since: Instant::now(),
            probing: None,
            upgrading: false,
            backoff,
            epoch: RandomState::new().build_hasher().finish() as u32,
            tx_seq: 0,
            unacked: VecDeque::new(),
            unacked_bytes: 0,
            last_progress: Instant::now(),
            rx_epoch: None,
            rx_next: 0,
            ack_due: false,
        }
    }
}

struct Shared {
    paths: Vec<(String, Arc<dyn Transport>)>,
    cfg: PathConfig,
    peers: Mutex<HashMap<PeerId, Peer>>,
    /// Events raised outside the receive loop (switches, overflow, down).
    notes: mpsc::UnboundedSender<TransportEvent>,
}

impl Shared {
    fn grow(&self, b: Duration) -> Duration {
        (b * 2).min(self.cfg.retry_max)
    }

    fn resend(&self, peer: PeerId, p: &mut Peer) {
        if let Some(a) = p.active {
            for (_, f) in &p.unacked {
                let _ = self.paths[a].1.send(peer, f.clone(), true);
            }
        }
        p.last_progress = Instant::now();
    }

    /// Make `to` the active path, resend everything unacked on it.
    fn switch(self: &Arc<Self>, peer: PeerId, p: &mut Peer, from: usize, to: usize) {
        p.active = Some(to);
        p.active_since = Instant::now();
        self.resend(peer, p);
        let _ = self.notes.send(TransportEvent::PathSwitch {
            peer,
            from: self.paths[from].0.clone(),
            to: self.paths[to].0.clone(),
        });
        self.ensure_upgrade(peer, p);
    }

    fn ensure_upgrade(self: &Arc<Self>, peer: PeerId, p: &mut Peer) {
        if !p.upgrading && p.active.is_some_and(|a| a > 0) {
            p.upgrading = true;
            tokio::spawn(upgrade(Arc::downgrade(self), peer));
        }
    }

    fn drop_peer(&self, peer: PeerId, peers: &mut HashMap<PeerId, Peer>) {
        peers.remove(&peer);
        for (_, t) in &self.paths {
            t.disconnect(peer);
        }
    }

    fn on_event(self: &Arc<Self>, peers: &mut HashMap<PeerId, Peer>, path: usize, ev: TransportEvent, up: &mut Vec<TransportEvent>) {
        let (peer, data) = match ev {
            TransportEvent::Frame { peer, data } => (peer, data),
            TransportEvent::Down { peer } => return self.on_down(peers, peer, path),
            _ => return,
        };
        let Some(&kind) = data.first() else { return };
        let p = match peers.entry(peer) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(_) if kind == L_ACK => return,
            Entry::Vacant(e) => {
                // First contact: the path it came on is live.
                let p = e.insert(Peer::new(self.paths.len(), self.cfg.retry_base));
                p.live[path] = true;
                p.active = Some(path);
                self.ensure_upgrade(peer, p);
                p
            }
        };
        match kind {
            L_UNREL => up.push(TransportEvent::Frame { peer, data: data[1..].to_vec() }),
            L_ACK => {
                let Some((epoch, next)) = parse(&data) else { return };
                if epoch != p.epoch {
                    return;
                }
                let mut progress = false;
                while p.unacked.front().is_some_and(|(s, _)| *s < next) {
                    let (_, f) = p.unacked.pop_front().unwrap();
                    p.unacked_bytes -= f.len();
                    progress = true;
                }
                if progress {
                    p.last_progress = Instant::now();
                }
            }
            L_REL => {
                let Some((epoch, seq)) = parse(&data) else { return };
                if p.rx_epoch != Some(epoch) {
                    if seq != 0 {
                        return;
                    }
                    p.rx_epoch = Some(epoch);
                    p.rx_next = 0;
                }
                p.ack_due = true;
                if seq == p.rx_next {
                    p.rx_next += 1;
                    up.push(TransportEvent::Frame { peer, data: data[HDR..].to_vec() });
                }
            }
            _ => {}
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
                tokio::spawn(reconnect(Arc::downgrade(self), peer, path));
            }
        }
    }

    fn flush_acks(&self, peers: &mut HashMap<PeerId, Peer>) {
        for (peer, p) in peers.iter_mut() {
            if !std::mem::take(&mut p.ack_due) {
                continue;
            }
            if let (Some(a), Some(e)) = (p.active, p.rx_epoch) {
                let _ = self.paths[a].1.send(*peer, header(L_ACK, e, p.rx_next), true);
            }
        }
    }

    fn on_tick(&self) {
        let mut peers = self.peers.lock().unwrap();
        for (peer, p) in peers.iter_mut() {
            if !p.unacked.is_empty() && p.last_progress.elapsed() >= self.cfg.rto {
                self.resend(*peer, p);
            }
        }
    }

    async fn try_connect(&self, j: usize, peer: PeerId, addrs: Vec<Multiaddr>, limit: bool) -> anyhow::Result<()> {
        let c = self.paths[j].1.connect(peer, addrs);
        if limit {
            tokio::time::timeout(self.cfg.connect_timeout, c)
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("connect timed out")))
        } else {
            c.await
        }
    }
}

/// Background retry of better paths while a worse one is active.
async fn upgrade(w: Weak<Shared>, peer: PeerId) {
    loop {
        let Some(s) = w.upgrade() else { return };
        let Some(backoff) = s.peers.lock().unwrap().get(&peer).map(|p| p.backoff) else { return };
        drop(s);
        tokio::time::sleep(backoff).await;
        let Some(s) = w.upgrade() else { return };
        let (active, addrs) = {
            let mut peers = s.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&peer) else { return };
            match p.active {
                None => continue, // reconnecting
                Some(0) => {
                    p.upgrading = false;
                    return;
                }
                Some(a) => (a, p.addrs.clone()),
            }
        };
        let mut got = None;
        for j in 0..active {
            if s.try_connect(j, peer, addrs.clone(), true).await.is_ok() {
                got = Some(j);
                break;
            }
        }
        {
            let mut peers = s.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&peer) else { return };
            let Some(j) = got else {
                p.backoff = s.grow(p.backoff);
                continue;
            };
            p.live[j] = true;
            p.probing = Some(j);
        }
        tokio::time::sleep(s.cfg.probe).await;
        let mut peers = s.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&peer) else { return };
        let j = got.unwrap();
        if p.probing != Some(j) {
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
            p.upgrading = false;
            s.switch(peer, p, a, j);
        }
    }
}

/// The active path died and no other is live: reconnect one, best other
/// path first, the dead one last.
async fn reconnect(w: Weak<Shared>, peer: PeerId, dead: usize) {
    let Some(s) = w.upgrade() else { return };
    let Some(addrs) = s.peers.lock().unwrap().get(&peer).map(|p| p.addrs.clone()) else { return };
    let order = (0..s.paths.len()).filter(|&j| j != dead).chain([dead]);
    for j in order {
        if s.try_connect(j, peer, addrs.clone(), true).await.is_ok() {
            let mut peers = s.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&peer) else { return };
            p.live[j] = true;
            if p.active.is_none() {
                s.switch(peer, p, dead, j);
            }
            return;
        }
    }
    let mut peers = s.peers.lock().unwrap();
    if peers.get(&peer).is_some_and(|p| p.active.is_none()) {
        s.drop_peer(peer, &mut peers);
        let _ = s.notes.send(TransportEvent::Down { peer });
    }
}

async fn run(
    s: Arc<Shared>,
    mut merged: mpsc::Receiver<(usize, TransportEvent)>,
    mut notes: mpsc::UnboundedReceiver<TransportEvent>,
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
        let (otx, orx) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared { paths, cfg, peers: Mutex::new(HashMap::new()), notes: ntx });
        tasks.push(tokio::spawn(run(shared.clone(), merged, notes, otx)));
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
                    return Ok(());
                }
            }
            let n = s.paths.len();
            let mut err = anyhow::anyhow!("no path to {peer}");
            for j in 0..n {
                match s.try_connect(j, peer, addrs.clone(), j + 1 < n).await {
                    Ok(()) => {
                        let mut peers = s.peers.lock().unwrap();
                        let p = peers.entry(peer).or_insert_with(|| Peer::new(n, s.cfg.retry_base));
                        if !addrs.is_empty() {
                            p.addrs = addrs;
                        }
                        p.live[j] = true;
                        if p.active.is_none() {
                            p.active = Some(j);
                            p.active_since = Instant::now();
                            s.resend(peer, p);
                        }
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
        let mut peers = s.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&peer) else { return Err(TransportError::Closed) };
        if !reliable {
            let Some(a) = p.active else { return Ok(()) };
            let mut f = Vec::with_capacity(1 + frame.len());
            f.push(L_UNREL);
            f.extend_from_slice(&frame);
            return s.paths[a].1.send(peer, f, false);
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
        // Lost or refused here means resent on the next switch or timeout.
        if let Some(a) = p.active {
            let _ = s.paths[a].1.send(peer, f, true);
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
