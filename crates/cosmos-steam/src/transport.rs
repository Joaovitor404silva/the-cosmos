//! `SteamTransport`: Cosmos frames over `ISteamNetworkingMessages` (SDR).
//!
//! A relay path for `PathSet`: it carries frames until direct libp2p is up,
//! then `PathSet` drops it, and takes them again if direct dies. Frames from
//! a SteamID only reach the session once the binding handshake (`bind`)
//! proved which Cosmos peer is behind it.
//!
//! Bindings heal themselves:
//! - frames from an unbound SteamID make us ask it for a proof;
//! - a `HELLO` from a bound SteamID makes us re-check it, so a peer that
//!   restarted with a new key on the same Steam account rebinds (the old
//!   peer gets `Down`);
//! - `connect` on a bound peer re-proves it, so `PathSet` reconnecting a dead
//!   path never trusts a stale binding.
//!
//! Frames over one Steam message are split into pieces (reliable only).
//! Strangers get at most half the handshake slots and a bounded number of
//! bindings, and proofs are rate limited.

use crate::backend::{MAX_MESSAGE, SendError, SteamBackend, SteamEvent, SteamId};
use crate::bind::{self, DATA, FRAG, FRAG_FIRST, FRAG_LAST, HELLO, HELLO_BACK, Nonce, PROOF};
use crate::record::SteamDirectory;
use cosmos_core::transport::FRAME_MAX;
use cosmos_core::{Transport, TransportError, TransportEvent};
use cosmos_net::{Keypair, Multiaddr, PeerId};
use futures::FutureExt;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};

#[derive(Clone, Debug)]
pub struct SteamTransportConfig {
    /// `connect` gives up after this long without a valid proof. Keep it at
    /// or under `PathConfig::connect_timeout`.
    pub handshake_timeout: Duration,
    /// Resend our HELLO this often while waiting.
    pub hello_every: Duration,
    /// Shortest sleep between polls when nothing arrived; idle polling backs
    /// off to 8x this.
    pub idle_poll: Duration,
    /// Unanswered handshakes kept at once; strangers get at most half.
    pub max_pending: usize,
    /// Bound peers kept at once; peers we did not ask for are evicted first.
    pub max_bindings: usize,
    /// Proofs we sign per second (each answers someone's HELLO).
    pub proofs_per_sec: u32,
}

impl Default for SteamTransportConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            hello_every: Duration::from_millis(500),
            idle_poll: Duration::from_millis(1),
            max_pending: 64,
            max_bindings: 16,
            proofs_per_sec: 64,
        }
    }
}

/// Largest Cosmos frame one Steam message carries (1 byte for the kind).
/// Bigger reliable frames (up to `FRAME_MAX`) are split.
pub const MAX_FRAME: usize = MAX_MESSAGE - 1;
const CHUNK: usize = MAX_MESSAGE - 2;
const EVENT_QUEUE: usize = 1024;

struct Pending {
    nonce: Nonce,
    /// The peer `connect` asked for; a proof from anyone else is rejected.
    expect: Option<PeerId>,
    /// We asked (connect), as opposed to a stranger or a re-check.
    outbound: bool,
    since: Instant,
    last_hello: Instant,
}

struct Binding {
    peer: PeerId,
    /// We asked for this peer at some point.
    wanted: bool,
    last_rx: Instant,
}

#[derive(Default)]
struct State {
    by_steam: HashMap<SteamId, Binding>,
    by_peer: HashMap<PeerId, SteamId>,
    pending: HashMap<SteamId, Pending>,
    /// Verified proofs per SteamID, so `connect` can wait for a fresh one.
    proofs: HashMap<SteamId, u64>,
    /// Frames being rebuilt from pieces.
    asm: HashMap<SteamId, Vec<u8>>,
    tokens: (u32, Option<Instant>),
}

impl State {
    fn unbind(&mut self, steam: SteamId) -> Option<PeerId> {
        let b = self.by_steam.remove(&steam)?;
        if self.by_peer.get(&b.peer) == Some(&steam) {
            self.by_peer.remove(&b.peer);
        }
        self.asm.remove(&steam);
        Some(b.peer)
    }

    fn strangers_pending(&self) -> usize {
        self.pending.values().filter(|p| !p.outbound).count()
    }

    /// Start a handshake we were not asked for, if strangers have room.
    fn pending_inbound(&mut self, from: SteamId, cap: usize) -> Option<Nonce> {
        if self.pending.contains_key(&from) || self.strangers_pending() >= cap / 2 {
            return None;
        }
        let n = bind::new_nonce();
        let now = Instant::now();
        self.pending.insert(from, Pending { nonce: n, expect: None, outbound: false, since: now, last_hello: now });
        Some(n)
    }

    fn take_token(&mut self, per_sec: u32) -> bool {
        let now = Instant::now();
        if self.tokens.1.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1)) {
            self.tokens = (per_sec, Some(now));
        }
        if self.tokens.0 == 0 {
            return false;
        }
        self.tokens.0 -= 1;
        true
    }
}

struct Shared {
    backend: Arc<dyn SteamBackend>,
    key: Keypair,
    me: PeerId,
    my_steam: SteamId,
    dir: Arc<dyn SteamDirectory>,
    cfg: SteamTransportConfig,
    state: Mutex<State>,
    bound: Notify,
    events: mpsc::Sender<TransportEvent>,
}

pub struct SteamTransport {
    shared: Arc<Shared>,
    rx: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for SteamTransport {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl SteamTransport {
    /// `key` is this node's Cosmos identity (the one its other paths use).
    pub fn new(
        backend: Arc<dyn SteamBackend>,
        key: Keypair,
        dir: Arc<dyn SteamDirectory>,
        cfg: SteamTransportConfig,
    ) -> Arc<Self> {
        let (events, rx) = mpsc::channel(EVENT_QUEUE);
        let shared = Arc::new(Shared {
            my_steam: backend.steam_id(),
            backend,
            me: key.public().to_peer_id(),
            key,
            dir,
            cfg,
            state: Mutex::new(State::default()),
            bound: Notify::new(),
            events,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (shared.clone(), stop.clone());
        std::thread::Builder::new()
            .name("cosmos-steam".into())
            .spawn(move || s.pump(&st))
            .expect("spawn steam pump");
        Arc::new(SteamTransport { shared, rx: Mutex::new(Some(rx)), stop })
    }

    pub fn steam_id(&self) -> SteamId {
        self.shared.my_steam
    }

    /// The SteamID bound to `peer`, if the handshake completed.
    pub fn bound_steam_id(&self, peer: PeerId) -> Option<SteamId> {
        self.shared.state.lock().unwrap().by_peer.get(&peer).copied()
    }

    /// Handshake with a SteamID (e.g. from a lobby invite) and return the
    /// Cosmos peer it proves to be. `expect`: fail unless it is this peer.
    pub async fn connect_steam(&self, steam: SteamId, expect: Option<PeerId>) -> anyhow::Result<PeerId> {
        self.handshake(steam, expect, false).await
    }

    /// `fresh`: a current binding doesn't count; wait for a new proof.
    async fn handshake(&self, steam: SteamId, expect: Option<PeerId>, fresh: bool) -> anyhow::Result<PeerId> {
        let s = &self.shared;
        anyhow::ensure!(steam != s.my_steam, "that is our own SteamID");
        let deadline = Instant::now() + s.cfg.handshake_timeout;
        let start = s.state.lock().unwrap().proofs.get(&steam).copied().unwrap_or(0);
        loop {
            let wake = s.bound.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let nonce = {
                let mut st = s.state.lock().unwrap();
                let proved = st.proofs.get(&steam).copied().unwrap_or(0) > start;
                if let Some(b) = st.by_steam.get_mut(&steam)
                    && (!fresh || proved)
                {
                    let peer = b.peer;
                    if expect.is_some_and(|e| e != peer) {
                        anyhow::bail!("SteamID {steam} is bound to {peer}, not the expected peer");
                    }
                    b.wanted = true;
                    return Ok(peer);
                }
                let now = Instant::now();
                if !st.pending.contains_key(&steam) && st.pending.len() >= s.cfg.max_pending {
                    // Our own connects outrank strangers: evict the oldest one.
                    let old = st.pending.iter().filter(|(_, p)| !p.outbound).min_by_key(|(_, p)| p.since).map(|(k, _)| *k);
                    match old {
                        Some(k) => {
                            st.pending.remove(&k);
                        }
                        None => anyhow::bail!("too many Steam handshakes in flight"),
                    }
                }
                let p = st.pending.entry(steam).or_insert_with(|| Pending {
                    nonce: bind::new_nonce(),
                    expect,
                    outbound: true,
                    since: now,
                    last_hello: now,
                });
                p.outbound = true;
                if expect.is_some() {
                    p.expect = expect;
                }
                p.last_hello = now;
                p.nonce
            };
            s.backend.allow(steam);
            match s.backend.send(steam, &bind::hello(&nonce), true) {
                Ok(()) | Err(SendError::Full) => {}
                Err(e) => tracing::debug!(steam, ?e, "steam hello failed"),
            }
            let now = Instant::now();
            if now >= deadline {
                let mut st = s.state.lock().unwrap();
                st.pending.remove(&steam);
                if fresh {
                    // It stopped answering: the old binding is stale.
                    st.unbind(steam);
                }
                anyhow::bail!("no Steam handshake with {steam}");
            }
            let _ = tokio::time::timeout(s.cfg.hello_every.min(deadline - now), wake).await;
        }
    }
}

impl Shared {
    fn pump(self: Arc<Self>, stop: &AtomicBool) {
        let mut buf = Vec::new();
        let mut last_gc = Instant::now();
        let mut idle = 0u32;
        while !stop.load(Ordering::Relaxed) {
            self.backend.poll(&mut buf);
            if buf.is_empty() {
                idle = (idle + 1).min(8);
                std::thread::sleep(self.cfg.idle_poll * idle);
            } else {
                idle = 0;
            }
            for ev in buf.drain(..) {
                match ev {
                    SteamEvent::Message { from, data } => self.on_message(from, data),
                    SteamEvent::SessionFailed { remote } => self.lost(remote, true),
                }
            }
            if last_gc.elapsed() >= Duration::from_secs(1) {
                last_gc = Instant::now();
                let ttl = self.cfg.handshake_timeout * 2;
                self.state.lock().unwrap().pending.retain(|_, p| p.since.elapsed() < ttl);
            }
        }
    }

    /// From the pump thread only (may block on a full event queue).
    fn emit(&self, ev: TransportEvent) {
        let _ = self.events.blocking_send(ev);
    }

    fn on_message(&self, from: SteamId, data: Vec<u8>) {
        let Some(&kind) = data.first() else { return };
        match kind {
            DATA | FRAG => self.on_data(from, kind, data),
            HELLO | HELLO_BACK => {
                let Some(nonce) = bind::parse_hello(&data) else { return };
                let (back, sign) = {
                    let mut st = self.state.lock().unwrap();
                    // A HELLO (not a HELLO_BACK) is a reason to (re)check them:
                    // they may be new, or a new key on a bound SteamID.
                    let back = if kind == HELLO { st.pending_inbound(from, self.cfg.max_pending) } else { None };
                    (back, st.take_token(self.cfg.proofs_per_sec))
                };
                if let Some(n) = back {
                    let _ = self.backend.send(from, &bind::hello_kind(HELLO_BACK, &n), true);
                }
                if sign {
                    let _ = self.backend.send(from, &bind::proof(&self.key, self.my_steam, from, &nonce), true);
                }
            }
            PROOF => self.on_proof(from, &data),
            _ => {}
        }
    }

    fn on_data(&self, from: SteamId, kind: u8, mut data: Vec<u8>) {
        let mut st = self.state.lock().unwrap();
        let Some(b) = st.by_steam.get_mut(&from) else {
            // They think we are bound: ask who they are (rate limited).
            let ask = match st.pending.get_mut(&from) {
                Some(p) if p.last_hello.elapsed() >= self.cfg.hello_every => {
                    p.last_hello = Instant::now();
                    Some(p.nonce)
                }
                Some(_) => None,
                None => st.pending_inbound(from, self.cfg.max_pending),
            };
            drop(st);
            if let Some(n) = ask {
                let _ = self.backend.send(from, &bind::hello(&n), true);
            }
            return;
        };
        b.last_rx = Instant::now();
        let peer = b.peer;
        let frame = if kind == DATA {
            data.remove(0);
            Some(data)
        } else {
            let (Some(&flags), Some(chunk)) = (data.get(1), data.get(2..)) else { return };
            if flags & FRAG_FIRST != 0 {
                // A new frame; any unfinished one was abandoned by the sender.
                st.asm.insert(from, Vec::new());
            }
            let full = match st.asm.get_mut(&from) {
                Some(buf) if buf.len() + chunk.len() <= FRAME_MAX => {
                    buf.extend_from_slice(chunk);
                    flags & FRAG_LAST != 0
                }
                _ => {
                    st.asm.remove(&from);
                    false
                }
            };
            if full { st.asm.remove(&from) } else { None }
        };
        drop(st);
        if let Some(data) = frame {
            self.emit(TransportEvent::Frame { peer, data });
        }
    }

    fn on_proof(&self, from: SteamId, data: &[u8]) {
        let mut downs = vec![];
        {
            let mut st = self.state.lock().unwrap();
            let Some(p) = st.pending.get(&from) else { return };
            let Some(peer) = bind::verify_proof(data, from, self.my_steam, &p.nonce) else {
                tracing::debug!(from, "steam proof rejected");
                return;
            };
            if p.expect.is_some_and(|e| e != peer) || peer == self.me {
                tracing::debug!(from, %peer, "steam proof for an unexpected peer rejected");
                return;
            }
            let wanted = p.outbound;
            st.pending.remove(&from);
            *st.proofs.entry(from).or_default() += 1;
            // The SteamID now proves a different key: the old peer is gone.
            if st.by_steam.get(&from).is_some_and(|b| b.peer != peer)
                && let Some(old) = st.unbind(from)
            {
                downs.push(old);
            }
            // The key moved to another SteamID.
            if let Some(&old) = st.by_peer.get(&peer)
                && old != from
            {
                st.unbind(old);
            }
            if !st.by_steam.contains_key(&from) && st.by_steam.len() >= self.cfg.max_bindings {
                // Full: evict the stalest, strangers first.
                let evict =
                    st.by_steam.iter().min_by_key(|(_, b)| (b.wanted, b.last_rx)).map(|(k, _)| *k);
                if let Some(k) = evict
                    && let Some(old) = st.unbind(k)
                {
                    downs.push(old);
                }
            }
            let b = st.by_steam.entry(from).or_insert(Binding { peer, wanted, last_rx: Instant::now() });
            b.wanted |= wanted;
            b.last_rx = Instant::now();
            st.by_peer.insert(peer, from);
            tracing::debug!(from, %peer, "steam binding up");
        }
        self.backend.allow(from);
        self.bound.notify_waiters();
        for peer in downs {
            self.emit(TransportEvent::Down { peer });
        }
    }

    /// The Steam session to `steam` is gone: unbind and report the path down.
    /// `pump`: called on the pump thread (may block to deliver `Down`);
    /// otherwise from `send`, which reports `Closed` itself.
    fn lost(&self, steam: SteamId, pump: bool) {
        let peer = self.state.lock().unwrap().unbind(steam);
        self.backend.close(steam);
        if let Some(peer) = peer {
            if pump {
                self.emit(TransportEvent::Down { peer });
            } else {
                let _ = self.events.try_send(TransportEvent::Down { peer });
            }
        }
    }

    fn send_msg(&self, steam: SteamId, m: &[u8], reliable: bool) -> Result<(), TransportError> {
        match self.backend.send(steam, m, reliable) {
            Ok(()) => Ok(()),
            Err(SendError::Full) if reliable => Err(TransportError::Backlog),
            Err(SendError::Full) => Ok(()),
            Err(e) => {
                tracing::debug!(steam, ?e, "steam send failed; path down");
                self.lost(steam, false);
                Err(TransportError::Closed)
            }
        }
    }
}

impl Transport for SteamTransport {
    fn local_peer(&self) -> PeerId {
        self.shared.me
    }

    fn local_addrs(&self) -> BoxFuture<'_, Vec<Multiaddr>> {
        async { vec![] }.boxed()
    }

    /// Always proves the peer afresh, so a stale binding never passes for a
    /// working path.
    fn connect(&self, peer: PeerId, _: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            let steam = match self.bound_steam_id(peer) {
                Some(s) => s,
                None => self
                    .shared
                    .dir
                    .lookup(peer)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("no SteamID known for {peer}"))?,
            };
            self.handshake(steam, Some(peer), true).await.map(|_| ())
        }
        .boxed()
    }

    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        let s = &self.shared;
        let steam = s.state.lock().unwrap().by_peer.get(&peer).copied().ok_or(TransportError::Closed)?;
        if frame.len() > FRAME_MAX {
            return Err(TransportError::Backlog);
        }
        if frame.len() <= MAX_FRAME {
            let mut m = Vec::with_capacity(frame.len() + 1);
            m.push(DATA);
            m.extend_from_slice(&frame);
            return s.send_msg(steam, &m, reliable);
        }
        if !reliable {
            // Best effort: too big to send as one datagram.
            return Ok(());
        }
        // A refused piece leaves a partial frame the receiver drops when the
        // next frame's first piece arrives; the caller resends the whole.
        let n = frame.len().div_ceil(CHUNK);
        for (i, c) in frame.chunks(CHUNK).enumerate() {
            let mut flags = 0;
            if i == 0 {
                flags |= FRAG_FIRST;
            }
            if i + 1 == n {
                flags |= FRAG_LAST;
            }
            let mut m = Vec::with_capacity(c.len() + 2);
            m.extend_from_slice(&[FRAG, flags]);
            m.extend_from_slice(c);
            s.send_msg(steam, &m, true)?;
        }
        Ok(())
    }

    /// Keeps the binding: the peer may still be sending to us over Steam,
    /// and `connect` re-proves it before the path is used again.
    fn disconnect(&self, _: PeerId) {}

    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.rx.lock().unwrap().take()
    }
}
