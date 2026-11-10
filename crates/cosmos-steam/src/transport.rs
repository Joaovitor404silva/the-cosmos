//! `SteamTransport`: Cosmos frames over `ISteamNetworkingMessages` (SDR).
//!
//! A relay path for `PathSet`: it carries frames until direct libp2p is up,
//! then `PathSet` drops it, and takes them again if direct dies. Frames from
//! a SteamID only reach the session once the binding handshake (`bind`)
//! proved which Cosmos peer is behind it.

use crate::backend::{MAX_MESSAGE, SendError, SteamBackend, SteamEvent, SteamId};
use crate::bind::{self, DATA, HELLO, Nonce, PROOF};
use crate::record::SteamDirectory;
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
    /// `connect` gives up after this long without a valid proof.
    pub handshake_timeout: Duration,
    /// Resend our HELLO this often while waiting.
    pub hello_every: Duration,
    /// Sleep between polls when nothing arrived.
    pub idle_poll: Duration,
    /// Unanswered handshakes kept at once (inbound strangers included).
    pub max_pending: usize,
}

impl Default for SteamTransportConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            hello_every: Duration::from_millis(500),
            idle_poll: Duration::from_millis(1),
            max_pending: 64,
        }
    }
}

/// Largest Cosmos frame one Steam message carries (1 byte for the kind).
pub const MAX_FRAME: usize = MAX_MESSAGE - 1;
const EVENT_QUEUE: usize = 1024;

struct Pending {
    nonce: Nonce,
    /// The peer `connect` asked for; a proof from anyone else is rejected.
    expect: Option<PeerId>,
    since: Instant,
}

#[derive(Default)]
struct State {
    by_steam: HashMap<SteamId, PeerId>,
    by_peer: HashMap<PeerId, SteamId>,
    pending: HashMap<SteamId, Pending>,
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
        let s = &self.shared;
        anyhow::ensure!(steam != s.my_steam, "that is our own SteamID");
        let deadline = Instant::now() + s.cfg.handshake_timeout;
        loop {
            let wake = s.bound.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let nonce = {
                let mut st = s.state.lock().unwrap();
                if let Some(&peer) = st.by_steam.get(&steam) {
                    if expect.is_some_and(|e| e != peer) {
                        anyhow::bail!("SteamID {steam} is bound to {peer}, not the expected peer");
                    }
                    return Ok(peer);
                }
                let now = Instant::now();
                let cap = s.cfg.max_pending;
                let p = st.pending.entry(steam).or_insert_with(|| Pending { nonce: bind::new_nonce(), expect, since: now });
                if expect.is_some() {
                    p.expect = expect;
                }
                let n = p.nonce;
                if st.pending.len() > cap {
                    st.pending.remove(&steam);
                    anyhow::bail!("too many Steam handshakes in flight");
                }
                n
            };
            match s.backend.send(steam, &bind::hello(&nonce), true) {
                Ok(()) | Err(SendError::Full) => {}
                Err(e) => {
                    s.backend.close(steam);
                    tracing::debug!(steam, ?e, "steam hello failed");
                }
            }
            let now = Instant::now();
            if now >= deadline {
                s.state.lock().unwrap().pending.remove(&steam);
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
        while !stop.load(Ordering::Relaxed) {
            self.backend.poll(&mut buf);
            if buf.is_empty() {
                std::thread::sleep(self.cfg.idle_poll);
            }
            for ev in buf.drain(..) {
                match ev {
                    SteamEvent::Message { from, data } => self.on_message(from, data),
                    SteamEvent::SessionFailed { remote } => self.lost(remote),
                }
            }
            if last_gc.elapsed() >= Duration::from_secs(1) {
                last_gc = Instant::now();
                let ttl = self.cfg.handshake_timeout * 2;
                self.state.lock().unwrap().pending.retain(|_, p| p.since.elapsed() < ttl);
            }
        }
    }

    fn on_message(&self, from: SteamId, data: Vec<u8>) {
        match data.first() {
            Some(&DATA) => {
                let peer = self.state.lock().unwrap().by_steam.get(&from).copied();
                match peer {
                    Some(peer) => {
                        let mut data = data;
                        data.remove(0);
                        let _ = self.events.blocking_send(TransportEvent::Frame { peer, data });
                    }
                    None => tracing::trace!(from, "steam frame from unbound SteamID dropped"),
                }
            }
            Some(&HELLO) => {
                let Some(nonce) = bind::parse_hello(&data) else { return };
                // Learn who they are too, unless we already know or are asking.
                let ours = {
                    let mut st = self.state.lock().unwrap();
                    if st.by_steam.contains_key(&from) {
                        None
                    } else if let Some(p) = st.pending.get(&from) {
                        Some(p.nonce)
                    } else if st.pending.len() < self.cfg.max_pending {
                        let n = bind::new_nonce();
                        st.pending.insert(from, Pending { nonce: n, expect: None, since: Instant::now() });
                        Some(n)
                    } else {
                        None
                    }
                };
                if let Some(n) = ours {
                    let _ = self.backend.send(from, &bind::hello(&n), true);
                }
                let _ = self.backend.send(from, &bind::proof(&self.key, self.my_steam, from, &nonce), true);
            }
            Some(&PROOF) => {
                let mut st = self.state.lock().unwrap();
                let Some(p) = st.pending.get(&from) else { return };
                let Some(peer) = bind::verify_proof(&data, from, self.my_steam, &p.nonce) else {
                    tracing::debug!(from, "steam proof rejected");
                    return;
                };
                if p.expect.is_some_and(|e| e != peer) || peer == self.me {
                    tracing::debug!(from, %peer, "steam proof for an unexpected peer rejected");
                    return;
                }
                st.pending.remove(&from);
                if let Some(old) = st.by_peer.insert(peer, from)
                    && old != from
                {
                    st.by_steam.remove(&old);
                }
                if let Some(old) = st.by_steam.insert(from, peer)
                    && old != peer
                {
                    st.by_peer.remove(&old);
                }
                drop(st);
                tracing::debug!(from, %peer, "steam binding up");
                self.bound.notify_waiters();
            }
            _ => {}
        }
    }

    /// The Steam session to `steam` is gone: unbind and report the path down.
    fn lost(&self, steam: SteamId) {
        let peer = {
            let mut st = self.state.lock().unwrap();
            let peer = st.by_steam.remove(&steam);
            if let Some(p) = peer {
                st.by_peer.remove(&p);
            }
            peer
        };
        self.backend.close(steam);
        if let Some(peer) = peer {
            let _ = self.events.try_send(TransportEvent::Down { peer });
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

    fn connect(&self, peer: PeerId, _: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            if self.bound_steam_id(peer).is_some() {
                return Ok(());
            }
            let steam = self
                .shared
                .dir
                .lookup(peer)
                .await
                .ok_or_else(|| anyhow::anyhow!("no SteamID known for {peer}"))?;
            self.connect_steam(steam, Some(peer)).await.map(|_| ())
        }
        .boxed()
    }

    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        let s = &self.shared;
        let steam = s.state.lock().unwrap().by_peer.get(&peer).copied().ok_or(TransportError::Closed)?;
        if frame.len() > MAX_FRAME {
            return Err(TransportError::Backlog);
        }
        let mut m = Vec::with_capacity(frame.len() + 1);
        m.push(DATA);
        m.extend_from_slice(&frame);
        match s.backend.send(steam, &m, reliable) {
            Ok(()) => Ok(()),
            Err(SendError::Full) if reliable => Err(TransportError::Backlog),
            Err(SendError::Full) => Ok(()),
            Err(e) => {
                tracing::debug!(steam, ?e, "steam send failed; path down");
                s.lost(steam);
                Err(TransportError::Closed)
            }
        }
    }

    /// Keeps the binding: the peer may still be sending to us over Steam,
    /// and idle Steam sessions time out by themselves.
    fn disconnect(&self, _: PeerId) {}

    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.rx.lock().unwrap().take()
    }
}
