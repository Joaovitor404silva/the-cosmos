//! Transport abstraction under the channel layer.
//!
//! A transport moves opaque frames between peers. Reliable frames must arrive
//! in order while the path lives; unreliable frames may be dropped. Sequence
//! numbers, ordering across paths and membership live above it, so a Steam
//! relay path (M3) or a path switch (M2) plugs in here without touching
//! sessions or channels.

use cosmos_net::{Multiaddr, Node, P2pStream, PeerId};
use futures::future::BoxFuture;
use futures::{AsyncReadExt, AsyncWriteExt, FutureExt, StreamExt};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum TransportEvent {
    Frame { peer: PeerId, data: Vec<u8> },
    /// The path to `peer` is gone.
    Down { peer: PeerId },
    /// Multi-path only: traffic to `peer` moved from path `from` to `to`.
    PathSwitch { peer: PeerId, from: String, to: String },
    /// Multi-path only: `peer` left too much reliable data unacknowledged
    /// and was dropped.
    Overflow { peer: PeerId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Too much queued for this peer.
    Backlog,
    /// No path to this peer.
    Closed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Backlog => f.write_str("send backlog full"),
            TransportError::Closed => f.write_str("no path to peer"),
        }
    }
}

impl std::error::Error for TransportError {}

pub trait Transport: Send + Sync + 'static {
    fn local_peer(&self) -> PeerId;
    /// Addresses other members can use to reach us (may be empty).
    fn local_addrs(&self) -> BoxFuture<'_, Vec<Multiaddr>>;
    /// Make sure a path to `peer` exists; `addrs` are hints.
    fn connect(&self, peer: PeerId, addrs: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>>;
    /// Queue one frame. Never blocks.
    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError>;
    /// Flush what is queued for `peer`, then release the path.
    fn disconnect(&self, peer: PeerId);
    /// Inbound frames and path loss. Can be taken once.
    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>>;
}

const EVENT_QUEUE: usize = 1024;

/// In-memory network for tests and for the M2 relay test double.
#[derive(Default)]
pub struct MemNet {
    inner: Mutex<MemInner>,
}

#[derive(Default)]
struct MemInner {
    peers: HashMap<PeerId, mpsc::Sender<TransportEvent>>,
    loss_pct: u64,
    rng: u64,
    cut: bool,
}

impl MemInner {
    fn roll(&mut self) -> u64 {
        // xorshift64; deterministic loss pattern per network.
        let mut x = self.rng.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x % 100
    }
}

impl MemNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Drop this share of unreliable frames (0..=100).
    pub fn set_unreliable_loss(&self, pct: u64) {
        let mut i = self.inner.lock().unwrap();
        i.loss_pct = pct.min(100);
        i.rng = 0x9e37_79b9_7f4a_7c15;
    }

    pub fn transport(self: &Arc<Self>) -> Arc<MemTransport> {
        self.transport_as(PeerId::random())
    }

    /// A transport with a given identity, so one peer can sit on several
    /// networks (e.g. a "direct" and a "relay" `MemNet`).
    pub fn transport_as(self: &Arc<Self>, me: PeerId) -> Arc<MemTransport> {
        let (tx, rx) = mpsc::channel(1 << 16);
        self.inner.lock().unwrap().peers.insert(me, tx);
        Arc::new(MemTransport {
            net: self.clone(),
            me,
            rx: Mutex::new(Some(rx)),
        })
    }

    /// Take the whole network down: frames in flight are lost silently,
    /// connects fail, and every peer sees every path go down.
    pub fn cut(&self) {
        let mut i = self.inner.lock().unwrap();
        i.cut = true;
        let ids: Vec<PeerId> = i.peers.keys().copied().collect();
        for (me, tx) in &i.peers {
            for peer in ids.iter().filter(|p| *p != me) {
                let _ = tx.try_send(TransportEvent::Down { peer: *peer });
            }
        }
    }

    /// Bring a `cut` network back.
    pub fn restore(&self) {
        self.inner.lock().unwrap().cut = false;
    }

    /// Simulate a crash: `peer` vanishes and everyone sees its path go down.
    pub fn kill(&self, peer: PeerId) {
        let mut i = self.inner.lock().unwrap();
        i.peers.remove(&peer);
        for tx in i.peers.values() {
            let _ = tx.try_send(TransportEvent::Down { peer });
        }
    }
}

pub struct MemTransport {
    net: Arc<MemNet>,
    me: PeerId,
    rx: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
}

impl Transport for MemTransport {
    fn local_peer(&self) -> PeerId {
        self.me
    }

    fn local_addrs(&self) -> BoxFuture<'_, Vec<Multiaddr>> {
        async { vec![] }.boxed()
    }

    fn connect(&self, peer: PeerId, _: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>> {
        let ok = {
            let i = self.net.inner.lock().unwrap();
            !i.cut && i.peers.contains_key(&peer)
        };
        async move {
            anyhow::ensure!(ok, "no path to {peer}");
            Ok(())
        }
        .boxed()
    }

    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        let mut i = self.net.inner.lock().unwrap();
        if !i.peers.contains_key(&self.me) {
            return Err(TransportError::Closed);
        }
        if i.cut {
            return Ok(());
        }
        if !reliable && i.loss_pct > 0 && i.roll() < i.loss_pct {
            return Ok(());
        }
        let tx = i.peers.get(&peer).ok_or(TransportError::Closed)?;
        match tx.try_send(TransportEvent::Frame { peer: self.me, data: frame }) {
            Ok(()) => Ok(()),
            Err(_) if !reliable => Ok(()),
            Err(_) => Err(TransportError::Backlog),
        }
    }

    fn disconnect(&self, _: PeerId) {}

    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.rx.lock().unwrap().take()
    }
}

/// Largest frame a transport carries: the biggest channel payload plus
/// channel and path headers. Fixed, so peers never disagree on it.
pub const FRAME_MAX: usize = crate::channel::CAP_MAX + 64;

/// Bytes queued per peer before reliable sends fail with `Backlog`.
const RELIABLE_QUEUE: usize = 8 << 20;
/// Bytes queued per peer before unreliable frames are dropped.
const UNRELIABLE_QUEUE: usize = 256 << 10;
/// Concurrent inbound sync streams per peer; more are refused.
const STREAMS_PER_PEER: usize = 4;

struct Writer {
    id: u64,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

struct NetShared {
    node: Node,
    writers: Mutex<HashMap<PeerId, Writer>>,
    readers: Mutex<HashMap<PeerId, usize>>,
    next_id: AtomicUsize,
    events: mpsc::Sender<TransportEvent>,
    max_frame: usize,
}

/// Direct / hole-punched libp2p path: one `/cosmos/sync` stream per direction.
pub struct NetTransport {
    shared: Arc<NetShared>,
    rx: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for NetTransport {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl NetTransport {
    /// Takes the node's inbound sync streams; one transport per node.
    pub fn new(node: Node) -> anyhow::Result<Arc<Self>> {
        let mut inbound = node
            .sync_streams()
            .ok_or_else(|| anyhow::anyhow!("sync streams already taken"))?;
        let (events, rx) = mpsc::channel(EVENT_QUEUE);
        let shared = Arc::new(NetShared {
            node: node.clone(),
            writers: Mutex::new(HashMap::new()),
            readers: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            events,
            max_frame: FRAME_MAX,
        });
        let s = shared.clone();
        let accept = tokio::spawn(async move {
            while let Some((peer, stream)) = inbound.recv().await {
                s.clone().read(peer, stream);
            }
        });
        let s = shared.clone();
        let mut node_events = Box::pin(node.events());
        let watch = tokio::spawn(async move {
            while let Some(ev) = node_events.next().await {
                if let cosmos_net::Event::Disconnected { peer } = ev {
                    s.writers.lock().unwrap().remove(&peer);
                    if s.events.send(TransportEvent::Down { peer }).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Arc::new(NetTransport {
            shared,
            rx: Mutex::new(Some(rx)),
            tasks: vec![accept, watch],
        }))
    }
}

impl NetShared {
    fn read(self: Arc<Self>, peer: PeerId, mut stream: P2pStream) {
        {
            let mut r = self.readers.lock().unwrap();
            let n = r.entry(peer).or_default();
            if *n >= STREAMS_PER_PEER {
                tracing::debug!(%peer, "sync stream refused: too many");
                return;
            }
            *n += 1;
        }
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).await.is_err() {
                    break;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > self.max_frame {
                    tracing::debug!(%peer, n, "sync frame over cap; closing stream");
                    break;
                }
                let mut data = vec![0u8; n];
                if stream.read_exact(&mut data).await.is_err() {
                    break;
                }
                if self.events.send(TransportEvent::Frame { peer, data }).await.is_err() {
                    break;
                }
            }
            let mut r = self.readers.lock().unwrap();
            if let Some(n) = r.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    r.remove(&peer);
                }
            }
        });
    }

    fn writer(self: &Arc<Self>, peer: PeerId) -> (mpsc::UnboundedSender<Vec<u8>>, Arc<AtomicUsize>) {
        let mut w = self.writers.lock().unwrap();
        if let Some(x) = w.get(&peer)
            && !x.tx.is_closed()
        {
            return (x.tx.clone(), x.queued.clone());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        w.insert(peer, Writer { id, tx: tx.clone(), queued: queued.clone() });
        tokio::spawn(self.clone().write(peer, id, rx, queued.clone()));
        (tx, queued)
    }

    async fn write(
        self: Arc<Self>,
        peer: PeerId,
        id: u64,
        mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
        queued: Arc<AtomicUsize>,
    ) {
        let r: anyhow::Result<()> = async {
            let mut s = self.node.open_sync_stream(peer).await?;
            let mut buf = Vec::new();
            while let Some(f) = rx.recv().await {
                buf.clear();
                let mut push = |f: Vec<u8>| {
                    queued.fetch_sub(f.len(), Ordering::Relaxed);
                    buf.extend_from_slice(&(f.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&f);
                };
                push(f);
                while let Ok(f) = rx.try_recv() {
                    push(f);
                }
                s.write_all(&buf).await?;
                s.flush().await?;
            }
            let _ = s.close().await;
            Ok(())
        }
        .await;
        if let Err(e) = r {
            tracing::debug!(%peer, "sync writer ended: {e:#}");
        }
        let mut w = self.writers.lock().unwrap();
        if w.get(&peer).is_some_and(|x| x.id == id) {
            w.remove(&peer);
        }
    }
}

impl Transport for NetTransport {
    fn local_peer(&self) -> PeerId {
        self.shared.node.peer_id()
    }

    fn local_addrs(&self) -> BoxFuture<'_, Vec<Multiaddr>> {
        self.shared.node.listen_addrs().boxed()
    }

    fn connect(&self, peer: PeerId, addrs: Vec<Multiaddr>) -> BoxFuture<'_, anyhow::Result<()>> {
        async move {
            let node = &self.shared.node;
            if node.connections(peer).await.is_empty() {
                for a in addrs {
                    let _ = node.dial(a).await;
                }
            }
            node.connect(peer).await?;
            self.shared.writer(peer);
            Ok(())
        }
        .boxed()
    }

    fn send(&self, peer: PeerId, frame: Vec<u8>, reliable: bool) -> Result<(), TransportError> {
        if frame.len() > self.shared.max_frame {
            return Err(TransportError::Backlog);
        }
        let (tx, queued) = self.shared.writer(peer);
        let cap = if reliable { RELIABLE_QUEUE } else { UNRELIABLE_QUEUE };
        let now = queued.load(Ordering::Relaxed);
        if now + frame.len() > cap {
            return if reliable { Err(TransportError::Backlog) } else { Ok(()) };
        }
        queued.fetch_add(frame.len(), Ordering::Relaxed);
        let n = frame.len();
        tx.send(frame).map_err(|_| {
            queued.fetch_sub(n, Ordering::Relaxed);
            TransportError::Closed
        })
    }

    fn disconnect(&self, peer: PeerId) {
        self.shared.writers.lock().unwrap().remove(&peer);
    }

    fn take_events(&self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.rx.lock().unwrap().take()
    }
}
