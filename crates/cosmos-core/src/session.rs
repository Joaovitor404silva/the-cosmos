//! Sessions: a host and up to three members in a full mesh.
//!
//! The host is the membership authority. A joiner sends `Join` to the host,
//! gets `Welcome` with the current members, connects to every one of them,
//! then sends `Ready`; only then does the host announce it with `Joined`.

use crate::channel::{self, CTRL_CAP, Channel, ChannelCaps, Delivery, Lane, Lanes, encode};
use crate::transport::{Transport, TransportError, TransportEvent};
use cosmos_net::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Hard cap from the spec: host + 3.
pub const MAX_PEERS: usize = 4;

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Total peers including the host; clamped to `MAX_PEERS`.
    pub max_peers: usize,
    pub caps: ChannelCaps,
    pub join_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_peers: MAX_PEERS,
            caps: ChannelCaps::default(),
            join_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Joined(PeerId),
    Left(PeerId),
    Message {
        from: PeerId,
        channel: Channel,
        delivery: Delivery,
        data: Vec<u8>,
    },
    /// The host left or vanished; the session is over.
    Ended,
    /// Traffic to `peer` moved to another path (e.g. "relay" -> "direct").
    PathSwitch { peer: PeerId, from: String, to: String },
    /// `peer` left too much reliable data unacknowledged and was dropped;
    /// `Left` (or `Ended` for the host) follows.
    Overflow(PeerId),
}

#[derive(Debug)]
pub enum JoinError {
    /// The session already has `max_peers` peers.
    Full,
    Timeout,
    NoPath(anyhow::Error),
    Transport(String),
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::Full => f.write_str("session is full"),
            JoinError::Timeout => f.write_str("join timed out"),
            JoinError::NoPath(e) => write!(f, "no path: {e:#}"),
            JoinError::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for JoinError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    NotMember,
    TooLarge { size: usize, cap: usize },
    Backlog,
    Ended,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::NotMember => f.write_str("peer is not a session member"),
            SendError::TooLarge { size, cap } => write!(f, "message of {size} bytes over channel cap {cap}"),
            SendError::Backlog => f.write_str("send backlog full"),
            SendError::Ended => f.write_str("session ended"),
        }
    }
}

impl std::error::Error for SendError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub rejected_full: u64,
    pub dropped_oversize: u64,
    pub dropped_malformed: u64,
    pub dropped_stranger: u64,
}

/// Frames buffered from a peer the host has not announced yet.
const STRANGER_PEERS: usize = 8;
const STRANGER_BYTES: usize = 256 << 10;
const EVENT_QUEUE: usize = 4096;
const MAX_ADDRS: usize = 16;
const TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ctrl {
    Join { addrs: Vec<Multiaddr> },
    Welcome { members: Vec<(PeerId, Vec<Multiaddr>)> },
    Reject,
    Ready,
    Joined { peer: PeerId, addrs: Vec<Multiaddr> },
    Left { peer: PeerId },
    Leave,
}

struct W(Vec<u8>);

impl W {
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u16).to_be_bytes());
        self.0.extend_from_slice(b);
    }
    fn peer(&mut self, p: &PeerId) {
        self.bytes(&p.to_bytes());
    }
    fn addrs(&mut self, a: &[Multiaddr]) {
        let a = &a[..a.len().min(MAX_ADDRS)];
        self.0.push(a.len() as u8);
        for x in a {
            self.bytes(&x.to_vec());
        }
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (self.0.len() >= n).then(|| {
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            a
        })
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
        self.take(n)
    }
    fn peer(&mut self) -> Option<PeerId> {
        PeerId::from_bytes(self.bytes()?).ok()
    }
    fn addrs(&mut self) -> Option<Vec<Multiaddr>> {
        let n = self.u8()? as usize;
        if n > MAX_ADDRS {
            return None;
        }
        (0..n).map(|_| Multiaddr::try_from(self.bytes()?.to_vec()).ok()).collect()
    }
}

impl Ctrl {
    fn encode(&self) -> Vec<u8> {
        let mut w = W(vec![]);
        match self {
            Ctrl::Join { addrs } => {
                w.0.push(1);
                w.addrs(addrs);
            }
            Ctrl::Welcome { members } => {
                w.0.push(2);
                w.0.push(members.len() as u8);
                for (p, a) in members {
                    w.peer(p);
                    w.addrs(a);
                }
            }
            Ctrl::Reject => w.0.push(3),
            Ctrl::Ready => w.0.push(4),
            Ctrl::Joined { peer, addrs } => {
                w.0.push(5);
                w.peer(peer);
                w.addrs(addrs);
            }
            Ctrl::Left { peer } => {
                w.0.push(6);
                w.peer(peer);
            }
            Ctrl::Leave => w.0.push(7),
        }
        w.0
    }

    fn decode(b: &[u8]) -> Option<Ctrl> {
        let mut r = R(b);
        let c = match r.u8()? {
            1 => Ctrl::Join { addrs: r.addrs()? },
            2 => {
                let n = r.u8()? as usize;
                if n >= MAX_PEERS {
                    return None;
                }
                let members = (0..n).map(|_| Some((r.peer()?, r.addrs()?))).collect::<Option<_>>()?;
                Ctrl::Welcome { members }
            }
            3 => Ctrl::Reject,
            4 => Ctrl::Ready,
            5 => Ctrl::Joined { peer: r.peer()?, addrs: r.addrs()? },
            6 => Ctrl::Left { peer: r.peer()? },
            7 => Ctrl::Leave,
            _ => return None,
        };
        r.0.is_empty().then_some(c)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Host,
    Joining,
    Member,
    Ended,
}

struct Stranger {
    bytes: usize,
    frames: Vec<Vec<u8>>,
    since: Instant,
}

enum Action {
    Emit(SessionEvent),
    Connect(PeerId, Vec<Multiaddr>),
    Mesh(Vec<(PeerId, Vec<Multiaddr>)>),
    JoinDone(Result<(), JoinError>),
}

enum Internal {
    MeshDone(Result<(), anyhow::Error>),
}

struct Inner {
    transport: Arc<dyn Transport>,
    me: PeerId,
    host: PeerId,
    role: Role,
    cfg: SessionConfig,
    my_addrs: Vec<Multiaddr>,
    /// Other members, ready to talk. For a member this includes the host.
    members: HashMap<PeerId, Vec<Multiaddr>>,
    /// Host only: welcomed, waiting for `Ready`.
    pending: HashMap<PeerId, (Vec<Multiaddr>, Instant)>,
    /// Sequence state; present exactly for peers we exchange frames with.
    lanes: HashMap<PeerId, Lanes>,
    strangers: HashMap<PeerId, Stranger>,
    stats: SessionStats,
    out: Vec<Action>,
}

impl Inner {
    fn emit(&mut self, e: SessionEvent) {
        self.out.push(Action::Emit(e));
    }

    fn send_ctrl(&mut self, peer: PeerId, c: &Ctrl) {
        let seq = self.lanes.entry(peer).or_default().next_seq(Lane::Ctrl);
        if let Err(e) = self.transport.send(peer, encode(Lane::Ctrl, seq, &c.encode()), true) {
            tracing::debug!(%peer, "ctrl send failed: {e}");
        }
    }

    /// Everyone the host keeps informed: members and welcomed joiners.
    fn audience(&self) -> Vec<PeerId> {
        self.members.keys().chain(self.pending.keys()).copied().collect()
    }

    fn send(&mut self, to: PeerId, channel: Channel, data: &[u8], d: Delivery) -> Result<(), SendError> {
        if self.role == Role::Ended {
            return Err(SendError::Ended);
        }
        if !self.members.contains_key(&to) {
            return Err(SendError::NotMember);
        }
        let cap = self.cfg.caps.cap(channel);
        if data.len() > cap {
            return Err(SendError::TooLarge { size: data.len(), cap });
        }
        let lane = Lane::Data(channel, d);
        let seq = self.lanes.entry(to).or_default().next_seq(lane);
        self.transport
            .send(to, encode(lane, seq, data), d == Delivery::Reliable)
            .map_err(|e| match e {
                TransportError::Backlog => SendError::Backlog,
                TransportError::Closed => SendError::NotMember,
            })
    }

    fn on_transport(&mut self, ev: TransportEvent) {
        match ev {
            TransportEvent::Frame { peer, data } => self.on_frame(peer, data),
            TransportEvent::Down { peer } => self.drop_peer(peer),
            TransportEvent::PathSwitch { peer, from, to } => {
                if self.members.contains_key(&peer) {
                    self.emit(SessionEvent::PathSwitch { peer, from, to });
                }
            }
            TransportEvent::Overflow { peer } => {
                if self.members.contains_key(&peer) {
                    self.emit(SessionEvent::Overflow(peer));
                }
                self.drop_peer(peer);
            }
        }
    }

    fn on_frame(&mut self, peer: PeerId, data: Vec<u8>) {
        let Some((lane, seq, payload)) = channel::decode(&data) else {
            self.stats.dropped_malformed += 1;
            return;
        };
        if !self.lanes.contains_key(&peer) {
            return self.on_stranger(peer, lane, seq, data);
        }
        let cap = match lane {
            Lane::Ctrl => CTRL_CAP,
            Lane::Data(c, _) => self.cfg.caps.cap(c),
        };
        let payload = if payload.len() > cap {
            self.stats.dropped_oversize += 1;
            None
        } else {
            Some(payload.to_vec())
        };
        let ready = self.lanes.get_mut(&peer).unwrap().accept(lane, seq, payload);
        for p in ready {
            match lane {
                Lane::Ctrl => match Ctrl::decode(&p) {
                    Some(c) => self.on_ctrl(peer, c),
                    None => self.stats.dropped_malformed += 1,
                },
                Lane::Data(channel, delivery) => {
                    if self.members.contains_key(&peer) {
                        self.emit(SessionEvent::Message { from: peer, channel, delivery, data: p });
                    }
                }
            }
        }
    }

    fn on_stranger(&mut self, peer: PeerId, lane: Lane, seq: u64, data: Vec<u8>) {
        match self.role {
            Role::Host if lane == Lane::Ctrl && seq == 0 => {
                match channel::decode(&data).and_then(|(_, _, p)| Ctrl::decode(p)) {
                    Some(Ctrl::Join { addrs }) => self.on_join(peer, addrs),
                    _ => self.stats.dropped_stranger += 1,
                }
            }
            // A member may hear from a newcomer before the host's `Joined`.
            Role::Member | Role::Joining => {
                if !self.strangers.contains_key(&peer) && self.strangers.len() >= STRANGER_PEERS {
                    self.stats.dropped_stranger += 1;
                    return;
                }
                let s = self.strangers.entry(peer).or_insert_with(|| Stranger {
                    bytes: 0,
                    frames: vec![],
                    since: Instant::now(),
                });
                if s.bytes + data.len() > STRANGER_BYTES {
                    self.stats.dropped_stranger += 1;
                    return;
                }
                s.bytes += data.len();
                s.frames.push(data);
            }
            _ => self.stats.dropped_stranger += 1,
        }
    }

    fn on_join(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        if 1 + self.members.len() + self.pending.len() >= self.cfg.max_peers.min(MAX_PEERS) {
            self.stats.rejected_full += 1;
            let seq = Lanes::default().next_seq(Lane::Ctrl);
            let _ = self.transport.send(peer, encode(Lane::Ctrl, seq, &Ctrl::Reject.encode()), true);
            self.transport.disconnect(peer);
            return;
        }
        let mut lanes = Lanes::default();
        lanes.accept(Lane::Ctrl, 0, None);
        self.lanes.insert(peer, lanes);
        self.pending.insert(peer, (addrs, Instant::now()));
        let mut members = vec![(self.me, self.my_addrs.clone())];
        members.extend(self.members.iter().map(|(p, a)| (*p, a.clone())));
        self.send_ctrl(peer, &Ctrl::Welcome { members });
    }

    fn on_ctrl(&mut self, from: PeerId, c: Ctrl) {
        let from_host = from == self.host;
        match (self.role, c) {
            (Role::Host, Ctrl::Ready) => {
                if let Some((addrs, _)) = self.pending.remove(&from) {
                    for p in self.audience() {
                        self.send_ctrl(p, &Ctrl::Joined { peer: from, addrs: addrs.clone() });
                    }
                    self.members.insert(from, addrs);
                    self.emit(SessionEvent::Joined(from));
                }
            }
            (Role::Joining, Ctrl::Welcome { members }) if from_host => {
                let members: Vec<_> = members.into_iter().filter(|(p, _)| *p != self.me).collect();
                for (p, a) in &members {
                    self.members.insert(*p, a.clone());
                    self.lanes.entry(*p).or_default();
                }
                let others = members.into_iter().filter(|(p, _)| *p != self.host).collect();
                self.out.push(Action::Mesh(others));
            }
            (Role::Joining, Ctrl::Reject) if from_host => {
                self.role = Role::Ended;
                self.out.push(Action::JoinDone(Err(JoinError::Full)));
            }
            (Role::Joining | Role::Member, Ctrl::Joined { peer, addrs }) if from_host => {
                if peer == self.me || self.members.contains_key(&peer) {
                    return;
                }
                self.members.insert(peer, addrs.clone());
                self.lanes.entry(peer).or_default();
                if self.role == Role::Member {
                    self.emit(SessionEvent::Joined(peer));
                }
                self.out.push(Action::Connect(peer, addrs));
                self.replay(peer);
            }
            (Role::Joining | Role::Member, Ctrl::Left { peer }) if from_host => self.drop_peer(peer),
            (_, Ctrl::Leave) => self.drop_peer(from),
            (role, c) => {
                tracing::debug!(%from, ?role, ?c, "unexpected ctrl");
                self.stats.dropped_malformed += 1;
            }
        }
    }

    /// Feed frames a peer sent before we knew it was a member.
    fn replay(&mut self, peer: PeerId) {
        if let Some(s) = self.strangers.remove(&peer) {
            for f in s.frames {
                self.on_frame(peer, f);
            }
        }
    }

    fn on_internal(&mut self, i: Internal) {
        let Internal::MeshDone(r) = i;
        if self.role != Role::Joining {
            return;
        }
        let host = self.host;
        match r {
            Ok(()) => {
                self.role = Role::Member;
                self.send_ctrl(host, &Ctrl::Ready);
                self.emit(SessionEvent::Joined(host));
                let others: Vec<_> = self.members.keys().filter(|p| **p != host).copied().collect();
                for p in others {
                    self.emit(SessionEvent::Joined(p));
                }
                self.out.push(Action::JoinDone(Ok(())));
            }
            Err(e) => {
                self.send_ctrl(host, &Ctrl::Leave);
                self.role = Role::Ended;
                self.out.push(Action::JoinDone(Err(JoinError::NoPath(e))));
            }
        }
    }

    fn drop_peer(&mut self, peer: PeerId) {
        self.strangers.remove(&peer);
        if self.role == Role::Host {
            if self.pending.remove(&peer).is_some() {
                self.lanes.remove(&peer);
            } else if self.members.remove(&peer).is_some() {
                self.lanes.remove(&peer);
                self.emit(SessionEvent::Left(peer));
                for p in self.audience() {
                    self.send_ctrl(p, &Ctrl::Left { peer });
                }
            }
            return;
        }
        if peer == self.host {
            match self.role {
                Role::Member => {
                    self.emit(SessionEvent::Left(peer));
                    self.emit(SessionEvent::Ended);
                }
                Role::Joining => self
                    .out
                    .push(Action::JoinDone(Err(JoinError::Transport("host went away".into())))),
                _ => {}
            }
            self.role = Role::Ended;
            self.members.clear();
            self.lanes.clear();
            return;
        }
        if self.members.remove(&peer).is_some() {
            self.lanes.remove(&peer);
            if self.role == Role::Member {
                self.emit(SessionEvent::Left(peer));
            }
        }
    }

    fn on_tick(&mut self) {
        let limit = self.cfg.join_timeout;
        let stale: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (_, t))| t.elapsed() > limit)
            .map(|(p, _)| *p)
            .collect();
        for p in stale {
            self.pending.remove(&p);
            self.lanes.remove(&p);
            self.transport.disconnect(p);
        }
        self.strangers.retain(|_, s| s.since.elapsed() <= limit);
    }

    fn leave(&mut self) {
        if self.role == Role::Ended {
            return;
        }
        let peers: Vec<_> = if self.role == Role::Host {
            self.audience()
        } else {
            self.members.keys().copied().collect()
        };
        for p in peers {
            self.send_ctrl(p, &Ctrl::Leave);
            self.transport.disconnect(p);
        }
        self.role = Role::Ended;
        self.members.clear();
        self.pending.clear();
    }
}

struct Shared {
    inner: Mutex<Inner>,
}

impl Shared {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap())
    }

    /// Run `f`, then hand back the side effects it queued.
    fn take(&self, f: impl FnOnce(&mut Inner)) -> Vec<Action> {
        self.with(|i| {
            f(i);
            std::mem::take(&mut i.out)
        })
    }
}

async fn run(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<TransportEvent>,
    events: mpsc::Sender<SessionEvent>,
    mut join_done: Option<oneshot::Sender<Result<(), JoinError>>>,
) {
    let (itx, mut irx) = mpsc::unbounded_channel();
    let transport = shared.with(|i| i.transport.clone());
    let mut tick = tokio::time::interval(TICK);
    loop {
        let actions = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => shared.take(|i| i.on_transport(ev)),
                None => return,
            },
            Some(i) = irx.recv() => shared.take(|inner| inner.on_internal(i)),
            _ = tick.tick() => shared.take(Inner::on_tick),
        };
        for a in actions {
            match a {
                Action::Emit(e) => {
                    if events.send(e).await.is_err() {
                        return;
                    }
                }
                Action::Connect(peer, addrs) => {
                    let t = transport.clone();
                    tokio::spawn(async move {
                        if let Err(e) = t.connect(peer, addrs).await {
                            tracing::debug!(%peer, "mesh connect failed: {e:#}");
                        }
                    });
                }
                Action::Mesh(peers) => {
                    let t = transport.clone();
                    let itx = itx.clone();
                    tokio::spawn(async move {
                        let r = futures::future::try_join_all(peers.into_iter().map(|(p, a)| t.connect(p, a)))
                            .await
                            .map(|_| ());
                        let _ = itx.send(Internal::MeshDone(r));
                    });
                }
                Action::JoinDone(r) => {
                    if let Some(tx) = join_done.take() {
                        let _ = tx.send(r);
                    }
                }
            }
        }
    }
}

pub struct Session {
    shared: Arc<Shared>,
    events: mpsc::Receiver<SessionEvent>,
    task: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    fn start(
        transport: Arc<dyn Transport>,
        cfg: SessionConfig,
        host: Option<PeerId>,
        my_addrs: Vec<Multiaddr>,
        join_done: Option<oneshot::Sender<Result<(), JoinError>>>,
    ) -> Result<Session, JoinError> {
        let rx = transport
            .take_events()
            .ok_or_else(|| JoinError::Transport("transport already used by a session".into()))?;
        let me = transport.local_peer();
        let mut inner = Inner {
            transport,
            me,
            host: host.unwrap_or(me),
            role: if host.is_some() { Role::Joining } else { Role::Host },
            cfg,
            my_addrs: my_addrs.clone(),
            members: HashMap::new(),
            pending: HashMap::new(),
            lanes: HashMap::new(),
            strangers: HashMap::new(),
            stats: SessionStats::default(),
            out: vec![],
        };
        if let Some(h) = host {
            inner.send_ctrl(h, &Ctrl::Join { addrs: my_addrs });
        }
        let shared = Arc::new(Shared { inner: Mutex::new(inner) });
        let (etx, events) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(run(shared.clone(), rx, etx, join_done));
        Ok(Session { shared, events, task })
    }

    /// Host a new session on `transport` (one session per transport).
    pub async fn host(transport: Arc<dyn Transport>, cfg: SessionConfig) -> Result<Session, JoinError> {
        let addrs = transport.local_addrs().await;
        Self::start(transport, cfg, None, addrs, None)
    }

    /// Join the session hosted by `host`; returns once connected to every
    /// member. A full session fails with `JoinError::Full`.
    pub async fn join(
        transport: Arc<dyn Transport>,
        cfg: SessionConfig,
        host: PeerId,
        host_addrs: Vec<Multiaddr>,
    ) -> Result<Session, JoinError> {
        let limit = cfg.join_timeout;
        let r = tokio::time::timeout(limit, async {
            transport.connect(host, host_addrs).await.map_err(JoinError::NoPath)?;
            let addrs = transport.local_addrs().await;
            let (tx, rx) = oneshot::channel();
            let s = Self::start(transport, cfg, Some(host), addrs, Some(tx))?;
            match rx.await {
                Ok(Ok(())) => Ok(s),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(JoinError::Transport("session task ended".into())),
            }
        })
        .await;
        r.unwrap_or(Err(JoinError::Timeout))
    }

    pub fn me(&self) -> PeerId {
        self.shared.with(|i| i.me)
    }

    pub fn host_peer(&self) -> PeerId {
        self.shared.with(|i| i.host)
    }

    pub fn is_host(&self) -> bool {
        self.shared.with(|i| i.role == Role::Host)
    }

    /// Other members currently in the session.
    pub fn members(&self) -> Vec<PeerId> {
        self.shared.with(|i| i.members.keys().copied().collect())
    }

    pub fn stats(&self) -> SessionStats {
        self.shared.with(|i| i.stats.clone())
    }

    pub fn send(&self, to: PeerId, channel: Channel, data: &[u8], delivery: Delivery) -> Result<(), SendError> {
        self.shared.with(|i| i.send(to, channel, data, delivery))
    }

    /// Send to every member; stops at the first error.
    pub fn broadcast(&self, channel: Channel, data: &[u8], delivery: Delivery) -> Result<(), SendError> {
        self.shared.with(|i| {
            let to: Vec<_> = i.members.keys().copied().collect();
            to.into_iter().try_for_each(|p| i.send(p, channel, data, delivery))
        })
    }

    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }

    pub fn try_event(&mut self) -> Option<SessionEvent> {
        self.events.try_recv().ok()
    }

    /// Tell everyone we are leaving, flush, and end the session.
    pub fn leave(self) {
        self.shared.with(Inner::leave);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{MemNet, MemTransport};
    use std::collections::HashSet;
    use tokio::time::timeout;

    const T: Duration = Duration::from_secs(5);

    async fn ev(s: &mut Session) -> SessionEvent {
        timeout(T, s.next_event()).await.expect("event timeout").expect("session closed")
    }

    async fn joined_set(s: &mut Session, n: usize) -> HashSet<PeerId> {
        let mut out = HashSet::new();
        while out.len() < n {
            match ev(s).await {
                SessionEvent::Joined(p) => {
                    out.insert(p);
                }
                e => panic!("unexpected {e:?}"),
            }
        }
        out
    }

    async fn join(net: &Arc<MemNet>, host: &Session) -> (Session, Arc<MemTransport>) {
        let t = net.transport();
        let s = Session::join(t.clone(), SessionConfig::default(), host.me(), vec![])
            .await
            .expect("join");
        (s, t)
    }

    /// Host + 3 members, all membership events drained.
    async fn full(net: &Arc<MemNet>) -> (Session, Vec<(Session, Arc<MemTransport>)>) {
        let mut host = Session::host(net.transport(), SessionConfig::default()).await.unwrap();
        let mut ms = vec![];
        for _ in 0..3 {
            ms.push(join(net, &host).await);
        }
        joined_set(&mut host, 3).await;
        for (m, _) in ms.iter_mut() {
            joined_set(m, 3).await;
        }
        (host, ms)
    }

    #[tokio::test]
    async fn four_peers_see_each_other_fifth_is_rejected() {
        let net = MemNet::new();
        let (mut host, mut ms) = full(&net).await;
        let all: HashSet<PeerId> =
            ms.iter().map(|(m, _)| m.me()).chain([host.me()]).collect();
        for (m, _) in &ms {
            let mut want = all.clone();
            want.remove(&m.me());
            assert_eq!(m.members().into_iter().collect::<HashSet<_>>(), want);
            assert_eq!(m.host_peer(), host.me());
        }
        assert_eq!(host.members().len(), 3);

        let fifth = Session::join(net.transport(), SessionConfig::default(), host.me(), vec![]).await;
        assert!(matches!(fifth, Err(JoinError::Full)), "5th peer joined");
        assert_eq!(host.stats().rejected_full, 1);
        assert_eq!(host.members().len(), 3);

        // A member leaving is announced to everyone; its slot frees up.
        let (gone, _) = ms.pop().unwrap();
        let gone_id = gone.me();
        gone.leave();
        assert_eq!(ev(&mut host).await, SessionEvent::Left(gone_id));
        for (m, _) in ms.iter_mut() {
            assert_eq!(ev(m).await, SessionEvent::Left(gone_id));
        }
        let (mut again, _) = join(&net, &host).await;
        joined_set(&mut again, 3).await;
        assert_eq!(ev(&mut host).await, SessionEvent::Joined(again.me()));
    }

    #[tokio::test]
    async fn host_crash_ends_session_for_members() {
        let net = MemNet::new();
        let (host, mut ms) = full(&net).await;
        net.kill(host.me());
        for (m, _) in ms.iter_mut() {
            assert_eq!(ev(m).await, SessionEvent::Left(host.me()));
            assert_eq!(ev(m).await, SessionEvent::Ended);
            assert_eq!(m.send(host.me(), 0, b"x", Delivery::Reliable), Err(SendError::Ended));
        }
    }

    #[tokio::test]
    async fn members_talk_directly_in_order() {
        let net = MemNet::new();
        let (_host, mut ms) = full(&net).await;
        let (a, b) = (ms[0].0.me(), ms[1].0.me());
        for i in 0..1000u32 {
            ms[0].0.send(b, 1, &i.to_be_bytes(), Delivery::Reliable).unwrap();
        }
        for i in 0..1000u32 {
            let e = ev(&mut ms[1].0).await;
            assert_eq!(
                e,
                SessionEvent::Message { from: a, channel: 1, delivery: Delivery::Reliable, data: i.to_be_bytes().to_vec() }
            );
        }
    }

    #[tokio::test]
    async fn unreliable_survives_loss_reliable_does_not_lose() {
        let net = MemNet::new();
        let (mut host, ms) = full(&net).await;
        net.set_unreliable_loss(30);
        let a = &ms[0].0;
        for i in 0..500u32 {
            a.send(host.me(), 2, &i.to_be_bytes(), Delivery::Unreliable).unwrap();
            a.send(host.me(), 1, &i.to_be_bytes(), Delivery::Reliable).unwrap();
        }
        let (mut rel, mut unrel) = (vec![], vec![]);
        while rel.len() < 500 {
            match ev(&mut host).await {
                SessionEvent::Message { channel: 1, data, .. } => rel.push(u32::from_be_bytes(data.try_into().unwrap())),
                SessionEvent::Message { channel: 2, data, .. } => unrel.push(u32::from_be_bytes(data.try_into().unwrap())),
                e => panic!("unexpected {e:?}"),
            }
        }
        assert_eq!(rel, (0..500).collect::<Vec<_>>());
        assert!(unrel.len() > 250 && unrel.len() < 450, "loss not applied: {}", unrel.len());
        assert!(unrel.windows(2).all(|w| w[0] < w[1]), "unreliable out of order");
    }

    #[tokio::test]
    async fn oversize_is_refused_on_send_and_dropped_on_receive() {
        let net = MemNet::new();
        let cfg = SessionConfig { caps: ChannelCaps::default().with(4, 8), ..SessionConfig::default() };
        let mut host = Session::host(net.transport(), cfg.clone()).await.unwrap();
        let t = net.transport();
        let mut m = Session::join(t.clone(), cfg, host.me(), vec![]).await.unwrap();
        assert_eq!(ev(&mut host).await, SessionEvent::Joined(m.me()));
        assert_eq!(ev(&mut m).await, SessionEvent::Joined(host.me()));

        assert_eq!(
            m.send(host.me(), 4, &[0; 9], Delivery::Reliable),
            Err(SendError::TooLarge { size: 9, cap: 8 })
        );
        // A peer that ignores the cap: frame 0 is oversize, frame 1 is fine.
        let lane = Lane::Data(4, Delivery::Reliable);
        t.send(host.me(), encode(lane, 0, &[0; 9]), true).unwrap();
        t.send(host.me(), encode(lane, 1, &[1; 8]), true).unwrap();
        assert_eq!(
            ev(&mut host).await,
            SessionEvent::Message { from: m.me(), channel: 4, delivery: Delivery::Reliable, data: vec![1; 8] }
        );
        assert_eq!(host.stats().dropped_oversize, 1);
    }

    #[tokio::test]
    async fn strangers_cannot_inject_messages() {
        let net = MemNet::new();
        let (mut host, _ms) = full(&net).await;
        let outsider = net.transport();
        let _rx = outsider.take_events();
        outsider
            .send(host.me(), encode(Lane::Data(1, Delivery::Reliable), 0, b"spoof"), true)
            .unwrap();
        assert!(timeout(Duration::from_millis(300), host.next_event()).await.is_err());
        assert_eq!(host.stats().dropped_stranger, 1);
    }
}
