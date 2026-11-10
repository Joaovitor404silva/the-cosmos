mod discovery;
mod kadnet;
mod pipe;
mod portguess;
mod record;
mod rpc;
mod store;
mod tunnel;

pub use discovery::{ConnLimits, ipfs_bootstrap, parse_list, provider_key};
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
pub use portguess::Plan as PortGuessPlan;
pub use record::{CLOCK_SKEW, MAX_TTL, Record};
pub use rpc::{RpcLimits, RpcRequest, RpcStats};

use anyhow::anyhow;
use futures::{AsyncReadExt, AsyncWriteExt, Stream, StreamExt};
use libp2p::{
    StreamProtocol, Swarm, autonat, connection_limits, gossipsub, identify, kad, mdns,
    multiaddr::Protocol,
    noise, ping,
    swarm::{
        ConnectionId, NetworkBehaviour, SwarmEvent,
        behaviour::toggle::Toggle,
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, upnp, yamux,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;


#[derive(Clone, Debug)]
pub struct Config {
    pub keypair: Option<Keypair>,
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub mdns: bool,
    pub upnp: bool,
    pub hole_punch: bool,
    pub tunnel_target: Option<SocketAddr>,
    pub tunnel_allowlist: Option<HashSet<PeerId>>,
    pub tunnel_blocklist: HashSet<PeerId>,
    pub max_tunnels: usize,
    pub max_streams_per_peer: usize,
    pub tunnel_reconnect_window: Duration,
    pub record_ttl: Duration,
    pub ipfs: bool,
    pub ipfs_bootstrap: Vec<Multiaddr>,
    pub ipfs_topics: Vec<String>,
    pub ipfs_announce_lan: bool,
    pub ipfs_lookup_interval: Duration,
    pub bootstrap_url: Option<String>,
    pub bootstrap_url_after: Duration,
    pub peer_cache: Option<PathBuf>,
    pub limits: ConnLimits,
    pub rpc: RpcLimits,
    pub port_guess: bool,
    pub port_guess_plan: portguess::Plan,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keypair: None,
            listen: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                "/ip6/::/udp/0/quic-v1".parse().unwrap(),
                "/ip6/::/tcp/0".parse().unwrap(),
            ],
            bootstrap: vec![],
            mdns: true,
            upnp: true,
            hole_punch: true,
            tunnel_target: None,
            tunnel_allowlist: None,
            tunnel_blocklist: HashSet::new(),
            max_tunnels: 16,
            max_streams_per_peer: 4,
            tunnel_reconnect_window: Duration::from_secs(30),
            record_ttl: Duration::from_secs(300),
            ipfs: false,
            ipfs_bootstrap: discovery::ipfs_bootstrap(),
            ipfs_topics: vec![],
            ipfs_announce_lan: false,
            ipfs_lookup_interval: Duration::from_secs(15),
            bootstrap_url: None,
            bootstrap_url_after: Duration::from_secs(30),
            peer_cache: None,
            limits: ConnLimits::default(),
            rpc: RpcLimits::default(),
            port_guess: false,
            port_guess_plan: portguess::Plan::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Listening(Multiaddr),
    Connected {
        peer: PeerId,
        addr: Multiaddr,
    },
    Disconnected {
        peer: PeerId,
    },
    Reachability {
        public: bool,
    },
    TunnelAccepted {
        peer: PeerId,
        local: SocketAddr,
    },
    TunnelPath {
        peer: PeerId,
        local: SocketAddr,
        quic: bool,
    },
    TunnelClosed {
        peer: PeerId,
        local: SocketAddr,
        reason: String,
    },
    UpnpMapped {
        addr: Multiaddr,
    },
    UpnpUnavailable {
        reason: String,
    },
    IpfsReady {
        peers: usize,
        error: Option<String>,
    },
    IpfsAnnounce {
        addrs: Vec<Multiaddr>,
    },
    IpfsProvided {
        topic: String,
        ok: bool,
    },
    IpfsProviders {
        topic: String,
        providers: usize,
    },
    Discovered {
        peer: PeerId,
        via: &'static str,
    },
    DiscoveryDialFailed {
        peer: PeerId,
        via: &'static str,
        error: String,
    },
    FallbackList {
        addrs: usize,
        error: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    pub peer: PeerId,
    pub local: SocketAddr,
    pub streams: usize,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    ip_limit: discovery::IpLimit,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kad: kadnet::Kad,
    ipfs: Toggle<discovery::Announce>,
    gossipsub: gossipsub::Behaviour,
    autonat: autonat::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    upnp: Toggle<upnp::tokio::Behaviour>,
    pipe: pipe::Behaviour,
    rpc: pipe::Behaviour,
    rec: pipe::Behaviour,
}

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const FIND_DEADLINE: Duration = Duration::from_secs(20);
pub const MAX_FIND_PROVIDERS: usize = 32;
const GOOD_MAX: usize = 4096;
const REC_PROTO: StreamProtocol = StreamProtocol::new("/cosmos/rec/1.0.0");
const REC_MAX: usize = 320 << 10;
const REC_TOPIC_MAX: usize = 1024;
const REC_SERVE_MAX: usize = 16;
const DIRECT_FETCH: Duration = Duration::from_secs(5);
const PURGE_EVERY: Duration = Duration::from_secs(5);
const GOSSIP_SEEN_MAX: usize = 8192;
const GOSSIP_RATE_MAX: usize = 4096;
const GOSSIP_PER_PEER_TOPIC_PER_SEC: u16 = 20;
const IPFS_FOUND_MAX: usize = 256;
const SEEDS_MAX: usize = 512;
const OWN_MAX: usize = 1024;

type Reply<T> = oneshot::Sender<anyhow::Result<T>>;

enum Command {
    Publish {
        topic: String,
        bytes: Vec<u8>,
        reply: Reply<()>,
    },
    Find {
        topic: String,
        deadline: Duration,
        complete: bool,
        reply: Reply<(Vec<Record>, Vec<PeerId>)>,
    },
    Subscribe {
        topic: String,
    },
    Connect {
        peer: PeerId,
        reply: Reply<()>,
    },
    Dial {
        addr: Multiaddr,
        reply: Reply<()>,
    },
    Disconnect {
        peer: PeerId,
    },
    ListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    Connections {
        peer: PeerId,
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    AddExternal {
        addr: Multiaddr,
    },
    OpenTunnel {
        peer: PeerId,
        reply: Reply<SocketAddr>,
    },
    CloseTunnel {
        peer: PeerId,
    },
    Tunnels {
        reply: oneshot::Sender<Vec<TunnelInfo>>,
    },
    Allow {
        peer: PeerId,
        allow: bool,
    },
    OpenRpc {
        peer: PeerId,
        reply: Reply<libp2p::Stream>,
    },
    OpenRec {
        peer: PeerId,
        reply: Reply<libp2p::Stream>,
    },
    RpcOk {
        peer: PeerId,
    },
}

enum Inner {
    Opened {
        peer: PeerId,
        sid: u64,
        rank: u8,
        conn: ConnectionId,
        result: Result<libp2p::Stream, String>,
    },
    Accepted {
        peer: PeerId,
        sid: u64,
        rank: u8,
        conn: ConnectionId,
        stream: libp2p::Stream,
    },
    AcceptFailed {
        peer: PeerId,
    },
    Note(tunnel::Note),
    Fallback(Result<Vec<Multiaddr>, String>),
}

enum Pending {
    PutRecord {
        reply: Reply<()>,
    },
    Providers {
        find: u64,
        topic: String,
        found: HashSet<PeerId>,
    },
    GetRecord {
        find: u64,
        topic: String,
        publisher: PeerId,
    },
    Closest {
        peer: PeerId,
    },
}

struct FindState {
    left: usize,
    searching: bool,
    out: Vec<Record>,
    reply: Reply<(Vec<Record>, Vec<PeerId>)>,
    deadline: Instant,
    complete: bool,
    truncated: bool,
    missing: Vec<PeerId>,
    queries: Vec<kad::QueryId>,
}

struct Anchor {
    peer: PeerId,
    addr: Multiaddr,
    next: Instant,
    backoff: Duration,
}

struct Tun {
    local: SocketAddr,
    ctl: mpsc::UnboundedSender<tunnel::Ctl>,
    streams: HashMap<u64, (u8, ConnectionId)>,
    pending: usize,
    opening: Option<u64>,
    waiters: Vec<Reply<SocketAddr>>,
    retry_at: Instant,
    backoff: Duration,
    down_since: Instant,
    ever_up: bool,
    path: Option<u8>,
}
impl Tun {
    fn top(&self) -> Option<u8> {
        self.streams.values().map(|(r, _)| *r).max()
    }
}

#[derive(Clone)]
pub struct Node {
    peer_id: PeerId,
    keypair: Keypair,
    ttl: Duration,
    cmd: mpsc::UnboundedSender<Command>,
    events: broadcast::Sender<Event>,
    topics: Topics,
    own: Own,
    targets: tunnel::SharedTargets,
    rpc_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<RpcRequest>>>>,
    gate: Arc<rpc::Gate>,
    blocked: PeerSet,
    permanently_blocked: HashSet<PeerId>,
}

const KAD_PROTO: StreamProtocol = StreamProtocol::new("/cosmos/kad/1.0.0");
const ANCHOR_BACKOFF: Duration = Duration::from_millis(500);
const ANCHOR_BACKOFF_MAX: Duration = Duration::from_secs(30);
const TUNNEL_BACKOFF: Duration = Duration::from_millis(200);
const TUNNEL_BACKOFF_MAX: Duration = Duration::from_secs(4);
const PRUNE_GRACE: Duration = Duration::from_secs(1);
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

fn topic_key(topic: &str) -> kad::RecordKey {
    kad::RecordKey::new(&Sha256::digest(topic.as_bytes()).to_vec())
}

fn record_key(topic: &str, publisher: &PeerId) -> kad::RecordKey {
    let mut k = Sha256::digest(topic.as_bytes()).to_vec();
    k.extend_from_slice(&publisher.to_bytes());
    kad::RecordKey::new(&k)
}

fn split_peer(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut a = addr.clone();
    match a.pop()? {
        Protocol::P2p(p) => Some((p, a)),
        _ => None,
    }
}

fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

fn rank(addr: &Multiaddr) -> u8 {
    if is_quic(addr) { 3 } else { 2 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Loopback,
    Private,
    Public,
}

fn ip_scope(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v) => {
            if v.is_loopback() {
                Scope::Loopback
            } else if !global_ip4(&v) {
                Scope::Private
            } else {
                Scope::Public
            }
        }
        IpAddr::V6(v) => {
            if v.is_loopback() {
                Scope::Loopback
            } else if let Some(m) = v.to_ipv4_mapped() {
                ip_scope(IpAddr::V4(m))
            } else if global_ip6(&v) {
                Scope::Public
            } else {
                Scope::Private
            }
        }
    }
}

fn global_ip6(v: &Ipv6Addr) -> bool {
    let s = v.segments();
    !((s[0] & 0xe000) != 0x2000
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0x0002)
        || v.is_loopback()
        || v.is_unspecified()
        || v.is_multicast()
        || v.to_ipv4_mapped().is_some()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x2001 && ((s[1] & 0xfff0) == 0x0010 || (s[1] & 0xfff0) == 0x0020)))
}

fn record_store_allowed(key: &kad::RecordKey, me: PeerId, peers: &[PeerId]) -> bool {
    let key = kad::KBucketKey::new(key.clone());
    let local_distance = key.distance(&kad::KBucketKey::from(me));
    peers
        .iter()
        .filter(|peer| key.distance(&kad::KBucketKey::from(**peer)) < local_distance)
        .take(20)
        .count()
        < 20
}

fn global_ip4(v: &Ipv4Addr) -> bool {
    let o = v.octets();
    !(v.is_private()
        || v.is_link_local()
        || v.is_unspecified()
        || v.is_multicast()
        || v.is_broadcast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113))
}

fn is_ip6(a: &Multiaddr) -> bool {
    a.iter().any(|p| matches!(p, Protocol::Ip6(_)))
}

fn ip4_of(a: &Multiaddr) -> Option<Ipv4Addr> {
    a.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(ip),
        _ => None,
    })
}

fn global_ip4_from<'a>(addrs: impl IntoIterator<Item = &'a Multiaddr>) -> Option<Ipv4Addr> {
    addrs
        .into_iter()
        .filter_map(ip4_of)
        .find(|ip| global_ip4(ip))
}

fn addr_scope(a: &Multiaddr) -> Scope {
    for p in a.iter() {
        match p {
            Protocol::Ip4(ip) => return ip_scope(ip.into()),
            Protocol::Ip6(ip) => return ip_scope(ip.into()),
            _ => {}
        }
    }
    Scope::Public
}

fn kad_addr_allowed(addr: &Multiaddr, via: Option<&Multiaddr>, mdns_peer: bool) -> bool {
    let via = via.map(addr_scope);
    match addr_scope(addr) {
        Scope::Public => true,
        Scope::Loopback => via == Some(Scope::Loopback),
        Scope::Private => mdns_peer || matches!(via, Some(Scope::Private) | Some(Scope::Loopback)),
    }
}

fn identify_config(key: libp2p::identity::PublicKey) -> identify::Config {
    identify::Config::new("/cosmos/id/1.0.0".into(), key)
        .with_hide_listen_addrs(true)
        .with_push_listen_addr_updates(true)
        .with_interval(Duration::from_secs(30))
}

pub fn is_public_addr(addr: &Multiaddr) -> bool {
    addr_scope(addr) == Scope::Public
        && addr
            .iter()
            .any(|protocol| matches!(protocol, Protocol::Ip4(_) | Protocol::Ip6(_)))
        && !is_dns(addr)
}

type PeerSet = Arc<Mutex<HashSet<PeerId>>>;
type Topics = Arc<Mutex<HashMap<String, broadcast::Sender<Record>>>>;
type Own = Arc<Mutex<HashMap<String, Vec<u8>>>>;

fn build_swarm(cfg: &Config, keypair: Keypair, blocked: PeerSet) -> anyhow::Result<Swarm<Behaviour>> {
    let ttl = cfg.record_ttl;
    let dns_peers: HashSet<PeerId> = cfg
        .bootstrap
        .iter()
        .filter_map(|addr| split_peer(addr).map(|(peer, _)| peer))
        .collect();
    let cfg = cfg.clone();
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| {
            let id = key.public().to_peer_id();
            let mut kcfg = kad::Config::new(KAD_PROTO);
            kcfg.set_record_ttl(Some(ttl));
            kcfg.set_provider_record_ttl(Some(ttl));
            kcfg.set_publication_interval(None);
            kcfg.set_provider_publication_interval(Some(ttl / 2));
            kcfg.set_query_timeout(Duration::from_secs(20));
            kcfg.set_record_filtering(kad::StoreInserts::FilterBoth);
            let local_only = !cfg.listen.is_empty()
                && cfg
                    .listen
                    .iter()
                    .all(|addr| addr_scope(addr) == Scope::Loopback);
            let mut kad = kadnet::Kad::new(
                kad::Behaviour::with_config(id, store::Store::new(id, REC_MAX), kcfg),
                local_only,
                dns_peers.clone(),
            );
            kad.set_mode(Some(kad::Mode::Server));
            let gcfg = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gcfg,
            )?;
            let mdns = if cfg.mdns {
                Some(mdns::tokio::Behaviour::new(mdns::Config::default(), id)?)
            } else {
                None
            };
            let ipfs = cfg.ipfs.then(|| {
                let mut icfg = kad::Config::new(discovery::IPFS_KAD_PROTO);
                icfg.set_provider_record_ttl(Some(discovery::PROVIDER_TTL));
                icfg.set_provider_publication_interval(Some(discovery::PROVIDER_REPUBLISH));
                icfg.set_publication_interval(None);
                let mut k = kad::Behaviour::with_config(id, kad::store::MemoryStore::new(id), icfg);
                k.set_mode(Some(kad::Mode::Client));
                let dns_peers = cfg
                    .ipfs_bootstrap
                    .iter()
                    .filter_map(|addr| split_peer(addr).map(|(peer, _)| peer))
                    .collect();
                discovery::Announce::new(k, dns_peers)
            });
            Ok(Behaviour {
                limits: connection_limits::Behaviour::new(cfg.limits.libp2p()),
                ip_limit: discovery::IpLimit::new(cfg.limits.max_inbound_per_ip, blocked),
                ipfs: ipfs.into(),
                identify: identify::Behaviour::new(identify_config(key.public())),
                ping: ping::Behaviour::default(),
                kad,
                gossipsub,
                autonat: autonat::Behaviour::new(id, autonat::Config::default()),
                mdns: mdns.into(),
                upnp: cfg.upnp.then(upnp::tokio::Behaviour::default).into(),
                pipe: pipe::Behaviour::new(tunnel::PROTOCOL),
                rpc: pipe::Behaviour::new(rpc::PROTO),
                rec: pipe::Behaviour::new(REC_PROTO),
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();
    Ok(swarm)
}

impl Node {
    pub async fn start(cfg: Config) -> anyhow::Result<Node> {
        let keypair = cfg
            .keypair
            .clone()
            .unwrap_or_else(Keypair::generate_ed25519);
        let permanently_blocked = cfg.tunnel_blocklist.clone();
        let blocked: PeerSet = Arc::new(Mutex::new(permanently_blocked.clone()));
        let mut swarm = build_swarm(&cfg, keypair.clone(), blocked.clone())?;
        let peer_id = *swarm.local_peer_id();
        let mut waiting = HashSet::new();
        for a in &cfg.listen {
            match swarm.listen_on(a.clone()) {
                Ok(id) => {
                    waiting.insert(id);
                }
                Err(e) if is_ip6(a) => tracing::debug!("ipv6 listen on {a} unavailable: {e}"),
                Err(e) => return Err(e.into()),
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !waiting.is_empty() {
            match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
                Ok(SwarmEvent::NewListenAddr { listener_id, .. }) => {
                    waiting.remove(&listener_id);
                }
                Ok(SwarmEvent::ListenerClosed {
                    listener_id,
                    reason,
                    ..
                }) => {
                    tracing::debug!("listener closed during start: {reason:?}");
                    waiting.remove(&listener_id);
                }
                Ok(SwarmEvent::ListenerError { listener_id, error }) => {
                    tracing::debug!("listener error during start: {error}");
                    waiting.remove(&listener_id);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let now = Instant::now();
        let mut anchors = Vec::new();
        for a in cfg.bootstrap.iter() {
            if let Some((p, base)) = split_peer(a) {
                swarm.behaviour_mut().kad.add_address(&p, base);
                if !anchors.iter().any(|x: &Anchor| x.peer == p) {
                    anchors.push(Anchor {
                        peer: p,
                        addr: a.clone(),
                        next: now,
                        backoff: ANCHOR_BACKOFF,
                    });
                }
            } else {
                let _ = swarm.dial(a.clone());
            }
        }
        let _ = swarm.behaviour_mut().kad.bootstrap();

        let mut seeds = HashMap::new();
        let cache = cfg.peer_cache.clone().map(discovery::PeerCache::load);
        if let Some(c) = &cache {
            for (p, addrs) in c.entries() {
                if p == peer_id {
                    continue;
                }
                for a in &addrs {
                    swarm.behaviour_mut().kad.add_address(&p, a.clone());
                }
                seeds.insert(p, "cache");
                let _ = swarm.dial(DialOpts::peer_id(p).addresses(addrs).build());
            }
        }
        if let Some(ipfs) = swarm.behaviour_mut().ipfs.as_mut() {
            for a in &cfg.ipfs_bootstrap {
                if let Some((p, base)) = split_peer(a) {
                    ipfs.kad.add_address(&p, base);
                }
            }
            let _ = ipfs.kad.bootstrap();
        }
        let fallback_at = cfg.bootstrap_url.as_ref().map(|_| {
            if cfg.ipfs {
                now + cfg.bootstrap_url_after
            } else {
                now
            }
        });

        let (events, _) = broadcast::channel(256);
        let topics: Topics = Arc::new(Mutex::new(HashMap::new()));
        let own: Own = Arc::new(Mutex::new(HashMap::new()));
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let (inner_tx, inner_rx) = mpsc::unbounded_channel();
        let (note_tx, note_rx) = mpsc::unbounded_channel();
        let targets: tunnel::SharedTargets = Arc::new(Mutex::new(tunnel::Targets {
            default: cfg.tunnel_target,
            peers: HashMap::new(),
        }));
        let (rpc_tx, rpc_rx) = mpsc::unbounded_channel();
        let gate = rpc::Gate::new(cfg.rpc.clone());

        let lp = EventLoop {
            swarm,
            cfg: cfg.clone(),
            me: peer_id,
            events: events.clone(),
            topics: topics.clone(),
            own: own.clone(),
            rec_slots: Arc::new(tokio::sync::Semaphore::new(REC_SERVE_MAX)),
            rec_peer_slots: HashMap::new(),
            gossip_seen: HashMap::new(),
            gossip_rate: HashMap::new(),
            purged: now,
            pending: HashMap::new(),
            finds: HashMap::new(),
            next_find: 0,
            dials: HashMap::new(),
            closest: HashSet::new(),
            in_flight: HashMap::new(),
            conns: HashMap::new(),
            anchors,
            mdns_peers: HashSet::new(),
            tunnels: HashMap::new(),
            allowed: HashSet::new(),
            targets: targets.clone(),
            next_sid: 0,
            inner_tx,
            note_tx,
            rpc_tx,
            gate: gate.clone(),
            cache,
            cache_saved: now,
            seeds,
            mesh_peers: HashSet::new(),
            good_peers: HashSet::new(),
            mesh_bootstrap_at: now,
            fallback_at,
            ipfs_ready: false,
            ipfs_pending: HashMap::new(),
            ipfs_next_lookup: now,
            ipfs_provided: None,
            ipfs_observed: Vec::new(),
            peer_direct: HashMap::new(),
            identify_dial_at: HashMap::new(),
            observed_votes: HashMap::new(),
            ipfs_found: HashSet::new(),
            observed_ip4: None,
            upnp_mapped: false,
            upnp_failed: false,
        };
        tokio::spawn(lp.run(cmd_rx, inner_rx, note_rx));

        let rpc_rx = Arc::new(Mutex::new(Some(rpc_rx)));
        Ok(Node {
            peer_id,
            keypair,
            ttl: cfg.record_ttl,
            cmd,
            events,
            topics,
            own,
            targets,
            rpc_rx,
            gate,
            blocked,
            permanently_blocked,
        })
    }

    #[doc(hidden)]
    pub fn block_direct(&self, peer: PeerId, block: bool) {
        let mut b = self.blocked.lock().unwrap();
        if block {
            b.insert(peer);
        } else if !self.permanently_blocked.contains(&peer) {
            b.remove(&peer);
        }
    }

    pub fn rpc_stats(&self) -> RpcStats {
        self.gate.stats()
    }

    #[doc(hidden)]
    pub async fn open_rpc_stream(&self, peer: PeerId) -> anyhow::Result<libp2p::Stream> {
        self.connect(peer).await?;
        self.call(|reply| Command::OpenRpc { peer, reply }).await
    }

    pub fn rpc_requests(&self) -> Option<mpsc::UnboundedReceiver<RpcRequest>> {
        self.rpc_rx.lock().unwrap().take()
    }

    pub async fn request(&self, peer: PeerId, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.connect(peer).await?;
        let mut s = self.call(|reply| Command::OpenRpc { peer, reply }).await?;
        let max = self.gate.limits().max_reply;
        let out = tokio::time::timeout(RPC_TIMEOUT, async move {
            rpc::write_frame(&mut s, &data).await?;
            let out = rpc::read_frame(&mut s, max).await?;
            let _ = s.close().await;
            anyhow::Ok(out)
        })
        .await
        .map_err(|_| anyhow!("rpc timed out"))??;
        let _ = self.cmd.send(Command::RpcOk { peer });
        Ok(out)
    }

    pub fn set_tunnel_target(&self, addr: SocketAddr) {
        self.targets.lock().unwrap().default = Some(addr);
    }

    pub fn clear_tunnel_target(&self) {
        self.targets.lock().unwrap().default = None;
    }

    pub fn set_peer_target(&self, peer: PeerId, addr: Option<SocketAddr>) {
        let mut t = self.targets.lock().unwrap();
        match addr {
            Some(a) => {
                t.peers.insert(peer, a);
            }
            None => {
                t.peers.remove(&peer);
            }
        }
    }

    pub fn allow_peer(&self, peer: PeerId) {
        let _ = self.cmd.send(Command::Allow { peer, allow: true });
    }

    pub fn deny_peer(&self, peer: PeerId) {
        let _ = self.cmd.send(Command::Allow { peer, allow: false });
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    async fn call<T>(&self, f: impl FnOnce(Reply<T>) -> Command) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(f(tx)).map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    async fn ask<T: Default>(&self, f: impl FnOnce(oneshot::Sender<T>) -> Command) -> T {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd.send(f(tx));
        rx.await.unwrap_or_default()
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let bytes = Record::sign(&self.keypair, topic, data, self.ttl)?;
        {
            let mut own = self.own.lock().unwrap();
            if own.len() >= OWN_MAX && !own.contains_key(topic) {
                own.retain(|_, b| Record::verify(b).is_some());
            }
            if own.len() < OWN_MAX || own.contains_key(topic) {
                own.insert(topic.to_string(), bytes.clone());
            }
        }
        self.call(|reply| Command::Publish {
            topic: topic.to_string(),
            bytes,
            reply,
        })
        .await
    }

    pub async fn find(&self, topic: &str) -> anyhow::Result<Vec<Record>> {
        self.find_within(topic, FIND_DEADLINE).await
    }

    pub async fn find_within(
        &self,
        topic: &str,
        deadline: Duration,
    ) -> anyhow::Result<Vec<Record>> {
        let (out, _) = self
            .call(|reply| Command::Find {
                topic: topic.to_string(),
                deadline,
                complete: false,
                reply,
            })
            .await?;
        Ok(out)
    }

    pub async fn find_complete(
        &self,
        topic: &str,
        deadline: Duration,
    ) -> anyhow::Result<Vec<Record>> {
        let start = Instant::now();
        let (mut out, missing) = self
            .call(|reply| Command::Find {
                topic: topic.to_string(),
                deadline,
                complete: true,
                reply,
            })
            .await?;
        if missing.is_empty() {
            return Ok(out);
        }
        let left = deadline.saturating_sub(start.elapsed()).min(DIRECT_FETCH);
        let got = futures::future::join_all(
            missing
                .into_iter()
                .map(|p| tokio::time::timeout(left, self.fetch_direct(p, topic))),
        )
        .await;
        out.extend(got.into_iter().filter_map(|r| r.ok().and_then(|r| r.ok())));
        Ok(out)
    }

    async fn fetch_direct(&self, peer: PeerId, topic: &str) -> anyhow::Result<Record> {
        self.connect(peer).await?;
        let mut s = self.call(|reply| Command::OpenRec { peer, reply }).await?;
        rpc::write_frame(&mut s, topic.as_bytes()).await?;
        let bytes = rpc::read_frame(&mut s, REC_MAX).await?;
        let _ = s.close().await;
        Record::verify(&bytes)
            .filter(|r| r.topic == topic && r.publisher == peer)
            .ok_or_else(|| anyhow!("peer served no valid record"))
    }

    pub fn subscribe(&self, topic: &str) -> impl Stream<Item = Record> + Send + 'static {
        let _ = self.cmd.send(Command::Subscribe {
            topic: topic.to_string(),
        });
        let topic = topic.to_string();
        let rx = {
            let mut t = self.topics.lock().unwrap();
            t.retain(|_, tx| tx.receiver_count() > 0);
            t.entry(topic.clone())
                .or_insert_with(|| broadcast::channel(256).0)
                .subscribe()
        };
        futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(r) => return Some((r, rx)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
        .filter(move |r| futures::future::ready(r.topic == topic))
    }

    pub fn events(&self) -> impl Stream<Item = Event> + Send + 'static {
        futures::stream::unfold(self.events.subscribe(), |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(e) => return Some((e, rx)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
    }

    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        let me = self.peer_id;
        self.ask(|reply| Command::ListenAddrs { reply })
            .await
            .into_iter()
            .map(|a| {
                if split_peer(&a).is_some() {
                    a
                } else {
                    a.with(Protocol::P2p(me))
                }
            })
            .collect()
    }

    pub async fn connections(&self, peer: PeerId) -> Vec<Multiaddr> {
        self.ask(|reply| Command::Connections { peer, reply }).await
    }

    pub fn add_external_addr(&self, addr: Multiaddr) {
        let _ = self.cmd.send(Command::AddExternal { addr });
    }

    pub async fn dial(&self, addr: Multiaddr) -> anyhow::Result<()> {
        self.call(|reply| Command::Dial { addr, reply }).await
    }

    pub fn disconnect(&self, peer: PeerId) {
        let _ = self.cmd.send(Command::Disconnect { peer });
    }

    pub async fn try_connect(&self, peer: PeerId) -> anyhow::Result<()> {
        self.call(|reply| Command::Connect { peer, reply }).await
    }

    pub async fn connect(&self, peer: PeerId) -> anyhow::Result<()> {
        let mut tries = 0;
        while let Err(e) = self.try_connect(peer).await {
            tries += 1;
            if tries >= 5 {
                return Err(e);
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        Ok(())
    }

    pub async fn open_tunnel(&self, peer: PeerId) -> anyhow::Result<SocketAddr> {
        self.connect(peer).await?;
        self.call(|reply| Command::OpenTunnel { peer, reply }).await
    }

    pub fn close_tunnel(&self, peer: PeerId) {
        let _ = self.cmd.send(Command::CloseTunnel { peer });
    }

    pub async fn tunnels(&self) -> Vec<TunnelInfo> {
        self.ask(|reply| Command::Tunnels { reply }).await
    }
}

struct EventLoop {
    swarm: Swarm<Behaviour>,
    cfg: Config,
    me: PeerId,
    events: broadcast::Sender<Event>,
    topics: Topics,
    own: Own,
    rec_slots: Arc<tokio::sync::Semaphore>,
    rec_peer_slots: HashMap<PeerId, Arc<tokio::sync::Semaphore>>,
    gossip_seen: HashMap<(String, PeerId), u64>,
    gossip_rate: HashMap<(PeerId, String), (Instant, u16)>,
    purged: Instant,
    pending: HashMap<kad::QueryId, Pending>,
    finds: HashMap<u64, FindState>,
    next_find: u64,
    dials: HashMap<PeerId, Vec<Reply<()>>>,
    closest: HashSet<PeerId>,
    in_flight: HashMap<PeerId, HashSet<ConnectionId>>,
    conns: HashMap<PeerId, HashMap<ConnectionId, Multiaddr>>,
    anchors: Vec<Anchor>,
    mdns_peers: HashSet<PeerId>,
    tunnels: HashMap<PeerId, Tun>,
    allowed: HashSet<PeerId>,
    targets: tunnel::SharedTargets,
    next_sid: u64,
    inner_tx: mpsc::UnboundedSender<Inner>,
    note_tx: mpsc::UnboundedSender<tunnel::Note>,
    rpc_tx: mpsc::UnboundedSender<RpcRequest>,
    gate: Arc<rpc::Gate>,
    cache: Option<discovery::PeerCache>,
    cache_saved: Instant,
    seeds: HashMap<PeerId, &'static str>,
    mesh_peers: HashSet<PeerId>,
    good_peers: HashSet<PeerId>,
    mesh_bootstrap_at: Instant,
    fallback_at: Option<Instant>,
    ipfs_ready: bool,
    ipfs_pending: HashMap<kad::QueryId, IpfsQuery>,
    ipfs_next_lookup: Instant,
    ipfs_provided: Option<(Instant, Vec<Multiaddr>)>,
    ipfs_observed: Vec<Multiaddr>,
    peer_direct: HashMap<PeerId, Vec<Multiaddr>>,
    identify_dial_at: HashMap<PeerId, Instant>,
    observed_votes: HashMap<Multiaddr, HashSet<IpAddr>>,
    ipfs_found: HashSet<PeerId>,
    observed_ip4: Option<Ipv4Addr>,
    upnp_mapped: bool,
    upnp_failed: bool,
}

pub fn network_source_bucket(peer: PeerId, addrs: &[Multiaddr]) -> String {
    for addr in addrs {
        if let Some(ip) = discovery::ip_of(addr) {
            return match ip {
                IpAddr::V4(ip) => {
                    let [a, b, c, _] = ip.octets();
                    format!("net4:{a}.{b}.{c}.0/24")
                }
                IpAddr::V6(ip) => {
                    let segments = ip.segments();
                    format!(
                        "net6:{:x}:{:x}:{:x}:{:x}::/64",
                        segments[0], segments[1], segments[2], segments[3]
                    )
                }
            };
        }
    }
    format!("peer:{peer}")
}

enum IpfsQuery {
    Provide {
        topic: String,
    },
    Lookup {
        topic: String,
        found: HashSet<PeerId>,
        dialed: u8,
    },
}

const MAX_DIRECT_DIAL: usize = 8;
const IPFS_REPROVIDE_MIN: Duration = Duration::from_secs(30);
const IPFS_LOOKUP_FOUND: Duration = Duration::from_secs(300);
const CACHE_SAVE_EVERY: Duration = Duration::from_secs(2);
const MESH_BOOTSTRAP_EVERY: Duration = Duration::from_secs(5);

impl EventLoop {
    async fn run(
        mut self,
        mut cmd_rx: mpsc::UnboundedReceiver<Command>,
        mut inner_rx: mpsc::UnboundedReceiver<Inner>,
        mut note_rx: mpsc::UnboundedReceiver<tunnel::Note>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                ev = self.swarm.select_next_some() => self.on_swarm(ev),
                cmd = cmd_rx.recv() => match cmd {
                    Some(c) => self.on_command(c),
                    None => break,
                },
                Some(i) = inner_rx.recv() => self.on_inner(i),
                Some(n) = note_rx.recv() => self.on_inner(Inner::Note(n)),
                _ = tick.tick() => self.on_tick(),
            }
        }
        let peers: Vec<PeerId> = self.tunnels.keys().copied().collect();
        for p in peers {
            self.drop_tunnel(p, "node stopped", false);
        }
        if let Some(c) = self.cache.as_mut() {
            if c.dirty() {
                let _ = c.save();
            }
        }
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    fn connected(&self, p: &PeerId) -> bool {
        self.swarm.is_connected(p)
    }

    fn dialing(&self, p: &PeerId) -> bool {
        self.in_flight.get(p).is_some_and(|s| !s.is_empty())
    }

    fn best_conn(&self, peer: &PeerId) -> Option<(ConnectionId, u8)> {
        self.conns
            .get(peer)?
            .iter()
            .map(|(c, a)| (*c, rank(a)))
            .max_by_key(|(c, r)| (*r, *c))
    }

    fn conn_rank(&self, peer: &PeerId, conn: ConnectionId) -> u8 {
        self.conns
            .get(peer)
            .and_then(|m| m.get(&conn))
            .map(rank)
            .unwrap_or(0)
    }
    fn on_command(&mut self, cmd: Command) {
        let me = self.me;
        match cmd {
            Command::Publish {
                topic,
                bytes,
                reply,
            } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(gossipsub::IdentTopic::new(&topic), bytes.clone());
                let rec = kad::Record {
                    key: record_key(&topic, &me),
                    value: bytes,
                    publisher: Some(me),
                    expires: Some(std::time::Instant::now() + self.cfg.record_ttl),
                };
                let k = &mut self.swarm.behaviour_mut().kad;
                match k.put_record(rec, kad::Quorum::One) {
                    Ok(id) => match k.start_providing(topic_key(&topic)) {
                        Ok(_) => {
                            self.pending.insert(id, Pending::PutRecord { reply });
                        }
                        Err(e) => {
                            let _ = reply.send(Err(anyhow!("start_providing: {e:?}")));
                        }
                    },
                    Err(e) => {
                        let _ = reply.send(Err(anyhow!("put_record: {e:?}")));
                    }
                }
            }
            Command::Find {
                topic,
                deadline,
                complete,
                reply,
            } => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .get_providers(topic_key(&topic));
                let find = self.next_find;
                self.next_find += 1;
                self.finds.insert(
                    find,
                    FindState {
                        left: 0,
                        searching: true,
                        out: vec![],
                        reply,
                        deadline: Instant::now() + deadline,
                        complete,
                        truncated: false,
                        missing: vec![],
                        queries: vec![id],
                    },
                );
                self.pending.insert(
                    id,
                    Pending::Providers {
                        find,
                        topic,
                        found: HashSet::new(),
                    },
                );
            }
            Command::Subscribe { topic } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(topic));
            }
            Command::Connect { peer, reply } => self.connect_peer(peer, Some(reply)),
            Command::Dial { addr, reply } => {
                if let Some((peer, base)) = split_peer(&addr) {
                    self.swarm.behaviour_mut().kad.add_address(&peer, base);
                }
                let _ = reply.send(self.swarm.dial(addr).map_err(|e| anyhow!("dial: {e}")));
            }
            Command::Disconnect { peer } => {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
            Command::AddExternal { addr } => {
                let addr = split_peer(&addr).map(|(_, a)| a).unwrap_or(addr);
                self.swarm.add_external_address(addr);
            }
            Command::ListenAddrs { reply } => {
                let _ = reply.send(self.swarm.listeners().cloned().collect());
            }
            Command::Connections { peer, reply } => {
                let v = self
                    .conns
                    .get(&peer)
                    .map(|m| m.values().cloned().collect())
                    .unwrap_or_default();
                let _ = reply.send(v);
            }
            Command::OpenTunnel { peer, reply } => self.open_tunnel(peer, reply),
            Command::CloseTunnel { peer } => self.drop_tunnel(peer, "closed locally", true),
            Command::Tunnels { reply } => {
                let v = self
                    .tunnels
                    .iter()
                    .map(|(p, t)| TunnelInfo {
                        peer: *p,
                        local: t.local,
                        streams: t.streams.len(),
                    })
                    .collect();
                let _ = reply.send(v);
            }
            Command::Allow { peer, allow } => {
                let permitted = !self.cfg.tunnel_blocklist.contains(&peer)
                    && self
                        .cfg
                        .tunnel_allowlist
                        .as_ref()
                        .is_none_or(|peers| peers.contains(&peer));
                if allow && permitted {
                    self.allowed.insert(peer);
                } else {
                    self.allowed.remove(&peer);
                    self.drop_tunnel(peer, "denied", true);
                }
            }
            Command::RpcOk { peer } => {
                if self.good_peers.len() < GOOD_MAX || self.good_peers.contains(&peer) {
                    self.good_peers.insert(peer);
                    if let Some(c) = self.cache.as_mut() {
                        c.good(peer);
                    }
                }
            }
            Command::OpenRpc { peer, reply } => self.open_stream(peer, false, reply),
            Command::OpenRec { peer, reply } => self.open_stream(peer, true, reply),
        }
    }

    fn open_stream(&mut self, peer: PeerId, rec: bool, reply: Reply<libp2p::Stream>) {
        match self.best_conn(&peer) {
            Some((conn, _)) => {
                let (tx, rx) =
                    futures::channel::oneshot::channel::<Result<libp2p::Stream, String>>();
                let b = self.swarm.behaviour_mut();
                if rec {
                    b.rec.open(peer, conn, tx)
                } else {
                    b.rpc.open(peer, conn, tx)
                }
                tokio::spawn(async move {
                    let r = match rx.await {
                        Ok(Ok(s)) => Ok(s),
                        Ok(Err(e)) => Err(anyhow!("rpc open: {e}")),
                        Err(_) => Err(anyhow!("connection closed")),
                    };
                    let _ = reply.send(r);
                });
            }
            None => {
                let _ = reply.send(Err(anyhow!("not connected")));
            }
        }
    }

    fn serve_rec(&mut self, peer: PeerId, mut stream: libp2p::Stream) {
        let Ok(permit) = self.rec_slots.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "rec stream rejected: busy");
            return;
        };
        let slots = self
            .rec_peer_slots
            .entry(peer)
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(2)));
        let Ok(peer_permit) = slots.clone().try_acquire_owned() else {
            return;
        };
        let own = self.own.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _peer_permit = peer_permit;
            let _ = tokio::time::timeout(DIRECT_FETCH, async {
                let topic = tokio::time::timeout(
                    Duration::from_secs(1),
                    rpc::read_frame(&mut stream, REC_TOPIC_MAX),
                )
                .await??;
                let topic = String::from_utf8(topic).unwrap_or_default();
                let bytes = own.lock().unwrap().get(&topic).cloned().unwrap_or_default();
                rpc::write_frame(&mut stream, &bytes).await?;
                stream.close().await?;
                anyhow::Ok(())
            })
            .await;
        });
    }

    fn connect_peer(&mut self, peer: PeerId, reply: Option<Reply<()>>) {
        if self.connected(&peer) {
            if let Some(r) = reply {
                let _ = r.send(Ok(()));
            }
            return;
        }
        let waiters = self.dials.entry(peer).or_default();
        waiters.extend(reply);
        if self.closest.insert(peer) {
            let id = self.swarm.behaviour_mut().kad.get_closest_peers(peer);
            self.pending.insert(id, Pending::Closest { peer });
        }
    }

    fn fail_dials(&mut self, peer: &PeerId, why: String) {
        for r in self.dials.remove(peer).unwrap_or_default() {
            let _ = r.send(Err(anyhow!("{why}")));
        }
    }

    fn new_tunnel(&mut self, peer: PeerId) -> std::io::Result<SocketAddr> {
        let sock = tunnel::bind_loopback()?;
        let local = sock.local_addr()?;
        let ctl = tunnel::spawn(peer, sock, self.targets.clone(), self.note_tx.clone());
        let now = Instant::now();
        self.tunnels.insert(
            peer,
            Tun {
                local,
                ctl,
                streams: HashMap::new(),
                pending: 0,
                opening: None,
                waiters: vec![],
                retry_at: now + TUNNEL_BACKOFF,
                backoff: TUNNEL_BACKOFF,
                down_since: now,
                ever_up: false,
                path: None,
            },
        );
        Ok(local)
    }

    fn open_tunnel(&mut self, peer: PeerId, reply: Reply<SocketAddr>) {
        if !self.allowed.contains(&peer) {
            let _ = reply.send(Err(anyhow!("peer not authorized")));
            return;
        }
        if let Some(t) = self.tunnels.get_mut(&peer) {
            if t.streams.is_empty() {
                t.waiters.push(reply);
                t.retry_at = Instant::now();
            } else {
                let _ = reply.send(Ok(t.local));
            }
            return;
        }
        if self.tunnels.len() >= self.cfg.max_tunnels {
            let _ = reply.send(Err(anyhow!("tunnel limit reached")));
            return;
        }
        if let Err(e) = self.new_tunnel(peer) {
            let _ = reply.send(Err(anyhow!("bind: {e}")));
            return;
        }
        self.tunnels.get_mut(&peer).unwrap().waiters.push(reply);
        self.start_open(peer);
    }

    fn start_open(&mut self, peer: PeerId) {
        let Some((conn, rank)) = self.best_conn(&peer) else {
            self.connect_peer(peer, None);
            return;
        };
        let sid = self.next_sid;
        self.next_sid += 1;
        let Some(t) = self.tunnels.get_mut(&peer) else {
            return;
        };
        if t.opening.is_some() {
            return;
        }
        t.opening = Some(sid);
        let (tx, rx) = futures::channel::oneshot::channel::<Result<libp2p::Stream, String>>();
        self.swarm.behaviour_mut().pipe.open(peer, conn, tx);
        let inner = self.inner_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let mut s = rx.await.map_err(|_| "connection closed".to_string())??;
                let mut b = [0u8; 1];
                tokio::time::timeout(ACK_TIMEOUT, s.read_exact(&mut b))
                    .await
                    .map_err(|_| "peer did not answer".to_string())?
                    .map_err(|e| format!("rejected by peer: {e}"))?;
                if b[0] != tunnel::ACCEPT {
                    return Err("rejected by peer".to_string());
                }
                Ok(s)
            }
            .await;
            let _ = inner.send(Inner::Opened {
                peer,
                sid,
                rank,
                conn,
                result,
            });
        });
    }

    fn attach(
        &mut self,
        peer: PeerId,
        sid: u64,
        rank: u8,
        conn: ConnectionId,
        stream: libp2p::Stream,
    ) {
        let lower = self.me < peer;
        let Some(t) = self.tunnels.get_mut(&peer) else {
            return;
        };
        t.streams.insert(sid, (rank, conn));
        let _ = t.ctl.send(tunnel::Ctl::Attach { sid, stream, rank });
        t.ever_up = true;
        t.backoff = TUNNEL_BACKOFF;
        for w in t.waiters.drain(..) {
            let _ = w.send(Ok(t.local));
        }
        if lower {
            let old: Vec<u64> = t
                .streams
                .iter()
                .filter(|(s, (r, _))| **s != sid && *r <= rank)
                .map(|(s, _)| *s)
                .collect();
            for s in old {
                let ctl = t.ctl.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(PRUNE_GRACE).await;
                    let _ = ctl.send(tunnel::Ctl::Drop { sid: s });
                });
            }
        }
        self.emit_path(peer);
    }

    fn emit_path(&mut self, peer: PeerId) {
        let Some(t) = self.tunnels.get_mut(&peer) else {
            return;
        };
        let Some(top) = t.top() else { return };
        if t.path != Some(top) {
            let quic = top >= 3;
            tracing::info!(%peer, quic, "tunnel path");
            t.path = Some(top);
            let e = Event::TunnelPath {
                peer,
                local: t.local,
                quic,
            };
            self.emit(e);
        }
    }

    fn drop_tunnel(&mut self, peer: PeerId, reason: &str, notify_remote: bool) {
        let Some(t) = self.tunnels.remove(&peer) else {
            return;
        };
        let _ = t.ctl.send(if notify_remote {
            tunnel::Ctl::Close
        } else {
            tunnel::Ctl::Stop
        });
        for w in t.waiters {
            let _ = w.send(Err(anyhow!("tunnel closed: {reason}")));
        }
        if t.ever_up {
            self.emit(Event::TunnelClosed {
                peer,
                local: t.local,
                reason: reason.to_string(),
            });
        }
    }

    fn on_inbound(&mut self, peer: PeerId, conn: ConnectionId, mut stream: libp2p::Stream) {
        let rank = self.conn_rank(&peer, conn);
        let verdict = if !self.allowed.contains(&peer) {
            Err("not authorized")
        } else if let Some(t) = self.tunnels.get(&peer) {
            if t.streams.len() + t.pending >= self.cfg.max_streams_per_peer {
                Err("stream limit")
            } else {
                Ok(())
            }
        } else if self.targets.lock().unwrap().get(&peer).is_none() {
            Err("no tunnel target")
        } else if self.tunnels.len() >= self.cfg.max_tunnels {
            Err("tunnel limit")
        } else {
            match self.new_tunnel(peer) {
                Ok(local) => {
                    self.emit(Event::TunnelAccepted { peer, local });
                    Ok(())
                }
                Err(_) => Err("bind failed"),
            }
        };
        if let Err(why) = verdict {
            tracing::debug!(%peer, why, "tunnel stream rejected");
        }
        let sid = self.next_sid;
        self.next_sid += 1;
        if verdict.is_ok() {
            self.tunnels.get_mut(&peer).unwrap().pending += 1;
        }
        let inner = self.inner_tx.clone();
        tokio::spawn(async move {
            let ok = verdict.is_ok();
            let byte = if ok { tunnel::ACCEPT } else { tunnel::REJECT };
            let sent = tokio::time::timeout(ACK_TIMEOUT, async {
                stream.write_all(&[byte]).await.is_ok() && stream.flush().await.is_ok()
            })
            .await
            .unwrap_or(false);
            if ok && sent {
                let _ = inner.send(Inner::Accepted {
                    peer,
                    sid,
                    rank,
                    conn,
                    stream,
                });
            } else {
                let _ = tokio::time::timeout(ACK_TIMEOUT, stream.close()).await;
                if ok {
                    let _ = inner.send(Inner::AcceptFailed { peer });
                }
            }
        });
    }

    fn on_inner(&mut self, i: Inner) {
        let now = Instant::now();
        match i {
            Inner::Opened {
                peer,
                sid,
                rank,
                conn,
                result,
            } => {
                let Some(t) = self.tunnels.get_mut(&peer) else {
                    if let Ok(mut s) = result {
                        tokio::spawn(async move {
                            let _ = s.close().await;
                        });
                    }
                    return;
                };
                if t.opening == Some(sid) {
                    t.opening = None;
                }
                match result {
                    Ok(stream) => self.attach(peer, sid, rank, conn, stream),
                    Err(e) => {
                        tracing::debug!(%peer, "tunnel open failed: {e}");
                        if t.streams.is_empty() {
                            for w in t.waiters.drain(..) {
                                let _ = w.send(Err(anyhow!("open_tunnel: {e}")));
                            }
                            if !t.ever_up {
                                self.drop_tunnel(peer, &e, false);
                            }
                        }
                    }
                }
            }
            Inner::Accepted {
                peer,
                sid,
                rank,
                conn,
                mut stream,
            } => {
                if let Some(t) = self.tunnels.get_mut(&peer) {
                    t.pending = t.pending.saturating_sub(1);
                }
                if self.tunnels.contains_key(&peer) {
                    self.attach(peer, sid, rank, conn, stream);
                } else {
                    tokio::spawn(async move {
                        let _ = stream.close().await;
                    });
                }
            }
            Inner::AcceptFailed { peer } => {
                if let Some(t) = self.tunnels.get_mut(&peer) {
                    t.pending = t.pending.saturating_sub(1);
                }
            }
            Inner::Note(tunnel::Note::Ended { peer, sid }) => {
                let lower = self.me < peer;
                let Some(t) = self.tunnels.get_mut(&peer) else {
                    return;
                };
                if t.streams.remove(&sid).is_some() {
                    let _ = t.ctl.send(tunnel::Ctl::Drop { sid });
                    if t.streams.is_empty() {
                        t.down_since = now;
                        t.path = None;
                        t.retry_at = if lower {
                            now
                        } else {
                            now + Duration::from_millis(1500)
                        };
                    } else {
                        t.path = None;
                        self.emit_path(peer);
                    }
                }
            }
            Inner::Note(tunnel::Note::RemoteClosed { peer }) => {
                self.drop_tunnel(peer, "closed by peer", false)
            }
            Inner::Fallback(r) => self.on_fallback(r),
        }
    }

    fn on_fallback(&mut self, r: Result<Vec<Multiaddr>, String>) {
        let addrs = match r {
            Ok(a) => a,
            Err(e) => {
                self.emit(Event::FallbackList {
                    addrs: 0,
                    error: Some(e),
                });
                return;
            }
        };
        let now = Instant::now();
        for a in &addrs {
            let Some((p, base)) = split_peer(a) else {
                continue;
            };
            if p == self.me {
                continue;
            }
            self.swarm.behaviour_mut().kad.add_address(&p, base);
            if self.seeds.len() >= SEEDS_MAX {
                self.prune_seeds();
            }
            if self.seeds.len() < SEEDS_MAX {
                self.seeds.entry(p).or_insert("fallback");
            }
            if !self.anchors.iter().any(|x| x.peer == p) {
                self.anchors.push(Anchor {
                    peer: p,
                    addr: a.clone(),
                    next: now,
                    backoff: ANCHOR_BACKOFF,
                });
            }
        }
        self.emit(Event::FallbackList {
            addrs: addrs.len(),
            error: None,
        });
    }

    fn discovery_tick(&mut self, now: Instant) {
        if let Some(at) = self.fallback_at {
            if now >= at {
                self.fallback_at = None;
                if self.mesh_peers.is_empty() {
                    if let Some(url) = self.cfg.bootstrap_url.clone() {
                        let inner = self.inner_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let r =
                                discovery::fetch_list_blocking(&url).map_err(|e| format!("{e}"));
                            let _ = inner.send(Inner::Fallback(r));
                        });
                    }
                }
            }
        }
        if let Some(c) = self.cache.as_mut() {
            if c.dirty() && now.duration_since(self.cache_saved) >= CACHE_SAVE_EVERY {
                self.cache_saved = now;
                if let Err(e) = c.save() {
                    tracing::debug!("peer cache save failed: {e}");
                }
            }
        }
        if !self.ipfs_ready {
            return;
        }
        let announce = self.ipfs_announce();
        let topics = self.cfg.ipfs_topics.clone();
        let Some(ipfs) = self.swarm.behaviour_mut().ipfs.as_mut() else {
            return;
        };
        let changed = ipfs.set_announced(announce.clone());
        if changed {
            let _ = self.events.send(Event::IpfsAnnounce {
                addrs: announce.clone(),
            });
        }
        let due = match self.ipfs_provided {
            None => true,
            Some((t, ref with)) => *with != announce && now.duration_since(t) >= IPFS_REPROVIDE_MIN,
        };
        if due && !announce.is_empty() {
            self.ipfs_provided = Some((now, announce.clone()));
            for topic in &topics {
                match ipfs.kad.start_providing(discovery::provider_key(topic)) {
                    Ok(id) => {
                        self.ipfs_pending.insert(
                            id,
                            IpfsQuery::Provide {
                                topic: topic.clone(),
                            },
                        );
                    }
                    Err(e) => tracing::debug!("ipfs start_providing: {e:?}"),
                }
            }
        }
        if now >= self.ipfs_next_lookup {
            let found_any = self.ipfs_found.iter().any(|p| self.mesh_peers.contains(p));
            self.ipfs_next_lookup = now
                + if found_any {
                    IPFS_LOOKUP_FOUND
                } else {
                    self.cfg.ipfs_lookup_interval
                };
            for topic in &topics {
                let id = ipfs.kad.get_providers(discovery::provider_key(topic));
                self.ipfs_pending.insert(
                    id,
                    IpfsQuery::Lookup {
                        topic: topic.clone(),
                        found: HashSet::new(),
                        dialed: 0,
                    },
                );
            }
        }
    }

    fn ipfs_announce(&self) -> Vec<Multiaddr> {
        let mut out: Vec<Multiaddr> = Vec::new();
        let push = |a: Multiaddr, out: &mut Vec<Multiaddr>| {
            let a = split_peer(&a).map(|(_, b)| b).unwrap_or(a);
            if !out.contains(&a) && !is_unspecified(&a) {
                out.push(a);
            }
        };
        for a in self.swarm.external_addresses() {
            push(a.clone(), &mut out);
        }
        for a in &self.ipfs_observed {
            push(a.clone(), &mut out);
        }
        for a in self.swarm.listeners() {
            let keep = self.cfg.ipfs_announce_lan && addr_scope(a) != Scope::Loopback;
            if keep {
                push(a.clone(), &mut out);
            }
        }
        out.truncate(8);
        out.sort_by_key(|a| a.to_vec());
        out
    }

    fn on_ipfs(&mut self, ev: kad::Event) {
        match ev {
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(r),
                ..
            } => {
                if !self.ipfs_ready {
                    self.ipfs_ready = true;
                    let peers = self
                        .swarm
                        .behaviour_mut()
                        .ipfs
                        .as_mut()
                        .map(|i| i.kad.kbuckets().map(|b| b.num_entries()).sum())
                        .unwrap_or(0);
                    self.emit(Event::IpfsReady {
                        peers,
                        error: r.err().map(|e| format!("{e:?}")),
                    });
                }
            }
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => {
                let Some(q) = self.ipfs_pending.remove(&id) else {
                    return;
                };
                match (q, result) {
                    (IpfsQuery::Provide { topic }, kad::QueryResult::StartProviding(r)) => {
                        self.emit(Event::IpfsProvided {
                            topic,
                            ok: r.is_ok(),
                        });
                    }
                    (
                        IpfsQuery::Lookup {
                            topic,
                            mut found,
                            mut dialed,
                        },
                        kad::QueryResult::GetProviders(r),
                    ) => {
                        if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = r {
                            for p in providers {
                                if p == self.me || !found.insert(p) {
                                    continue;
                                }
                                if self.ipfs_found.len() >= IPFS_FOUND_MAX {
                                    let keep: HashSet<PeerId> = self
                                        .ipfs_found
                                        .iter()
                                        .filter(|q| self.mesh_peers.contains(q))
                                        .copied()
                                        .collect();
                                    self.ipfs_found = keep;
                                }
                                if self.ipfs_found.len() < IPFS_FOUND_MAX {
                                    self.ipfs_found.insert(p);
                                }
                                if dialed < 8 && !self.connected(&p) {
                                    dialed += 1;
                                    if self.seeds.len() >= SEEDS_MAX {
                                        self.prune_seeds();
                                    }
                                    if self.seeds.len() < SEEDS_MAX {
                                        self.seeds.entry(p).or_insert("ipfs");
                                    }
                                    if let Err(e) = self.swarm.dial(DialOpts::peer_id(p).build()) {
                                        self.emit(Event::DiscoveryDialFailed {
                                            peer: p,
                                            via: "ipfs",
                                            error: format!("{e}"),
                                        });
                                    }
                                }
                            }
                        }
                        if step.last {
                            self.emit(Event::IpfsProviders {
                                topic,
                                providers: found.len(),
                            });
                        } else {
                            self.ipfs_pending.insert(
                                id,
                                IpfsQuery::Lookup {
                                    topic,
                                    found,
                                    dialed,
                                },
                            );
                        }
                    }
                    (q, _) => {
                        if !step.last {
                            self.ipfs_pending.insert(id, q);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn done_dialing(&mut self, peer: &PeerId, conn: ConnectionId) {
        if let Some(s) = self.in_flight.get_mut(peer) {
            s.remove(&conn);
            if s.is_empty() {
                self.in_flight.remove(peer);
            }
        }
    }

    fn prune_seeds(&mut self) {
        let live: Vec<PeerId> = self
            .seeds
            .keys()
            .filter(|p| !self.connected(p) && !self.dialing(p))
            .copied()
            .collect();
        for p in live {
            self.seeds.remove(&p);
        }
    }

    fn purge(&mut self, now: Instant) {
        if now.duration_since(self.purged) < PURGE_EVERY {
            return;
        }
        self.purged = now;
        self.swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .purge(std::time::Instant::now());
        let t = record::now_secs();
        self.gossip_seen
            .retain(|_, e| e.saturating_add(CLOCK_SKEW.as_secs()) > t);
        self.in_flight.retain(|_, s| !s.is_empty());
        if self.seeds.len() >= SEEDS_MAX / 2 {
            self.prune_seeds();
        }
    }

    fn gossip_fresh(&mut self, rec: &Record) -> bool {
        let k = (rec.topic.clone(), rec.publisher);
        match self.gossip_seen.get_mut(&k) {
            Some(e) if *e >= rec.expires => false,
            Some(e) => {
                *e = rec.expires;
                true
            }
            None => {
                if self.gossip_seen.len() >= GOSSIP_SEEN_MAX {
                    let t = record::now_secs();
                    self.gossip_seen
                        .retain(|_, e| e.saturating_add(CLOCK_SKEW.as_secs()) > t);
                }
                if self.gossip_seen.len() < GOSSIP_SEEN_MAX {
                    self.gossip_seen.insert(k, rec.expires);
                }
                true
            }
        }
    }

    fn identify_dial_allowed(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        self.identify_dial_at
            .retain(|_, at| now.duration_since(*at) < Duration::from_secs(60));
        if self.identify_dial_at.len() >= 4096 && !self.identify_dial_at.contains_key(&peer) {
            return false;
        }
        if self
            .identify_dial_at
            .get(&peer)
            .is_some_and(|at| now.duration_since(*at) < Duration::from_secs(5))
        {
            return false;
        }
        self.identify_dial_at.insert(peer, now);
        true
    }

    fn gossip_rate_ok(&mut self, peer: PeerId, topic: &str) -> bool {
        let now = Instant::now();
        let key = (peer, topic.to_string());
        if self.gossip_rate.len() >= GOSSIP_RATE_MAX && !self.gossip_rate.contains_key(&key) {
            self.gossip_rate
                .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(10));
            if self.gossip_rate.len() >= GOSSIP_RATE_MAX {
                return false;
            }
        }
        let state = self.gossip_rate.entry(key).or_insert((now, 0));
        if now.duration_since(state.0) >= Duration::from_secs(1) {
            *state = (now, 0);
        }
        if state.1 >= GOSSIP_PER_PEER_TOPIC_PER_SEC {
            return false;
        }
        state.1 += 1;
        true
    }

    fn store_source(&self, peer: PeerId) -> Option<store::StoreSource> {
        self.conns
            .get(&peer)?
            .values()
            .find_map(discovery::ip_of)
            .map(store::StoreSource::Ip)
    }

    fn on_mesh_peer(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        let new = self.mesh_peers.insert(peer);
        if let Some(c) = self.cache.as_mut() {
            c.seen(peer, addrs);
        }
        if let Some(via) = self.seeds.remove(&peer) {
            self.emit(Event::Discovered { peer, via });
        }
        let now = Instant::now();
        if new && now >= self.mesh_bootstrap_at {
            self.mesh_bootstrap_at = now + MESH_BOOTSTRAP_EVERY;
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }
    }

    fn finish_find(&mut self, find: u64, expired: bool) {
        let Some(st) = self.finds.remove(&find) else {
            return;
        };
        for q in &st.queries {
            self.pending.remove(q);
            if let Some(mut q) = self.swarm.behaviour_mut().kad.query_mut(q) {
                q.finish();
            }
        }
        let r = if st.complete && expired {
            Err(anyhow!("find timed out"))
        } else {
            Ok((st.out, st.missing))
        };
        let _ = st.reply.send(r);
    }

    fn on_tick(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .finds
            .iter()
            .filter(|(_, f)| now >= f.deadline)
            .map(|(k, _)| *k)
            .collect();
        for f in expired {
            self.finish_find(f, true);
        }
        for i in 0..self.anchors.len() {
            let p = self.anchors[i].peer;
            if self.connected(&p) || self.dialing(&p) || now < self.anchors[i].next {
                continue;
            }
            let a = &mut self.anchors[i];
            a.next = now + a.backoff;
            a.backoff = (a.backoff * 2).min(ANCHOR_BACKOFF_MAX);
            let addr = a.addr.clone();
            let _ = self.swarm.dial(addr);
        }
        self.discovery_tick(now);
        self.purge(now);
        let window = self.cfg.tunnel_reconnect_window;
        let peers: Vec<PeerId> = self.tunnels.keys().copied().collect();
        for peer in peers {
            let best = self.best_conn(&peer).map(|(_, r)| r);
            let lower = self.me < peer;
            let Some(t) = self.tunnels.get_mut(&peer) else {
                continue;
            };
            if t.opening.is_some() || now < t.retry_at {
                continue;
            }
            if t.streams.is_empty() {
                if now.duration_since(t.down_since) > window {
                    self.drop_tunnel(peer, "peer unreachable", false);
                    continue;
                }
                t.retry_at = now + t.backoff;
                t.backoff = (t.backoff * 2).min(TUNNEL_BACKOFF_MAX);
                self.start_open(peer);
            } else if lower && best > t.top() {
                t.retry_at = now + Duration::from_secs(1);
                self.start_open(peer);
            }
        }
    }

    fn on_kad(&mut self, ev: kad::Event) {
        use kad::store::RecordStore;
        match ev {
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => self.on_query(id, result, step.last),
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(r),
                        source,
                        ..
                    },
            } => {
                let Some(rec) = Record::verify(&r.value)
                    .filter(|rec| r.key == record_key(&rec.topic, &rec.publisher))
                else {
                    tracing::debug!(%source, "dropping unverified kad record");
                    return;
                };
                let peers: Vec<_> = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .kbuckets()
                    .flat_map(|bucket| {
                        bucket
                            .iter()
                            .map(|entry| *entry.node.key.preimage())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                if !record_store_allowed(&r.key, self.me, &peers) {
                    return;
                }
                let source_peer = source;
                let source_bucket = self.store_source(source_peer);
                let store = self.swarm.behaviour_mut().kad.store_mut();
                let newer = store
                    .get(&r.key)
                    .and_then(|old| Record::verify(&old.value))
                    .is_some_and(|old| old.expires > rec.expires);
                if newer {
                    tracing::debug!(%source, "dropping kad record older than the stored one");
                    return;
                }
                if let Err(e) = store.put_foreign_from(r, source_peer, source_bucket) {
                    tracing::debug!(%source_peer, "kad record not stored: {e}");
                }
            }
            kad::Event::InboundRequest {
                request: kad::InboundRequest::AddProvider { record: Some(r) },
            } => {
                let source = self.store_source(r.provider);
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .store_mut()
                    .add_foreign_provider_from(r, source)
                {
                    tracing::debug!("kad provider not stored: {e}");
                }
            }
            _ => {}
        }
    }

    fn on_query(&mut self, id: kad::QueryId, result: kad::QueryResult, last: bool) {
        let Some(p) = self.pending.remove(&id) else {
            return;
        };
        match (p, result) {
            (Pending::PutRecord { reply }, kad::QueryResult::PutRecord(r)) => {
                let _ = reply.send(r.map(|_| ()).map_err(|e| anyhow!("put_record: {e:?}")));
            }
            (
                Pending::Providers {
                    find,
                    topic,
                    mut found,
                },
                kad::QueryResult::GetProviders(r),
            ) => {
                if !self.finds.contains_key(&find) {
                    return;
                }
                let mut new = Vec::new();
                if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = r {
                    let mut providers: Vec<_> = providers.into_iter().collect();
                    providers.sort_by_key(|peer| {
                        !(self.allowed.contains(peer)
                            || self.good_peers.contains(peer)
                            || self.anchors.iter().any(|anchor| anchor.peer == *peer)
                            || self.connected(peer))
                    });
                    for p in providers {
                        if found.contains(&p) {
                            continue;
                        }
                        if found.len() < MAX_FIND_PROVIDERS {
                            found.insert(p);
                            new.push(p);
                        } else {
                            if let Some(st) = self.finds.get_mut(&find) {
                                st.truncated = true;
                            }
                        }
                    }
                }
                let mut queries = Vec::new();
                for publisher in &new {
                    let qid = self
                        .swarm
                        .behaviour_mut()
                        .kad
                        .get_record(record_key(&topic, publisher));
                    self.pending.insert(
                        qid,
                        Pending::GetRecord {
                            find,
                            topic: topic.clone(),
                            publisher: *publisher,
                        },
                    );
                    queries.push(qid);
                }
                let Some(st) = self.finds.get_mut(&find) else {
                    return;
                };
                st.left += queries.len();
                st.queries.extend(queries);
                if !last {
                    self.pending
                        .insert(id, Pending::Providers { find, topic, found });
                    return;
                }
                st.searching = false;
                if st.left == 0 {
                    self.finish_find(find, false);
                }
            }
            (
                Pending::GetRecord {
                    find,
                    topic,
                    publisher,
                },
                kad::QueryResult::GetRecord(r),
            ) => {
                let rec = match r {
                    Ok(kad::GetRecordOk::FoundRecord(pr)) => Record::verify(&pr.record.value)
                        .filter(|rec| rec.topic == topic && rec.publisher == publisher),
                    _ => None,
                };
                if rec.is_none() && !last {
                    self.pending.insert(
                        id,
                        Pending::GetRecord {
                            find,
                            topic,
                            publisher,
                        },
                    );
                    return;
                }
                if let Some(mut q) = self.swarm.behaviour_mut().kad.query_mut(&id) {
                    q.finish();
                }
                let Some(st) = self.finds.get_mut(&find) else {
                    return;
                };
                if rec.is_none() {
                    st.missing.push(publisher);
                }
                st.out.extend(rec);
                st.left = st.left.saturating_sub(1);
                if st.left == 0 && !st.searching {
                    self.finish_find(find, false);
                }
            }
            (Pending::Closest { peer }, kad::QueryResult::GetClosestPeers(r)) => {
                self.closest.remove(&peer);
                let peers = match r {
                    Ok(ok) => ok.peers,
                    Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                };
                let addrs: Vec<Multiaddr> = peers
                    .into_iter()
                    .filter(|i| i.peer_id == peer)
                    .flat_map(|i| i.addrs)
                    .collect();
                let mut addrs = self.swarm.behaviour_mut().kad.dialable(&peer, addrs);
                addrs.sort_by_key(|a| !is_quic(a));
                if self.connected(&peer) {
                    for r in self.dials.remove(&peer).unwrap_or_default() {
                        let _ = r.send(Ok(()));
                    }
                    return;
                }
                let opts = DialOpts::peer_id(peer)
                    .addresses(addrs)
                    .extend_addresses_through_behaviour()
                    .build();
                if let Err(e) = self.swarm.dial(opts) {
                    if !self.dialing(&peer) {
                        self.fail_dials(&peer, format!("dial: {e}"));
                    }
                }
            }
            (p, _) => {
                if !last {
                    self.pending.insert(id, p);
                }
            }
        }
    }

    fn on_swarm(&mut self, ev: SwarmEvent<BehaviourEvent>) {
        match ev {
            SwarmEvent::NewListenAddr { address, .. } => self.emit(Event::Listening(address)),
            SwarmEvent::Dialing {
                peer_id: Some(p),
                connection_id,
            } => {
                self.in_flight.entry(p).or_default().insert(connection_id);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let addr = endpoint.get_remote_address().clone();
                let scope = addr_scope(&addr);
                let local_only = !self.cfg.listen.is_empty()
                    && self
                        .cfg
                        .listen
                        .iter()
                        .all(|listen| addr_scope(listen) == Scope::Loopback);
                if scope == Scope::Public || (local_only && scope == Scope::Loopback) {
                    let base = split_peer(&addr)
                        .map(|(_, base)| base)
                        .unwrap_or_else(|| addr.clone());
                    if self.mesh_peers.contains(&peer_id)
                        || self.anchors.iter().any(|anchor| anchor.peer == peer_id)
                        || (local_only && scope == Scope::Loopback)
                    {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, base.clone());
                    }
                    if scope == Scope::Public {
                        if let Some(ipfs) = self.swarm.behaviour_mut().ipfs.as_mut() {
                            ipfs.kad.add_address(&peer_id, base);
                        }
                    }
                }
                self.done_dialing(&peer_id, connection_id);
                self.conns
                    .entry(peer_id)
                    .or_default()
                    .insert(connection_id, addr.clone());
                for r in self.dials.remove(&peer_id).unwrap_or_default() {
                    let _ = r.send(Ok(()));
                }
                if let Some(a) = self.anchors.iter_mut().find(|a| a.peer == peer_id) {
                    a.backoff = ANCHOR_BACKOFF;
                    a.next = Instant::now();
                    if self.cfg.bootstrap.contains(&a.addr) {
                        let _ = self.swarm.behaviour_mut().kad.bootstrap();
                    }
                }
                if let Some(t) = self.tunnels.get_mut(&peer_id) {
                    if t.streams.is_empty() {
                        t.retry_at = Instant::now();
                    }
                }
                self.emit(Event::Connected {
                    peer: peer_id,
                    addr,
                });
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                if let Some(m) = self.conns.get_mut(&peer_id) {
                    m.remove(&connection_id);
                }
                if num_established == 0 {
                    self.conns.remove(&peer_id);
                    self.rec_peer_slots.remove(&peer_id);
                    self.peer_direct.remove(&peer_id);
                    self.mesh_peers.remove(&peer_id);
                    self.emit(Event::Disconnected { peer: peer_id });
                }
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(p),
                connection_id,
                error,
            } => {
                self.done_dialing(&p, connection_id);
                if !self.connected(&p) && !self.dialing(&p) && !self.closest.contains(&p) {
                    self.fail_dials(&p, format!("{error}"));
                }
                if let Some(via) = self.seeds.get(&p).copied() {
                    if !self.connected(&p) && !self.dialing(&p) {
                        self.emit(Event::DiscoveryDialFailed {
                            peer: p,
                            via,
                            error: format!("{error}"),
                        });
                    }
                }
            }
            SwarmEvent::Behaviour(b) => self.on_behaviour(b),
            _ => {}
        }
    }

    fn on_behaviour(&mut self, ev: BehaviourEvent) {
        match ev {
            BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                connection_id,
                info,
            }) => {
                let via = self
                    .conns
                    .get(&peer_id)
                    .and_then(|m| m.get(&connection_id))
                    .cloned();
                let lan = self.mdns_peers.contains(&peer_id);
                let good: Vec<Multiaddr> = info
                    .listen_addrs
                    .iter()
                    .map(|a| match split_peer(a) {
                        Some((p, base)) if p == peer_id => base,
                        _ => a.clone(),
                    })
                    .filter(|a| {
                        !is_unspecified(a) && !is_dns(a) && kad_addr_allowed(a, via.as_ref(), lan)
                    })
                    .collect();
                let obs = &info.observed_addr;
                if addr_scope(obs) == Scope::Public {
                    if let Some(voter) = via
                        .as_ref()
                        .and_then(discovery::ip_of)
                    {
                        if self.observed_votes.len() >= 32 && !self.observed_votes.contains_key(obs)
                        {
                            self.observed_votes.clear();
                        }
                        let votes = self.observed_votes.entry(obs.clone()).or_default();
                        votes.insert(voter);
                        if votes.len() >= 2 {
                            self.observed_ip4 = ip4_of(obs).or(self.observed_ip4);
                            if self.cfg.ipfs {
                                let obs = split_peer(obs)
                                    .map(|(_, b)| b)
                                    .unwrap_or_else(|| obs.clone());
                                self.ipfs_observed.retain(|a| *a != obs);
                                self.ipfs_observed.insert(0, obs);
                                self.ipfs_observed.truncate(4);
                            }
                        }
                    }
                }
                if info.protocols.contains(&discovery::IPFS_KAD_PROTO) {
                    if let Some(ipfs) = self.swarm.behaviour_mut().ipfs.as_mut() {
                        for a in good.iter().filter(|a| addr_scope(a) == Scope::Public) {
                            ipfs.kad.add_address(&peer_id, a.clone());
                        }
                    }
                }
                if info.protocols.contains(&KAD_PROTO) {
                    for a in &good {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, a.clone());
                    }
                } else {
                    self.swarm.behaviour_mut().kad.remove_peer(&peer_id);
                }
                if info.protocols.contains(&rpc::PROTO) {
                    let via_loopback = via
                        .as_ref()
                        .is_some_and(|v| addr_scope(v) == Scope::Loopback);
                    let direct: Vec<Multiaddr> = info
                        .listen_addrs
                        .iter()
                        .map(|a| match split_peer(a) {
                            Some((p, base)) if p == peer_id => base,
                            _ => a.clone(),
                        })
                        .filter(|a| !is_unspecified(a) && !is_dns(a))
                        .filter(|a| via_loopback || addr_scope(a) != Scope::Loopback)
                        .filter(|a| via_loopback || !is_ip6(a) || addr_scope(a) == Scope::Public)
                        .filter(|a| kad_addr_allowed(a, via.as_ref(), lan))
                        .take(MAX_DIRECT_DIAL)
                        .collect();
                    let has_quic = self.best_conn(&peer_id).is_some_and(|(_, r)| r >= 3);
                    let quic: Vec<Multiaddr> = direct.iter().filter(|a| is_quic(a)).cloned().collect();
                    if !has_quic
                        && !quic.is_empty()
                        && self.peer_direct.get(&peer_id) != Some(&direct)
                        && self.identify_dial_allowed(peer_id)
                    {
                        tracing::debug!(%peer_id, ?quic, "peer reachable over quic, dialing it");
                        let opts = DialOpts::peer_id(peer_id)
                            .addresses(quic)
                            .condition(PeerCondition::Always)
                            .build();
                        if let Err(e) = self.swarm.dial(opts) {
                            tracing::debug!(%peer_id, "quic dial failed: {e}");
                        }
                    }
                    self.peer_direct.insert(peer_id, direct);
                    self.on_mesh_peer(peer_id, good);
                }
            }
            BehaviourEvent::Ipfs(e) => self.on_ipfs(e),
            BehaviourEvent::Kad(e) => self.on_kad(e),
            BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                if let Some(rec) = Record::verify(&message.data) {
                    if gossipsub::IdentTopic::new(&rec.topic).hash() == message.topic
                        && self.gossip_rate_ok(propagation_source, &rec.topic)
                        && self.gossip_fresh(&rec)
                    {
                        let tx = self.topics.lock().unwrap().get(&rec.topic).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(rec);
                        }
                    }
                }
            }
            BehaviourEvent::Rec(pipe::Inbound { peer, stream, .. }) => self.serve_rec(peer, stream),
            BehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (p, a) in list {
                    self.mdns_peers.insert(p);
                    self.swarm.behaviour_mut().kad.allow_lan_peer(p, true);
                    self.swarm.behaviour_mut().kad.add_address(&p, a.clone());
                    let _ = self.swarm.dial(a);
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer, addr) in list {
                    self.mdns_peers.remove(&peer);
                    self.swarm.behaviour_mut().kad.allow_lan_peer(peer, false);
                    self.swarm.behaviour_mut().kad.remove_address(&peer, &addr);
                }
            }
            BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. }) => {
                let public = matches!(new, autonat::NatStatus::Public(_));
                if let Some(ipfs) = self.swarm.behaviour_mut().ipfs.as_mut() {
                    ipfs.kad.set_mode(Some(if public {
                        kad::Mode::Server
                    } else {
                        kad::Mode::Client
                    }));
                }
                self.emit(Event::Reachability { public });
            }
            BehaviourEvent::Pipe(pipe::Inbound { peer, conn, stream }) => {
                self.on_inbound(peer, conn, stream)
            }
            BehaviourEvent::Upnp(e) => {
                if let Some(ev) = upnp_note(&mut self.upnp_mapped, &mut self.upnp_failed, e) {
                    match &ev {
                        Event::UpnpMapped { addr } => tracing::info!("upnp mapped {addr}"),
                        Event::UpnpUnavailable { reason } => {
                            tracing::info!("upnp unavailable: {reason}")
                        }
                        _ => {}
                    }
                    self.emit(ev);
                }
            }
            BehaviourEvent::Rpc(pipe::Inbound { peer, conn, stream }) => {
                let bucket = self
                    .conns
                    .get(&peer)
                    .and_then(|m| m.get(&conn))
                    .and_then(discovery::ip_of)
                    .map(rpc::Bucket::Ip)
                    .unwrap_or(rpc::Bucket::Unknown);
                let trusted = self.allowed.contains(&peer) || self.good_peers.contains(&peer);
                match self.gate.admit_bucket(peer, bucket, trusted) {
                    Ok(permit) => {
                        tokio::spawn(rpc::serve(permit, stream, self.rpc_tx.clone()));
                    }
                    Err(why) => {
                        tracing::debug!(%peer, ?why, "rpc stream rejected");
                        drop(stream);
                    }
                }
            }
            _ => {}
        }
    }
}

fn upnp_note(mapped: &mut bool, failed: &mut bool, e: upnp::Event) -> Option<Event> {
    let fail = |failed: &mut bool, reason: &str| {
        if *failed {
            return None;
        }
        *failed = true;
        Some(Event::UpnpUnavailable {
            reason: reason.to_string(),
        })
    };
    match e {
        upnp::Event::NewExternalAddr { external_addr, .. } => {
            if *mapped {
                return None;
            }
            *mapped = true;
            Some(Event::UpnpMapped {
                addr: external_addr,
            })
        }
        upnp::Event::GatewayNotFound => fail(failed, "gateway not found"),
        upnp::Event::NonRoutableGateway => fail(failed, "gateway is not routable"),
        upnp::Event::ExpiredExternalAddr { external_addr, .. } => {
            tracing::debug!("upnp mapping expired: {external_addr}");
            None
        }
    }
}

fn is_dns(a: &Multiaddr) -> bool {
    a.iter().any(|p| {
        matches!(
            p,
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
        )
    })
}

fn is_unspecified(a: &Multiaddr) -> bool {
    a.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

/// Topic for one kind of record inside one game's namespace.
pub fn topic_for(namespace: &str, kind: &str) -> String {
    format!("{namespace}:{kind}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn identify_pushes_listen_addr_updates() {
        let c = identify_config(Keypair::generate_ed25519().public());
        assert!(c.hide_listen_addrs());
        assert!(c.push_listen_addr_updates());
        assert!(c.interval() <= Duration::from_secs(30));
    }

    #[test]
    fn foreign_record_storage_requires_local_kademlia_closeness() {
        let key = kad::RecordKey::new(&b"topic/publisher".to_vec());
        let me = PeerId::random();
        let target = kad::KBucketKey::new(key.clone());
        let local_distance = target.distance(&kad::KBucketKey::from(me));
        let mut peers = Vec::new();
        while peers.len() < 20 {
            let peer = PeerId::random();
            if target.distance(&kad::KBucketKey::from(peer)) < local_distance {
                peers.push(peer);
            }
        }
        assert!(!record_store_allowed(&key, me, &peers));
        peers.pop();
        assert!(record_store_allowed(&key, me, &peers));
    }

    #[test]
    fn kad_skips_private_addrs_unless_same_lan() {
        let public = ma("/ip4/1.2.3.4/tcp/1");
        let lan = ma("/ip4/192.168.1.9/tcp/1");
        let lo = ma("/ip4/127.0.0.1/tcp/1");
        let cgnat = ma("/ip4/100.64.0.1/tcp/1");
        let ula = ma("/ip6/fd00::1/udp/1/quic-v1");
        let via_wan = ma("/ip4/5.6.7.8/tcp/9");
        let via_lan = ma("/ip4/192.168.1.2/tcp/9");
        let via_lo = ma("/ip4/127.0.0.1/tcp/9");
        assert!(kad_addr_allowed(&public, Some(&via_wan), false));
        assert!(!kad_addr_allowed(&lan, Some(&via_wan), false));
        assert!(!kad_addr_allowed(&lo, Some(&via_wan), false));
        assert!(!kad_addr_allowed(&cgnat, Some(&via_wan), false));
        assert!(!kad_addr_allowed(&ula, Some(&via_wan), false));
        assert!(!kad_addr_allowed(&lan, None, false));
        assert!(kad_addr_allowed(&lan, Some(&via_wan), true));
        assert!(kad_addr_allowed(&lan, Some(&via_lan), false));
        assert!(!kad_addr_allowed(&lo, Some(&via_lan), false));
        assert!(!kad_addr_allowed(&lo, Some(&via_wan), true));
        assert!(kad_addr_allowed(&lo, Some(&via_lo), false));
    }

    #[test]
    fn direct_quic_ranks_above_tcp() {
        assert!(rank(&ma("/ip4/1.2.3.4/udp/1/quic-v1")) > rank(&ma("/ip4/1.2.3.4/tcp/1")));
    }

    #[test]
    fn global_ip4_skips_private_addresses() {
        let advertised = [
            ma("/ip4/192.168.1.20/udp/49551/quic-v1"),
            ma("/ip4/8.8.4.4/udp/65184/quic-v1"),
        ];
        assert_eq!(global_ip4_from(&advertised), Some("8.8.4.4".parse().unwrap()));
        assert_eq!(global_ip4_from([&advertised[0]]), None);
    }

    #[test]
    fn default_config_listens_on_ip4_and_ip6() {
        let c = Config::default();
        let s: Vec<String> = c.listen.iter().map(|a| a.to_string()).collect();
        for want in [
            "/ip4/0.0.0.0/udp/0/quic-v1",
            "/ip4/0.0.0.0/tcp/0",
            "/ip6/::/udp/0/quic-v1",
            "/ip6/::/tcp/0",
        ] {
            assert!(s.iter().any(|x| x == want), "missing {want} in {s:?}");
        }
    }

    #[test]
    fn ip6_filter_keeps_only_global() {
        let ok: Ipv6Addr = "2804:14c:5b80::1".parse().unwrap();
        assert!(global_ip6(&ok));
        assert_eq!(
            addr_scope(&ma("/ip6/2804:14c:5b80::1/udp/1/quic-v1")),
            Scope::Public
        );
        for bad in [
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "2001:0:4136:e378::1",
            "::1",
            "::",
            "ff02::1",
            "::ffff:1.2.3.4",
        ] {
            let ip: Ipv6Addr = bad.parse().unwrap();
            assert!(!global_ip6(&ip), "{bad} must not count as global");
        }
        assert!(!global_ip6(&"2001:db8::1".parse().unwrap()));
        assert!(!global_ip6(&"2001:2::1".parse().unwrap()));
        assert!(!global_ip6(&"2001:10::1".parse().unwrap()));
        assert!(!global_ip6(&"2001:20::1".parse().unwrap()));
        assert_eq!(addr_scope(&ma("/ip4/198.51.100.4/tcp/1")), Scope::Private);
        assert_eq!(addr_scope(&ma("/ip4/203.0.113.7/tcp/1")), Scope::Private);
        assert_eq!(
            addr_scope(&ma("/ip6/2001:0:4136:e378::1/tcp/1")),
            Scope::Private
        );
        assert_eq!(addr_scope(&ma("/ip6/fe80::1/tcp/1")), Scope::Private);
        assert!(!kad_addr_allowed(
            &ma("/ip6/2001:0:4136:e378::1/tcp/1"),
            Some(&ma("/ip4/5.6.7.8/tcp/1")),
            false
        ));
        assert!(kad_addr_allowed(
            &ma("/ip6/2804:14c:5b80::1/tcp/1"),
            Some(&ma("/ip4/5.6.7.8/tcp/1")),
            false
        ));
    }

    #[test]
    fn public_listeners_are_advertised_but_local_listeners_are_hidden() {
        assert!(identify_config(Keypair::generate_ed25519().public()).hide_listen_addrs());
        assert!(is_public_addr(&ma("/ip4/8.8.8.8/tcp/4001")));
        assert!(!is_public_addr(&ma("/ip4/192.168.1.2/tcp/4001")));
        assert!(!is_public_addr(&ma("/ip4/203.0.113.1/tcp/4001")));
    }

    #[test]
    fn network_bucket_groups_ipv4_prefixes() {
        let a = network_source_bucket(PeerId::random(), &[ma("/ip4/8.8.8.1/tcp/4001")]);
        let b = network_source_bucket(PeerId::random(), &[ma("/ip4/8.8.8.254/tcp/4001")]);
        assert_eq!(a, b);
        let p = PeerId::random();
        assert_eq!(network_source_bucket(p, &[]), format!("peer:{p}"));
    }

    #[test]
    fn upnp_reports_failure_and_mapping_once_each() {
        let (mut mapped, mut failed) = (false, false);
        let e = upnp_note(&mut mapped, &mut failed, upnp::Event::GatewayNotFound);
        assert!(
            matches!(e, Some(Event::UpnpUnavailable { ref reason }) if reason.contains("not found"))
        );
        assert!(upnp_note(&mut mapped, &mut failed, upnp::Event::GatewayNotFound).is_none());
        assert!(upnp_note(&mut mapped, &mut failed, upnp::Event::NonRoutableGateway).is_none());
        let (mut m2, mut f2) = (false, false);
        let e = upnp_note(&mut m2, &mut f2, upnp::Event::NonRoutableGateway);
        assert!(
            matches!(e, Some(Event::UpnpUnavailable { ref reason }) if reason.contains("routable"))
        );
        let ext = ma("/ip4/203.0.113.9/udp/4001/quic-v1");
        let ev = upnp::Event::NewExternalAddr {
            local_addr: ma("/ip4/192.168.1.2/udp/4001/quic-v1"),
            external_addr: ext.clone(),
        };
        assert!(
            matches!(upnp_note(&mut mapped, &mut failed, ev), Some(Event::UpnpMapped { ref addr }) if *addr == ext)
        );
        let again = upnp::Event::NewExternalAddr {
            local_addr: ma("/ip4/192.168.1.2/tcp/4001"),
            external_addr: ma("/ip4/203.0.113.9/tcp/4001"),
        };
        assert!(upnp_note(&mut mapped, &mut failed, again).is_none());
        let gone = upnp::Event::ExpiredExternalAddr {
            local_addr: ma("/ip4/192.168.1.2/tcp/4001"),
            external_addr: ext,
        };
        assert!(upnp_note(&mut mapped, &mut failed, gone).is_none());
    }
}
