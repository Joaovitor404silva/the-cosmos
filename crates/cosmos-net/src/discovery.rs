use crate::{Scope, addr_scope};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    core::{Endpoint, transport::PortUse},
    kad,
    multiaddr::Protocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
        behaviour::{ExternalAddrConfirmed, ExternalAddrExpired},
        dummy,
    },
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const IPFS_KAD_PROTO: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");
pub const PROVIDER_TTL: Duration = Duration::from_secs(48 * 3600);
pub const PROVIDER_REPUBLISH: Duration = Duration::from_secs(22 * 3600);
pub const CACHE_MAX_PEERS: usize = 64;
pub const CACHE_MAX_ADDRS: usize = 4;
pub const CACHE_EXPIRE: Duration = Duration::from_secs(7 * 86400);
const LIST_MAX_BYTES: u64 = 64 << 10;

const IPFS_BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
    "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

pub fn ipfs_bootstrap() -> Vec<Multiaddr> {
    IPFS_BOOTSTRAP
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

pub fn provider_key(topic: &str) -> kad::RecordKey {
    let digest = Sha256::digest(format!("cosmos/v1/{topic}").as_bytes());
    let mut k = vec![0x12, 0x20];
    k.extend_from_slice(&digest);
    kad::RecordKey::new(&k)
}

pub fn parse_list(body: &str) -> Vec<Multiaddr> {
    parse_list_inner(body, false)
}

fn parse_list_inner(body: &str, allow_loopback: bool) -> Vec<Multiaddr> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<Multiaddr>().ok())
        .filter(|a| matches!(a.iter().last(), Some(Protocol::P2p(_))))
        .filter(|a| !crate::is_dns(a))
        .filter(|a| {
            addr_scope(a) == Scope::Public || (allow_loopback && addr_scope(a) == Scope::Loopback)
        })
        .collect()
}

pub fn fetch_list_blocking(url: &str) -> anyhow::Result<Vec<Multiaddr>> {
    anyhow::ensure!(
        url.starts_with("https://") || local_http_url(url),
        "bootstrap list requires HTTPS"
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let mut resp = agent.get(url).call()?;
    let body = resp
        .body_mut()
        .with_config()
        .limit(LIST_MAX_BYTES)
        .read_to_string()?;
    let local = local_http_url(url);
    Ok(parse_list_inner(&body, local))
}

fn local_http_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    matches!(host, "127.0.0.1" | "::1") && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct PeerCache {
    path: PathBuf,
    peers: HashMap<PeerId, (u64, Vec<Multiaddr>, bool)>,
    dirty: bool,
}

fn rank(e: &(u64, Vec<Multiaddr>, bool)) -> (bool, u64) {
    (e.2, e.0)
}

impl PeerCache {
    pub fn load(path: PathBuf) -> Self {
        let mut peers = HashMap::new();
        let now = unix_now();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let (Some(t), Some(p)) = (it.next(), it.next()) else {
                    continue;
                };
                let (Ok(t), Ok(p)) = (t.parse::<u64>(), p.parse::<PeerId>()) else {
                    continue;
                };
                if t.saturating_add(CACHE_EXPIRE.as_secs()) < now {
                    continue;
                }
                let mut it = it.peekable();
                let good = it.next_if_eq(&"+").is_some();
                let addrs: Vec<Multiaddr> = it
                    .filter_map(|a| a.parse().ok())
                    .take(CACHE_MAX_ADDRS)
                    .collect();
                if !addrs.is_empty() {
                    peers.insert(p, (t, addrs, good));
                }
            }
        }
        let mut c = PeerCache {
            path,
            peers,
            dirty: false,
        };
        c.evict();
        c
    }

    pub fn entries(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        let mut v: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, e)| e.2)
            .map(|(p, e)| {
                let addrs: Vec<_> =
                    e.1.iter()
                        .filter(|addr| {
                            !crate::is_dns(addr)
                                && matches!(addr_scope(addr), Scope::Public | Scope::Loopback)
                        })
                        .cloned()
                        .collect();
                (rank(e), *p, addrs)
            })
            .filter(|(_, _, addrs)| !addrs.is_empty())
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v.into_iter().map(|(_, p, a)| (p, a)).collect()
    }

    pub fn good(&mut self, peer: PeerId) {
        if let Some(e) = self.peers.get_mut(&peer) {
            if !e.2 {
                e.2 = true;
                self.dirty = true;
            }
        }
    }

    fn oldest(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .min_by_key(|(_, e)| rank(e))
            .map(|(p, _)| *p)
    }

    pub fn seen(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        if addrs.is_empty() {
            return;
        }
        let now = unix_now();
        if !self.peers.contains_key(&peer) && self.peers.len() >= CACHE_MAX_PEERS {
            if let Some(old) = self.oldest() {
                self.peers.remove(&old);
            }
        }
        let e = self.peers.entry(peer).or_insert((now, vec![], false));
        let mut merged = addrs;
        for a in e.1.drain(..) {
            if !merged.contains(&a) {
                merged.push(a);
            }
        }
        merged.truncate(CACHE_MAX_ADDRS);
        if e.1 != merged || now.saturating_sub(e.0) > 60 {
            self.dirty = true;
        }
        *e = (now, merged, e.2);
    }

    fn evict(&mut self) {
        while self.peers.len() > CACHE_MAX_PEERS {
            let Some(old) = self.oldest() else { break };
            self.peers.remove(&old);
            self.dirty = true;
        }
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let mut out = String::new();
        for (p, (t, addrs, good)) in &self.peers {
            if !good {
                continue;
            }
            out.push_str(&format!("{t} {p}"));
            if *good {
                out.push_str(" +");
            }
            for a in addrs {
                out.push(' ');
                out.push_str(&a.to_string());
            }
            out.push('\n');
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConnLimits {
    pub max_established: u32,
    pub max_established_incoming: u32,
    pub max_established_per_peer: u32,
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_inbound_per_ip: usize,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            max_established: 192,
            max_established_incoming: 64,
            max_established_per_peer: 8,
            max_pending_incoming: 32,
            max_pending_outgoing: 64,
            max_inbound_per_ip: 8,
        }
    }
}

impl ConnLimits {
    pub fn libp2p(&self) -> libp2p::connection_limits::ConnectionLimits {
        libp2p::connection_limits::ConnectionLimits::default()
            .with_max_established(Some(self.max_established))
            .with_max_established_incoming(Some(self.max_established_incoming))
            .with_max_established_per_peer(Some(self.max_established_per_peer))
            .with_max_pending_incoming(Some(self.max_pending_incoming))
            .with_max_pending_outgoing(Some(self.max_pending_outgoing))
    }
}

pub fn ip_of(a: &Multiaddr) -> Option<IpAddr> {
    a.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(
            ip.to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
        ),
        _ => None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ConnSource {
    Ip(IpAddr),
    Unknown,
}

fn conn_source(addr: &Multiaddr) -> ConnSource {
    ip_of(addr)
        .map(ConnSource::Ip)
        .unwrap_or(ConnSource::Unknown)
}

/// (ip, port, udp) of a socket.
type Hole = (IpAddr, u16, bool);

/// How long a simulated NAT keeps a mapping open after an outbound packet.
const HOLE_TTL: Duration = Duration::from_secs(10);
const HOLES_MAX: usize = 4096;

fn hole_of(a: &Multiaddr) -> Option<Hole> {
    let ip = ip_of(a)?;
    a.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some((ip, port, false)),
        Protocol::Udp(port) => Some((ip, port, true)),
        _ => None,
    })
}

pub struct IpLimit {
    max: usize,
    blocked: Arc<Mutex<HashSet<PeerId>>>,
    pending: HashMap<ConnectionId, ConnSource>,
    established: HashMap<ConnectionId, ConnSource>,
    /// `Some` when simulating a NAT: sockets we dialed recently.
    holes: Option<HashMap<Hole, Instant>>,
}

impl IpLimit {
    pub fn new(max: usize, blocked: Arc<Mutex<HashSet<PeerId>>>, nat_sim: bool) -> Self {
        IpLimit {
            max,
            blocked,
            pending: HashMap::new(),
            established: HashMap::new(),
            holes: nat_sim.then(HashMap::new),
        }
    }

    fn open_hole(&mut self, a: &Multiaddr) {
        let (Some(holes), Some(h)) = (self.holes.as_mut(), hole_of(a)) else {
            return;
        };
        if holes.len() >= HOLES_MAX {
            holes.retain(|_, at| at.elapsed() < HOLE_TTL);
        }
        if holes.len() < HOLES_MAX {
            holes.insert(h, Instant::now());
        }
    }

    fn deny_unsolicited(&self, remote: &Multiaddr) -> Result<(), ConnectionDenied> {
        let Some(holes) = &self.holes else {
            return Ok(());
        };
        let open = hole_of(remote)
            .and_then(|h| holes.get(&h))
            .is_some_and(|at| at.elapsed() < HOLE_TTL);
        if open {
            Ok(())
        } else {
            Err(ConnectionDenied::new("simulated nat: unsolicited inbound"))
        }
    }

    fn deny_blocked(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        if self.blocked.lock().unwrap().contains(peer) {
            return Err(ConnectionDenied::new("connections to this peer are blocked"));
        }
        Ok(())
    }

    fn count(&self, source: ConnSource) -> usize {
        self.pending
            .values()
            .chain(self.established.values())
            .filter(|x| **x == source)
            .count()
    }
}

impl NetworkBehaviour for IpLimit {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.deny_unsolicited(remote)?;
        let source = conn_source(remote);
        if self.count(source) >= self.max {
            return Err(ConnectionDenied::new(format!(
                "inbound limit of {} reached for {source:?}",
                self.max
            )));
        }
        self.pending.insert(id, source);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _local: &Multiaddr,
        _remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.deny_blocked(&peer)?;
        if let Some(ip) = self.pending.remove(&id) {
            self.established.insert(id, ip);
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _id: ConnectionId,
        _peer: Option<PeerId>,
        addrs: &[Multiaddr],
        _role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        for a in addrs {
            self.open_hole(a);
        }
        Ok(vec![])
    }

    fn handle_established_outbound_connection(
        &mut self,
        _id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _role: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.deny_blocked(&peer)?;
        self.open_hole(addr);
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(c) => {
                self.established.remove(&c.connection_id);
                self.pending.remove(&c.connection_id);
            }
            FromSwarm::ListenFailure(f) => {
                self.pending.remove(&f.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _id: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        match ev {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

type Kad = kad::Behaviour<kad::store::MemoryStore>;

pub struct Announce {
    pub kad: Kad,
    extra: Vec<Multiaddr>,
    dns_peers: HashSet<PeerId>,
    dial_candidates: HashMap<PeerId, (Instant, Vec<Multiaddr>)>,
}

impl Announce {
    pub fn new(kad: Kad, dns_peers: HashSet<PeerId>) -> Self {
        Announce {
            kad,
            extra: vec![],
            dns_peers,
            dial_candidates: HashMap::new(),
        }
    }

    pub fn dial_candidates(&self, peer: &PeerId) -> &[Multiaddr] {
        self.dial_candidates
            .get(peer)
            .filter(|(at, _)| at.elapsed() < Duration::from_secs(300))
            .map(|(_, addrs)| addrs.as_slice())
            .unwrap_or(&[])
    }

    pub fn set_announced(&mut self, addrs: Vec<Multiaddr>) -> bool {
        if addrs == self.extra {
            return false;
        }
        for a in self.extra.iter().filter(|a| !addrs.contains(a)) {
            self.kad
                .on_swarm_event(FromSwarm::ExternalAddrExpired(ExternalAddrExpired {
                    addr: a,
                }));
        }
        for a in addrs.iter().filter(|a| !self.extra.contains(a)) {
            self.kad
                .on_swarm_event(FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
                    addr: a,
                }));
        }
        self.extra = addrs;
        true
    }
}

impl NetworkBehaviour for Announce {
    type ConnectionHandler = <Kad as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = kad::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.kad
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.kad
            .handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addrs: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let mut addresses = self
            .kad
            .handle_pending_outbound_connection(id, peer, addrs, role)?;
        addresses.retain(|addr| {
            let dns = addr.iter().any(|protocol| matches!(protocol, Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)));
            let dns_allowed = !dns
                || peer.is_some_and(|peer| self.dns_peers.contains(&peer));
            dns_allowed && crate::addr_scope(addr) == crate::Scope::Public
        });
        if let Some(peer) = peer {
            let direct: Vec<_> = addresses
                .iter()
                .chain(addrs)
                .filter(|addr| crate::is_public_addr(addr))
                .take(8)
                .cloned()
                .collect();
            if !direct.is_empty() {
                if self.dial_candidates.len() >= CACHE_MAX_PEERS
                    && !self.dial_candidates.contains_key(&peer)
                {
                    if let Some(oldest) = self.dial_candidates
                        .iter()
                        .min_by_key(|(_, (at, _))| *at)
                        .map(|(peer, _)| *peer)
                    {
                        self.dial_candidates.remove(&oldest);
                    }
                }
                self.dial_candidates.insert(peer, (Instant::now(), direct));
            }
        }
        Ok(addresses)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.kad
            .handle_established_outbound_connection(id, peer, addr, role, port_use)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.kad.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        self.kad.on_connection_handler_event(peer, id, ev)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.kad.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_inbound_limits_bound_public_connection_fan_in() {
        let limits = ConnLimits::default();
        assert_eq!(limits.max_established_incoming, 64);
        assert_eq!(limits.max_inbound_per_ip, 8);
    }

    #[test]
    fn public_dht_does_not_supply_private_dial_targets() {
        let me = PeerId::random();
        let peer = PeerId::random();
        let config = kad::Config::new(IPFS_KAD_PROTO);
        let inner = kad::Behaviour::with_config(me, kad::store::MemoryStore::new(me), config);
        let mut announce = Announce::new(inner, HashSet::new());
        let public: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        for text in [
            "/ip4/192.168.1.1/tcp/80",
            "/ip4/127.0.0.1/tcp/22",
            "/ip4/169.254.169.254/tcp/80",
            "/ip4/224.0.0.1/tcp/80",
            "/ip6/fe80::1/tcp/80",
        ] {
            announce.kad.add_address(&peer, text.parse().unwrap());
        }
        announce.kad.add_address(&peer, public.clone());
        let addresses = announce
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(peer),
                &[],
                Endpoint::Dialer,
            )
            .unwrap();
        assert_eq!(addresses, vec![public.with(Protocol::P2p(peer))]);
    }

    #[test]
    fn discovery_candidates_survive_empty_updates_and_exclude_private_ips() {
        let me = PeerId::random();
        let peer = PeerId::random();
        let inner = kad::Behaviour::with_config(
            me,
            kad::store::MemoryStore::new(me),
            kad::Config::new(IPFS_KAD_PROTO),
        );
        let mut announce = Announce::new(inner, HashSet::new());
        let public: Multiaddr = "/ip4/186.205.17.114/udp/50127/quic-v1".parse().unwrap();
        let private: Multiaddr = "/ip4/192.168.0.11/tcp/63014".parse().unwrap();
        announce.handle_pending_outbound_connection(
            ConnectionId::new_unchecked(1), Some(peer),
            &[private, public.clone()], Endpoint::Dialer,
        ).unwrap();
        assert_eq!(announce.dial_candidates(&peer), &[public.clone()]);
        announce.handle_pending_outbound_connection(
            ConnectionId::new_unchecked(2), Some(peer), &[], Endpoint::Dialer,
        ).unwrap();
        assert_eq!(announce.dial_candidates(&peer), &[public]);
        announce.dial_candidates.get_mut(&peer).unwrap().0 =
            Instant::now() - Duration::from_secs(301);
        assert!(announce.dial_candidates(&peer).is_empty());
    }

    #[test]
    fn ipfs_dns_bootstraps_must_be_configured() {
        let me = PeerId::random();
        let peer = PeerId::random();
        let mut inner = kad::Behaviour::with_config(
            me,
            kad::store::MemoryStore::new(me),
            kad::Config::new(IPFS_KAD_PROTO),
        );
        let addr: Multiaddr = format!("/dns4/bootstrap.example/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        inner.add_address(&peer, addr.clone());
        let mut untrusted = Announce::new(inner, HashSet::new());
        assert!(
            untrusted
                .handle_pending_outbound_connection(
                    ConnectionId::new_unchecked(1),
                    Some(peer),
                    &[addr.clone()],
                    Endpoint::Dialer
                )
                .unwrap()
                .is_empty()
        );
        let mut inner = kad::Behaviour::with_config(
            me,
            kad::store::MemoryStore::new(me),
            kad::Config::new(IPFS_KAD_PROTO),
        );
        inner.add_address(&peer, addr.clone());
        let mut configured = Announce::new(inner, [peer].into_iter().collect());
        assert_eq!(
            configured
                .handle_pending_outbound_connection(
                    ConnectionId::new_unchecked(2),
                    Some(peer),
                    &[addr.clone()],
                    Endpoint::Dialer
                )
                .unwrap(),
            vec![addr]
        );
    }

    #[test]
    fn provider_key_is_sha256_multihash() {
        let k = provider_key("global");
        assert_eq!(k.as_ref().len(), 34);
        assert_eq!(&k.as_ref()[..2], &[0x12, 0x20]);
        assert_ne!(provider_key("a"), provider_key("b"));
    }

    #[test]
    fn list_parser_keeps_only_peer_addrs() {
        let p = PeerId::random();
        let body = format!(
            "# list\n\n/ip4/1.2.3.4/tcp/1/p2p/{p}\n/ip4/1.2.3.4/tcp/2\ngarbage\n  /dns4/x.org/udp/3/quic-v1/p2p/{p}  \n"
        );
        assert_eq!(parse_list(&body).len(), 1);
    }

    #[test]
    fn peer_cache_caps_and_expires() {
        let path = std::env::temp_dir().join(format!("cosmos-cache-unit-{}.peers", PeerId::random()));
        let old = PeerId::random();
        std::fs::write(&path, format!("1 {old} /ip4/1.2.3.4/tcp/1\n")).unwrap();
        let mut c = PeerCache::load(path.clone());
        assert!(c.entries().is_empty());
        for i in 0..(CACHE_MAX_PEERS + 10) {
            let a: Multiaddr = format!("/ip4/1.2.3.4/tcp/{}", i + 1).parse().unwrap();
            c.seen(PeerId::random(), vec![a; 1]);
        }
        let p = PeerId::random();
        let addrs: Vec<Multiaddr> = (1..10)
            .map(|i| format!("/ip4/5.6.7.8/tcp/{i}").parse().unwrap())
            .collect();
        c.seen(p, addrs);
        c.good(p);
        c.save().unwrap();
        let back = PeerCache::load(path.clone());
        assert!(back.entries().len() <= CACHE_MAX_PEERS);
        let mine = back
            .entries()
            .into_iter()
            .find(|(q, _)| *q == p)
            .expect("newest kept");
        assert_eq!(mine.1.len(), CACHE_MAX_ADDRS);
        let _ = std::fs::remove_file(path);
    }
}
