use crate::store::Store;
use crate::{Scope, addr_scope, is_dns};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    kad,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll};

type Inner = kad::Behaviour<Store>;

pub struct Kad {
    inner: Inner,
    scopes: HashMap<ConnectionId, (PeerId, Scope)>,
    lan_peers: HashSet<PeerId>,
    local_only: bool,
    relay_only: bool,
    dns_peers: std::collections::HashSet<PeerId>,
}

impl Deref for Kad {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}

impl DerefMut for Kad {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }
}

impl Kad {
    pub fn new(
        inner: Inner,
        local_only: bool,
        relay_only: bool,
        dns_peers: std::collections::HashSet<PeerId>,
    ) -> Self {
        Kad {
            inner,
            scopes: HashMap::new(),
            lan_peers: HashSet::new(),
            local_only,
            relay_only,
            dns_peers,
        }
    }

    pub fn allow_lan_peer(&mut self, peer: PeerId, allowed: bool) {
        if allowed {
            self.lan_peers.insert(peer);
        } else {
            self.lan_peers.remove(&peer);
        }
    }

    fn reaches(&self, peer: &PeerId, s: Scope) -> bool {
        self.scopes.values().any(|(p, c)| {
            p == peer
                && match s {
                    Scope::Public => true,
                    Scope::Loopback => *c == Scope::Loopback,
                    Scope::Private => matches!(c, Scope::Private | Scope::Loopback),
                }
        })
    }

    pub fn dialable(&mut self, peer: &PeerId, addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
        if self.relay_only {
            return addrs
                .into_iter()
                .filter(|addr| {
                    crate::is_relayed(addr)
                        && (addr_scope(addr) == Scope::Public
                            || crate::circuit_relay(addr)
                                .is_some_and(|relay| self.dns_peers.contains(&relay)))
                        && (!is_dns(addr)
                            || crate::circuit_relay(addr)
                                .is_some_and(|relay| self.dns_peers.contains(&relay)))
                })
                .collect();
        }
        addrs
            .into_iter()
            .filter(|a| {
                if let Some(relay) = crate::circuit_relay(a) {
                    return self.dns_peers.contains(&relay);
                }
                let s = addr_scope(a);
                (!is_dns(a)
                    || self.dns_peers.contains(peer)
                    || crate::circuit_relay(a).is_some_and(|relay| self.dns_peers.contains(&relay)))
                    && (s == Scope::Public
                        || (self.local_only && s == Scope::Loopback)
                        || (self.lan_peers.contains(peer) && s == Scope::Private)
                        || self.reaches(peer, s))
            })
            .collect()
    }
}

impl NetworkBehaviour for Kad {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = kad::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let h = self
            .inner
            .handle_established_inbound_connection(id, peer, local, remote)?;
        self.scopes.insert(id, (peer, addr_scope(remote)));
        Ok(h)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addrs: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let out = self
            .inner
            .handle_pending_outbound_connection(id, peer, addrs, role)?;
        Ok(match peer {
            Some(p) => self.dialable(&p, out),
            None => out,
        })
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let h = self
            .inner
            .handle_established_outbound_connection(id, peer, addr, role, port_use)?;
        self.scopes.insert(id, (peer, addr_scope(addr)));
        Ok(h)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match &event {
            FromSwarm::ConnectionClosed(c) => {
                self.scopes.remove(&c.connection_id);
            }
            FromSwarm::DialFailure(f) => {
                self.scopes.remove(&f.connection_id);
            }
            FromSwarm::ListenFailure(f) => {
                self.scopes.remove(&f.connection_id);
            }
            _ => {}
        }
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, ev)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::StreamProtocol;

    #[test]
    fn find_node_lan_addrs_need_a_lan_connection() {
        let me = PeerId::random();
        let inner = kad::Behaviour::with_config(
            me,
            Store::new(me, 1 << 16),
            kad::Config::new(StreamProtocol::new("/t/kad")),
        );
        let mut k = Kad::new(inner, false, false, Default::default());
        let p = PeerId::random();
        let public: Multiaddr = "/ip4/1.2.3.4/tcp/1".parse().unwrap();
        let lan: Multiaddr = "/ip4/192.168.1.5/tcp/80".parse().unwrap();
        let lo: Multiaddr = "/ip4/127.0.0.1/tcp/22".parse().unwrap();
        k.scopes
            .insert(ConnectionId::new_unchecked(1), (p, Scope::Public));
        assert_eq!(
            k.dialable(&p, vec![public.clone(), lan.clone(), lo.clone()]),
            vec![public.clone()]
        );
        k.inner.add_address(&p, lan.clone());
        assert!(k.dialable(&p, vec![lan.clone(), lo.clone()]).is_empty());
        k.allow_lan_peer(p, true);
        assert_eq!(
            k.dialable(&p, vec![lan.clone(), lo.clone()]),
            vec![lan.clone()]
        );
        k.scopes
            .insert(ConnectionId::new_unchecked(2), (p, Scope::Loopback));
        assert!(
            k.dialable(&PeerId::random(), vec![lan.clone(), lo.clone()])
                .is_empty()
        );
        assert_eq!(k.dialable(&p, vec![lan.clone(), lo.clone()]), vec![lan, lo]);
    }

    #[test]
    fn dht_dns_dials_are_restricted_to_configured_bootstrap_peers() {
        let me = PeerId::random();
        let inner = kad::Behaviour::with_config(
            me,
            Store::new(me, 1 << 16),
            kad::Config::new(StreamProtocol::new("/t/kad")),
        );
        let configured = PeerId::random();
        let stranger = PeerId::random();
        let mut allowed = Kad::new(inner, false, false, [configured].into_iter().collect());
        let configured_dns: Multiaddr =
            format!("/dns4/bootstrap.example/tcp/4001/p2p/{configured}")
                .parse()
                .unwrap();
        let stranger_dns: Multiaddr = format!("/dns4/attacker.example/tcp/4001/p2p/{stranger}")
            .parse()
            .unwrap();
        assert_eq!(
            allowed.dialable(&configured, vec![configured_dns.clone()]),
            vec![configured_dns]
        );
        assert!(allowed.dialable(&stranger, vec![stranger_dns]).is_empty());
    }
}
