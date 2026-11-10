use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    relay,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use std::collections::HashSet;
use std::task::{Context, Poll};

pub struct RelayServer {
    inner: relay::Behaviour,
    relayed: HashSet<ConnectionId>,
}

impl RelayServer {
    pub fn new(inner: relay::Behaviour) -> Self {
        RelayServer { inner, relayed: HashSet::new() }
    }
}

impl NetworkBehaviour for RelayServer {
    type ConnectionHandler = <relay::Behaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = relay::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner.handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if crate::is_relayed(local) {
            self.relayed.insert(id);
        }
        self.inner.handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addrs: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(id, peer, addrs, role)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if crate::is_relayed(addr) {
            self.relayed.insert(id);
        }
        self.inner.handle_established_outbound_connection(id, peer, addr, role, port_use)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(c) = &event {
            self.relayed.remove(&c.connection_id);
        }
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(&mut self, peer: PeerId, id: ConnectionId, ev: THandlerOutEvent<Self>) {
        self.inner.on_connection_handler_event(peer, id, ev)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::NotifyHandler { handler: NotifyHandler::One(id), .. }) if self.relayed.contains(&id) => {
                    continue;
                }
                other => return other,
            }
        }
    }
}
