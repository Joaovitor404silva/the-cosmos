use futures::channel::oneshot;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse, upgrade::ReadyUpgrade},
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm, NetworkBehaviour,
        NotifyHandler, Stream, StreamProtocol, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent,
        ToSwarm,
        handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound},
    },
};
use std::collections::VecDeque;
use std::fmt;
use std::task::{Context, Poll, Waker};

pub type Opened = oneshot::Sender<Result<Stream, String>>;

pub struct Inbound {
    pub peer: PeerId,
    pub conn: ConnectionId,
    pub stream: Stream,
}

impl fmt::Debug for Inbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inbound").field("peer", &self.peer).field("conn", &self.conn).finish()
    }
}

pub struct Behaviour {
    protocol: StreamProtocol,
    queue: VecDeque<ToSwarm<Inbound, Opened>>,
    waker: Option<Waker>,
}

impl Behaviour {
    pub fn new(protocol: StreamProtocol) -> Self {
        Self { protocol, queue: VecDeque::new(), waker: None }
    }

    pub fn open(&mut self, peer: PeerId, conn: ConnectionId, reply: Opened) {
        self.queue.push_back(ToSwarm::NotifyHandler { peer_id: peer, handler: NotifyHandler::One(conn), event: reply });
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Inbound;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.protocol.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(self.protocol.clone()))
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(&mut self, peer: PeerId, conn: ConnectionId, stream: THandlerOutEvent<Self>) {
        self.queue.push_back(ToSwarm::GenerateEvent(Inbound { peer, conn, stream }));
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        match self.queue.pop_front() {
            Some(e) => Poll::Ready(e),
            None => {
                self.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

pub struct Handler {
    protocol: StreamProtocol,
    requests: VecDeque<Opened>,
    inbound: VecDeque<Stream>,
    waker: Option<Waker>,
}

impl Handler {
    fn new(protocol: StreamProtocol) -> Self {
        Self { protocol, requests: VecDeque::new(), inbound: VecDeque::new(), waker: None }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Opened;
    type ToBehaviour = Stream;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = Opened;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        SubstreamProtocol::new(ReadyUpgrade::new(self.protocol.clone()), ())
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>> {
        if let Some(s) = self.inbound.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(s));
        }
        if let Some(reply) = self.requests.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(self.protocol.clone()), reply),
            });
        }
        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, reply: Opened) {
        self.requests.push_back(reply);
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), Opened>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound { protocol, .. }) => {
                self.inbound.push_back(protocol);
                if let Some(w) = self.waker.take() {
                    w.wake();
                }
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound { protocol, info }) => {
                let _ = info.send(Ok(protocol));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                let _ = info.send(Err(error.to_string()));
            }
            _ => {}
        }
    }
}
