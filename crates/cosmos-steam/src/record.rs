//! Peer -> SteamID discovery: each node with Steam publishes a signed DHT
//! record (publisher = its PeerId) carrying its SteamID. Only a hint for whom
//! to message; the binding handshake still decides who is who.

use crate::backend::SteamId;
use cosmos_net::{Node, PeerId, Record};
use futures::FutureExt;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::Mutex;

pub const STEAM_TOPIC: &str = "cosmos/steam";
const MAGIC: &[u8] = b"cosmos-steamid:v1";

/// Record payload: magic, SteamID, AppID.
pub fn encode(steam: SteamId, app_id: u32) -> Vec<u8> {
    let mut d = MAGIC.to_vec();
    d.extend_from_slice(&steam.to_be_bytes());
    d.extend_from_slice(&app_id.to_be_bytes());
    d
}

pub fn decode(d: &[u8]) -> Option<(SteamId, u32)> {
    let rest = d.strip_prefix(MAGIC)?;
    if rest.len() != 12 {
        return None;
    }
    let steam = u64::from_be_bytes(rest[..8].try_into().unwrap());
    (steam != 0).then(|| (steam, u32::from_be_bytes(rest[8..].try_into().unwrap())))
}

/// The SteamID in `rec`, if `peer` signed it under the Steam topic.
pub fn from_record(rec: &Record, peer: PeerId) -> Option<(SteamId, u32)> {
    if rec.topic != STEAM_TOPIC || rec.publisher != peer {
        return None;
    }
    decode(&rec.data)
}

/// Announce our SteamID (call again before the node's record TTL runs out).
pub async fn publish_steam_id(node: &Node, steam: SteamId, app_id: u32) -> anyhow::Result<()> {
    node.publish(STEAM_TOPIC, encode(steam, app_id)).await
}

/// Where to find a peer's SteamID.
pub trait SteamDirectory: Send + Sync + 'static {
    fn lookup(&self, peer: PeerId) -> BoxFuture<'_, Option<SteamId>>;
}

/// The DHT records published with `publish_steam_id`.
pub struct DhtDirectory {
    pub node: Node,
}

impl SteamDirectory for DhtDirectory {
    fn lookup(&self, peer: PeerId) -> BoxFuture<'_, Option<SteamId>> {
        async move {
            let rec = self.node.get(STEAM_TOPIC, peer).await.ok()??;
            from_record(&rec, peer).map(|(s, _)| s)
        }
        .boxed()
    }
}

/// A fixed map (tests, or SteamIDs learned from a join advert / lobby).
#[derive(Default)]
pub struct StaticDirectory(Mutex<HashMap<PeerId, SteamId>>);

impl StaticDirectory {
    pub fn insert(&self, peer: PeerId, steam: SteamId) {
        self.0.lock().unwrap().insert(peer, steam);
    }
}

impl SteamDirectory for StaticDirectory {
    fn lookup(&self, peer: PeerId) -> BoxFuture<'_, Option<SteamId>> {
        let s = self.0.lock().unwrap().get(&peer).copied();
        async move { s }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmos_net::Keypair;
    use std::time::Duration;

    #[test]
    fn record_roundtrip_and_publisher_check() {
        let k = Keypair::generate_ed25519();
        let me = k.public().to_peer_id();
        let bytes = Record::sign(&k, STEAM_TOPIC, encode(76561198000000001, 480), Duration::from_secs(60)).unwrap();
        let rec = Record::verify(&bytes).unwrap();
        assert_eq!(from_record(&rec, me), Some((76561198000000001, 480)));
        // Someone else's record does not speak for `me`.
        assert_eq!(from_record(&rec, PeerId::random()), None);
        let other = Record::verify(&Record::sign(&k, "cosmos/addr", encode(1, 480), Duration::from_secs(60)).unwrap()).unwrap();
        assert_eq!(from_record(&other, me), None);
        assert_eq!(decode(&encode(0, 480)), None);
        assert_eq!(decode(b"junk"), None);
    }
}
