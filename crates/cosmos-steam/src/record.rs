//! Peer -> SteamID discovery for session members. Each member with Steam
//! publishes a signed DHT record (publisher = its PeerId) whose SteamID is
//! encrypted with the join code's session key, under a topic derived from
//! that key. Outsiders see neither the SteamID nor which records are Steam
//! records. Only a hint for whom to message; the binding handshake still
//! decides who is who.

use crate::backend::SteamId;
use cosmos_core::sealed;
use cosmos_net::{Node, PeerId, Record};
use futures::FutureExt;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::Mutex;

const MAGIC: &[u8] = b"cosmos-steamid:v2";

/// The record topic for one session key.
pub fn topic(key: &[u8; 32]) -> String {
    let d = sealed::derive(key, &[MAGIC, b"topic"]);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("cosmos/s/{hex}")
}

fn aead_key(key: &[u8; 32]) -> [u8; 32] {
    sealed::derive(key, &[MAGIC, b"key"])
}

/// Record payload: the SteamID, sealed.
pub fn encode(key: &[u8; 32], steam: SteamId) -> Vec<u8> {
    sealed::seal(&aead_key(key), topic(key).as_bytes(), &steam.to_be_bytes())
}

pub fn decode(key: &[u8; 32], d: &[u8]) -> Option<SteamId> {
    let p = sealed::open(&aead_key(key), topic(key).as_bytes(), d)?;
    let steam = u64::from_be_bytes(p.as_slice().try_into().ok()?);
    (steam != 0).then_some(steam)
}

/// The SteamID in `rec`, if `peer` signed it under the session's topic.
pub fn from_record(key: &[u8; 32], rec: &Record, peer: PeerId) -> Option<SteamId> {
    if rec.topic != topic(key) || rec.publisher != peer {
        return None;
    }
    decode(key, &rec.data)
}

/// Announce our SteamID to session members (call again before the node's
/// record TTL runs out).
pub async fn publish_steam_id(node: &Node, key: &[u8; 32], steam: SteamId) -> anyhow::Result<()> {
    node.publish(&topic(key), encode(key, steam)).await
}

/// Where to find a peer's SteamID.
pub trait SteamDirectory: Send + Sync + 'static {
    fn lookup(&self, peer: PeerId) -> BoxFuture<'_, Option<SteamId>>;
}

/// The DHT records published with `publish_steam_id`; finds nothing until
/// the session key is set.
pub struct DhtDirectory {
    pub node: Node,
    key: Mutex<Option<[u8; 32]>>,
}

impl DhtDirectory {
    pub fn new(node: Node) -> Self {
        Self { node, key: Mutex::new(None) }
    }

    pub fn set_key(&self, key: [u8; 32]) {
        *self.key.lock().unwrap() = Some(key);
    }
}

impl SteamDirectory for DhtDirectory {
    fn lookup(&self, peer: PeerId) -> BoxFuture<'_, Option<SteamId>> {
        let key = *self.key.lock().unwrap();
        async move {
            let key = key?;
            let rec = self.node.get(&topic(&key), peer).await.ok()??;
            from_record(&key, &rec, peer)
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
        let key = [5u8; 32];
        let sid: SteamId = 76561198000000001;
        let bytes = Record::sign(&k, &topic(&key), encode(&key, sid), Duration::from_secs(60)).unwrap();
        let rec = Record::verify(&bytes).unwrap();
        assert_eq!(from_record(&key, &rec, me), Some(sid));
        // Someone else's record does not speak for `me`.
        assert_eq!(from_record(&key, &rec, PeerId::random()), None);
        // Audit finding 2: outsiders can't read the SteamID or spot the topic.
        assert!(!rec.data.windows(8).any(|w| w == sid.to_be_bytes()), "SteamID in clear");
        assert!(!rec.topic.contains("steam"));
        assert_eq!(from_record(&[6u8; 32], &rec, me), None);
        assert_ne!(topic(&key), topic(&[6u8; 32]));
        assert_eq!(decode(&key, b"junk"), None);
        assert_eq!(decode(&key, &encode(&key, 0)), None);
    }
}
