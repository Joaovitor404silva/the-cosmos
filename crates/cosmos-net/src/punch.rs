//! DHT-signaled hole punching.
//!
//! No relay is involved. Each node keeps a signed record of the addresses it
//! can be reached on (observed, UPnP, public and LAN listeners) in the DHT
//! under `record_key(ADDR_TOPIC, peer_id)`. To reach a peer, a node fetches
//! that record, publishes a signed punch request under `punch_topic(target)`
//! carrying its own addresses and a dial-at time, and dials the target
//! repeatedly. The target polls its punch topic and dials back at the same
//! time, so both NATs open a mapping toward each other.
//!
//! If the request also carries a port-guess offer, the target answers with
//! its own offer under `guess_topic(requester)` and both sides run the
//! port-guess spray (for symmetric-ish NATs).

use crate::Record;
use crate::portguess::Offer;
use libp2p::{Multiaddr, PeerId};
use std::net::Ipv4Addr;

pub const ADDR_TOPIC: &str = "cosmos/addr";
pub const MAX_ADDRS: usize = 16;
const MAX_ADDR_LEN: usize = 256;
const VERSION: u8 = 1;

pub fn punch_topic(target: &PeerId) -> String {
    format!("cosmos/punch/{target}")
}

pub fn guess_topic(requester: &PeerId) -> String {
    format!("cosmos/guess/{requester}")
}

/// Raised by `Node::connect` when no direct, punched or guessed path exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    NoPath { peer: PeerId },
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::NoPath { peer } => write!(f, "no path to peer {peer}"),
        }
    }
}

impl std::error::Error for ConnectError {}

fn put_addrs(out: &mut Vec<u8>, addrs: &[Multiaddr]) {
    let addrs: Vec<&Multiaddr> = addrs
        .iter()
        .filter(|a| a.as_ref().len() <= MAX_ADDR_LEN)
        .take(MAX_ADDRS)
        .collect();
    out.push(addrs.len() as u8);
    for a in addrs {
        let b = a.to_vec();
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(&b);
    }
}

fn take_addrs(b: &[u8]) -> Option<(Vec<Multiaddr>, &[u8])> {
    let (&n, mut rest) = b.split_first()?;
    if n as usize > MAX_ADDRS {
        return None;
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        if rest.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len > MAX_ADDR_LEN || rest.len() < 2 + len {
            return None;
        }
        out.push(Multiaddr::try_from(rest[2..2 + len].to_vec()).ok()?);
        rest = &rest[2 + len..];
    }
    Some((out, rest))
}

pub fn encode_addrs(addrs: &[Multiaddr]) -> Vec<u8> {
    let mut out = vec![VERSION];
    put_addrs(&mut out, addrs);
    out
}

pub fn decode_addrs(b: &[u8]) -> Option<Vec<Multiaddr>> {
    let (&v, rest) = b.split_first()?;
    if v != VERSION {
        return None;
    }
    let (addrs, rest) = take_addrs(rest)?;
    rest.is_empty().then_some(addrs)
}

/// Addresses from a signed address record, only if `peer` signed it.
pub fn verify_addr_record(bytes: &[u8], peer: &PeerId) -> Option<Vec<Multiaddr>> {
    let rec = Record::verify(bytes)?;
    addrs_of(&rec, peer)
}

pub fn addrs_of(rec: &Record, peer: &PeerId) -> Option<Vec<Multiaddr>> {
    if rec.topic != ADDR_TOPIC || rec.publisher != *peer {
        return None;
    }
    decode_addrs(&rec.data)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub dial_at_ms: u64,
    pub nonce: [u8; 16],
    pub addrs: Vec<Multiaddr>,
    pub guess: Option<(Ipv4Addr, [u8; 16])>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.dial_at_ms.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        put_addrs(&mut out, &self.addrs);
        if let Some((ip, nonce)) = self.guess {
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&nonce);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Request> {
        let (&v, rest) = b.split_first()?;
        if v != VERSION || rest.len() < 8 + 16 {
            return None;
        }
        let dial_at_ms = u64::from_be_bytes(rest[..8].try_into().ok()?);
        let nonce: [u8; 16] = rest[8..24].try_into().ok()?;
        let (addrs, rest) = take_addrs(&rest[24..])?;
        let guess = match rest.len() {
            0 => None,
            20 => {
                let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
                Some((ip, rest[4..20].try_into().ok()?))
            }
            _ => return None,
        };
        Some(Request {
            dial_at_ms,
            nonce,
            addrs,
            guess,
        })
    }
}

/// Port-guess answer from the target: its own offer, signed by the target.
pub fn guess_answer_of(rec: &Record, requester: &PeerId, target: &PeerId) -> Option<Offer> {
    if rec.topic != guess_topic(requester) || rec.publisher != *target {
        return None;
    }
    Offer::decode(&rec.data)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::time::Duration;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn addr_record_roundtrip_and_only_owner_verifies() {
        let k = Keypair::generate_ed25519();
        let me = k.public().to_peer_id();
        let addrs = vec![ma("/ip4/8.8.8.8/udp/4001/quic-v1"), ma("/ip6/2804::1/tcp/9")];
        let bytes =
            Record::sign(&k, ADDR_TOPIC, encode_addrs(&addrs), Duration::from_secs(60)).unwrap();
        assert_eq!(verify_addr_record(&bytes, &me), Some(addrs.clone()));
        assert_eq!(verify_addr_record(&bytes, &PeerId::random()), None);
        let other =
            Record::sign(&k, "cosmos/other", encode_addrs(&addrs), Duration::from_secs(60)).unwrap();
        assert_eq!(verify_addr_record(&other, &me), None);
    }

    #[test]
    fn forged_or_unsigned_addr_record_rejected() {
        let victim = Keypair::generate_ed25519();
        let attacker = Keypair::generate_ed25519();
        let addrs = vec![ma("/ip4/6.6.6.6/tcp/1")];
        let forged =
            Record::sign(&attacker, ADDR_TOPIC, encode_addrs(&addrs), Duration::from_secs(60))
                .unwrap();
        assert_eq!(verify_addr_record(&forged, &victim.public().to_peer_id()), None);
        assert_eq!(verify_addr_record(&encode_addrs(&addrs), &victim.public().to_peer_id()), None);
        let mut tampered =
            Record::sign(&victim, ADDR_TOPIC, encode_addrs(&addrs), Duration::from_secs(60))
                .unwrap();
        let at = tampered.len() - 70;
        tampered[at] ^= 1;
        assert_eq!(verify_addr_record(&tampered, &victim.public().to_peer_id()), None);
    }

    #[test]
    fn request_roundtrip_and_rejects_junk() {
        let r = Request {
            dial_at_ms: 1_700_000_000_123,
            nonce: [7; 16],
            addrs: vec![ma("/ip4/1.2.3.4/udp/5/quic-v1")],
            guess: Some((Ipv4Addr::new(1, 2, 3, 4), [9; 16])),
        };
        assert_eq!(Request::decode(&r.encode()), Some(r.clone()));
        let plain = Request { guess: None, ..r };
        assert_eq!(Request::decode(&plain.encode()), Some(plain.clone()));
        let mut long = plain.encode();
        long.push(0);
        assert_eq!(Request::decode(&long), None);
        assert_eq!(Request::decode(&plain.encode()[..10]), None);
        let mut many = vec![VERSION];
        many.push(200);
        assert_eq!(decode_addrs(&many), None);
    }
}
