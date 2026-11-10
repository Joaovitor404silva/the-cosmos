//! DHT-signaled hole punching.
//!
//! No relay is involved. Each node keeps a signed record of the addresses it
//! can be reached on (observed, UPnP, public and LAN listeners) in the DHT
//! under `record_key(ADDR_TOPIC, peer_id)`. To reach a peer, a node fetches
//! that record, puts a short-lived signed punch request into one of the
//! target's `INBOX_SLOTS` inbox keys (a plain DHT record, no provider entry,
//! no gossip) carrying its own addresses, and dials the target repeatedly.
//! The target polls its inbox slots and dials back as soon as it sees a
//! request, so both NATs open a mapping toward each other. Freshness comes
//! from the signed record expiry plus a nonce, not from wall-clock dial times.
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
const REQ_VERSION: u8 = 2;

/// Inbox slots per target. Sessions hold at most 4 players, so at most 3
/// requesters punch one host at a time; requesters re-put into a random slot
/// every poll, so a collision only delays them by one poll.
pub const INBOX_SLOTS: u8 = 4;
/// Longest lifetime a punch inbox record may claim.
pub const INBOX_MAX_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const INBOX_PREFIX: &str = "cosmos/punch/";

pub fn inbox_topic(target: &PeerId, slot: u8) -> String {
    format!("{INBOX_PREFIX}{target}/{slot}")
}

/// `(target, slot)` of a punch inbox topic.
pub fn parse_inbox_topic(topic: &str) -> Option<(PeerId, u8)> {
    let (target, slot) = topic.strip_prefix(INBOX_PREFIX)?.rsplit_once('/')?;
    let n: u8 = slot.parse().ok()?;
    if n >= INBOX_SLOTS || n.to_string() != slot {
        return None;
    }
    Some((target.parse().ok()?, n))
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
    pub nonce: [u8; 16],
    pub addrs: Vec<Multiaddr>,
    pub guess: Option<(Ipv4Addr, [u8; 16])>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![REQ_VERSION];
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
        if v != REQ_VERSION || rest.len() < 16 {
            return None;
        }
        let nonce: [u8; 16] = rest[..16].try_into().ok()?;
        let (addrs, rest) = take_addrs(&rest[16..])?;
        let guess = match rest.len() {
            0 => None,
            20 => {
                let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
                Some((ip, rest[4..20].try_into().ok()?))
            }
            _ => return None,
        };
        Some(Request {
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

/// A punch request read from our inbox: valid only if it is a signed record
/// for `inbox_topic(me, slot)`, short-lived, and not from ourselves.
pub fn inbox_request(rec: &Record, me: &PeerId, slot: u8) -> Option<Request> {
    let max_expiry = crate::record::now_secs() + INBOX_MAX_TTL.as_secs() + crate::CLOCK_SKEW.as_secs();
    if rec.topic != inbox_topic(me, slot) || rec.publisher == *me || rec.expires > max_expiry {
        return None;
    }
    Request::decode(&rec.data)
}

#[cfg(test)]
mod tests {
    #[test]
    fn inbox_topics_roundtrip_and_reject_junk() {
        let t = PeerId::random();
        for slot in 0..INBOX_SLOTS {
            assert_eq!(parse_inbox_topic(&inbox_topic(&t, slot)), Some((t, slot)));
        }
        assert_eq!(parse_inbox_topic(&format!("cosmos/punch/{t}/{INBOX_SLOTS}")), None);
        assert_eq!(parse_inbox_topic(&format!("cosmos/punch/{t}/01")), None);
        assert_eq!(parse_inbox_topic(&format!("cosmos/punch/{t}")), None);
        assert_eq!(parse_inbox_topic("cosmos/punch/nope/0"), None);
        assert_eq!(parse_inbox_topic(&format!("cosmos/addr/{t}/0")), None);
    }

    #[test]
    fn inbox_request_checks_target_slot_publisher_and_ttl() {
        let me_k = Keypair::generate_ed25519();
        let me = me_k.public().to_peer_id();
        let other = Keypair::generate_ed25519();
        let req = Request { nonce: [1; 16], addrs: vec![ma("/ip4/1.2.3.4/udp/5/quic-v1")], guess: None };
        let sign = |k: &Keypair, topic: &str, ttl: u64| {
            Record::verify(&Record::sign(k, topic, req.encode(), Duration::from_secs(ttl)).unwrap()).unwrap()
        };
        assert_eq!(inbox_request(&sign(&other, &inbox_topic(&me, 2), 30), &me, 2), Some(req.clone()));
        assert_eq!(inbox_request(&sign(&other, &inbox_topic(&me, 2), 30), &me, 1), None);
        assert_eq!(inbox_request(&sign(&other, &inbox_topic(&PeerId::random(), 2), 30), &me, 2), None);
        assert_eq!(inbox_request(&sign(&me_k, &inbox_topic(&me, 2), 30), &me, 2), None);
        assert_eq!(inbox_request(&sign(&other, &inbox_topic(&me, 2), 900), &me, 2), None);
    }

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
        let mut v1 = plain.encode();
        v1[0] = VERSION;
        assert_eq!(Request::decode(&v1), None);
        let mut many = vec![VERSION];
        many.push(200);
        assert_eq!(decode_addrs(&many), None);
    }
}
