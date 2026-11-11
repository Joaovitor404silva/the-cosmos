//! SteamID <-> Cosmos key binding.
//!
//! Steam authenticates who sent a message (a SteamID), not which Cosmos peer
//! that is. Each side sends `HELLO(nonce)`; the other answers
//! `PROOF(pubkey, sig)` where `sig` signs (signer SteamID, receiver SteamID,
//! nonce) with its Cosmos key. A proof only binds when it answers our nonce,
//! names the SteamID Steam says sent it and names us as receiver. A SteamID
//! is never trusted alone.

use crate::backend::SteamId;
use cosmos_net::{Keypair, PeerId};
use libp2p_identity::PublicKey;

pub const HELLO: u8 = 1;
pub const PROOF: u8 = 2;
pub const DATA: u8 = 3;
/// A piece of a frame too big for one Steam message: `[FRAG][flags][chunk]`.
pub const FRAG: u8 = 4;
pub const FRAG_FIRST: u8 = 1;
pub const FRAG_LAST: u8 = 2;
/// `HELLO` sent in answer to a `HELLO`: answered with a proof only, never
/// with another hello (so two re-proving sides can't ping-pong).
pub const HELLO_BACK: u8 = 5;
pub const NONCE: usize = 16;
const DOMAIN: &[u8] = b"cosmos-steam-bind:v1";
const MAX_KEY: usize = 1024;

pub type Nonce = [u8; NONCE];

pub fn new_nonce() -> Nonce {
    let mut n = [0u8; NONCE];
    getrandom::fill(&mut n).expect("os rng");
    n
}

/// Bytes of the session tag on a hello.
pub const TAG: usize = 16;

/// An untagged `HELLO` (answered only by peers that asked for us).
pub fn hello(nonce: &Nonce) -> Vec<u8> {
    hello_kind(HELLO, nonce)
}

pub fn hello_kind(kind: u8, nonce: &Nonce) -> Vec<u8> {
    let mut m = vec![kind];
    m.extend_from_slice(nonce);
    m.extend_from_slice(&[0; TAG]);
    m
}

fn tag(key: &[u8; 32], kind: u8, from: SteamId, to: SteamId, nonce: &Nonce) -> [u8; TAG] {
    let d = cosmos_core::sealed::derive(key, &[b"cosmos-steam-hello:v1", &[kind], &from.to_be_bytes(), &to.to_be_bytes(), nonce]);
    d[..TAG].try_into().unwrap()
}

/// A hello from `from` to `to` tagged with the session key, which proves
/// the sender holds the join code (so the receiver may reveal its key).
pub fn hello_tagged(kind: u8, nonce: &Nonce, key: Option<&[u8; 32]>, from: SteamId, to: SteamId) -> Vec<u8> {
    let mut m = hello_kind(kind, nonce);
    if let Some(k) = key {
        m[1 + NONCE..].copy_from_slice(&tag(k, kind, from, to, nonce));
    }
    m
}

/// Nonce of a `HELLO` or `HELLO_BACK`.
pub fn parse_hello(m: &[u8]) -> Option<Nonce> {
    (m.len() == 1 + NONCE + TAG && (m[0] == HELLO || m[0] == HELLO_BACK)).then(|| m[1..1 + NONCE].try_into().unwrap())
}

/// `m` is a hello `from` -> `to` carrying a valid tag for `key`.
pub fn hello_tag_ok(m: &[u8], key: &[u8; 32], from: SteamId, to: SteamId) -> bool {
    let Some(n) = parse_hello(m) else { return false };
    cosmos_core::sealed::ct_eq(&m[1 + NONCE..], &tag(key, m[0], from, to, &n))
}

fn signed(signer: SteamId, receiver: SteamId, nonce: &Nonce) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(&signer.to_be_bytes());
    m.extend_from_slice(&receiver.to_be_bytes());
    m.extend_from_slice(nonce);
    m
}

/// Our answer to `receiver`'s `HELLO(nonce)`.
pub fn proof(key: &Keypair, signer: SteamId, receiver: SteamId, nonce: &Nonce) -> Vec<u8> {
    let pk = key.public().encode_protobuf();
    let sig = key.sign(&signed(signer, receiver, nonce)).expect("sign");
    let mut m = vec![PROOF];
    m.extend_from_slice(&(pk.len() as u16).to_be_bytes());
    m.extend_from_slice(&pk);
    m.extend_from_slice(&sig);
    m
}

/// The Cosmos peer behind `from`, if `m` is its valid answer to our `nonce`.
pub fn verify_proof(m: &[u8], from: SteamId, me: SteamId, nonce: &Nonce) -> Option<PeerId> {
    if m.len() < 3 || m[0] != PROOF {
        return None;
    }
    let n = u16::from_be_bytes([m[1], m[2]]) as usize;
    if n > MAX_KEY || m.len() < 3 + n {
        return None;
    }
    let key = PublicKey::try_decode_protobuf(&m[3..3 + n]).ok()?;
    key.verify(&signed(from, me, nonce), &m[3 + n..]).then(|| key.to_peer_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: SteamId = 76561198000000001;
    const B: SteamId = 76561198000000002;

    #[test]
    fn proof_binds_signer() {
        let k = Keypair::generate_ed25519();
        let n = new_nonce();
        let p = proof(&k, A, B, &n);
        assert_eq!(verify_proof(&p, A, B, &n), Some(k.public().to_peer_id()));
    }

    #[test]
    fn proof_rejects_wrong_ids_nonce_and_tamper() {
        let k = Keypair::generate_ed25519();
        let n = new_nonce();
        let p = proof(&k, A, B, &n);
        // Relayed by another SteamID, or aimed at someone else.
        assert_eq!(verify_proof(&p, B, B, &n), None);
        assert_eq!(verify_proof(&p, A, A, &n), None);
        assert_eq!(verify_proof(&p, A, B, &new_nonce()), None);
        let mut t = p.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert_eq!(verify_proof(&t, A, B, &n), None);
        assert_eq!(verify_proof(&p[..10], A, B, &n), None);
        assert_eq!(verify_proof(&[PROOF, 0xff, 0xff], A, B, &n), None);
    }

    #[test]
    fn hello_roundtrip() {
        let n = new_nonce();
        assert_eq!(parse_hello(&hello(&n)), Some(n));
        assert_eq!(parse_hello(&hello(&n)[..5]), None);
    }

    #[test]
    fn hello_tag_binds_key_ids_and_kind() {
        let (k, n) = ([3u8; 32], new_nonce());
        let m = hello_tagged(HELLO, &n, Some(&k), A, B);
        assert_eq!(parse_hello(&m), Some(n));
        assert!(hello_tag_ok(&m, &k, A, B));
        assert!(!hello_tag_ok(&m, &[4u8; 32], A, B));
        assert!(!hello_tag_ok(&m, &k, B, A));
        assert!(!hello_tag_ok(&hello(&n), &k, A, B), "untagged hello passed");
        let mut back = m.clone();
        back[0] = HELLO_BACK;
        assert!(!hello_tag_ok(&back, &k, A, B), "kind not bound");
    }
}
