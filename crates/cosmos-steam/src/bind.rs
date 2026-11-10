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
pub const NONCE: usize = 16;
const DOMAIN: &[u8] = b"cosmos-steam-bind:v1";
const MAX_KEY: usize = 1024;

pub type Nonce = [u8; NONCE];

pub fn new_nonce() -> Nonce {
    let mut n = [0u8; NONCE];
    getrandom::fill(&mut n).expect("os rng");
    n
}

pub fn hello(nonce: &Nonce) -> Vec<u8> {
    let mut m = vec![HELLO];
    m.extend_from_slice(nonce);
    m
}

pub fn parse_hello(m: &[u8]) -> Option<Nonce> {
    (m.len() == 1 + NONCE && m[0] == HELLO).then(|| m[1..].try_into().unwrap())
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
}
