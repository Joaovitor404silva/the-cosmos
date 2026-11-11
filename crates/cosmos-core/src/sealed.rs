//! XChaCha20-Poly1305 with a random nonce: `nonce || ciphertext`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 24;

/// Encrypt `msg`, bound to `aad`.
pub fn seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("os rng");
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg, aad })
        .expect("aead encrypt");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// Decrypt what `seal` made with the same key and `aad`.
pub fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).ok()
}

/// A purpose-specific 32-byte key (or tag) from `key`: SHA-256 over
/// length-framed parts.
pub fn derive(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in std::iter::once(&key[..]).chain(parts.iter().copied()) {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejects() {
        let k = [7u8; 32];
        let s = seal(&k, b"aad", b"hello");
        assert_eq!(open(&k, b"aad", &s).as_deref(), Some(&b"hello"[..]));
        assert!(open(&k, b"other", &s).is_none());
        assert!(open(&[8u8; 32], b"aad", &s).is_none());
        assert!(open(&k, b"aad", &s[..10]).is_none());
        assert_ne!(seal(&k, b"aad", b"hello"), s, "nonce must be random");
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac") && !ct_eq(b"a", b"ab"));
    }
}
