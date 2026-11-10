//! Join codes: a short human code resolves, through the DHT, to a
//! host-signed session advert.
//!
//! The code is derived from the host key: `code = H(namespace, host, salt)`
//! cut to 40 bits, so a valid advert for a code must be signed by the key
//! that produced it. Anyone else publishing under the same DHT topic is
//! ignored (forging one means grinding 2^40 hashes against a short-lived
//! advert). Expired adverts are rejected.

use cosmos_net::{Multiaddr, Node, PeerId, Record};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const CODE_LEN: usize = 8;
/// Crockford base32: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN: &[u8] = b"cosmos-join:v1";
const VERSION: u8 = 1;
const MAX_ADDRS: usize = 16;
/// Republish interval; must stay under the node's record TTL.
const REFRESH: Duration = Duration::from_secs(60);
const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);

/// Uppercase, drop separators, map look-alikes (O->0, I/L->1). `None` if not
/// a well-formed code.
pub fn normalize(code: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in code.chars().filter(|c| !matches!(c, '-' | ' ')) {
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// Display form, e.g. `7K3Q-M9XA`.
pub fn pretty(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

/// The code a host key and salt produce inside one game namespace.
pub fn code_for(namespace: &str, host: &PeerId, salt: u64) -> String {
    let mut h = Sha256::new();
    for part in [DOMAIN, namespace.as_bytes(), &host.to_bytes()] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.update(salt.to_be_bytes());
    let d = h.finalize();
    let bits = u64::from_be_bytes(d[..8].try_into().unwrap()) >> (64 - 5 * CODE_LEN);
    (0..CODE_LEN)
        .rev()
        .map(|i| ALPHABET[((bits >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// DHT topic of the advert for `code` (game namespace included).
pub fn topic(namespace: &str, code: &str) -> String {
    cosmos_net::topic_for(namespace, &format!("join/{code}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    pub host: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub salt: u64,
}

impl Advert {
    pub fn encode(&self, namespace: &str) -> Vec<u8> {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.salt.to_be_bytes());
        let mut field = |x: &[u8]| {
            b.extend_from_slice(&(x.len() as u16).to_be_bytes());
            b.extend_from_slice(x);
        };
        field(namespace.as_bytes());
        field(&self.host.to_bytes());
        for a in self.addrs.iter().take(MAX_ADDRS) {
            field(&a.to_vec());
        }
        b
    }

    fn decode(b: &[u8]) -> Option<(String, Advert)> {
        let (&ver, rest) = b.split_first()?;
        if ver != VERSION || rest.len() < 8 {
            return None;
        }
        let (salt, mut rest) = rest.split_at(8);
        let mut field = || -> Option<&[u8]> {
            let n = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?) as usize;
            let x = rest.get(2..2 + n)?;
            rest = &rest[2 + n..];
            Some(x)
        };
        let ns = String::from_utf8(field()?.to_vec()).ok()?;
        let host = PeerId::from_bytes(field()?).ok()?;
        let mut addrs = vec![];
        while let Some(a) = field() {
            if addrs.len() == MAX_ADDRS {
                return None;
            }
            addrs.push(Multiaddr::try_from(a.to_vec()).ok()?);
        }
        if !rest.is_empty() {
            return None;
        }
        let salt = u64::from_be_bytes(salt.try_into().ok()?);
        Some((ns, Advert { host, addrs, salt }))
    }
}

/// Validate a record found under a code's topic: right topic, not expired,
/// right namespace, and the code really derives from the signer's key.
pub fn check(rec: &Record, namespace: &str, code: &str, now_secs: u64) -> Option<Advert> {
    if rec.topic != topic(namespace, code) || rec.expires <= now_secs {
        return None;
    }
    let (ns, a) = Advert::decode(&rec.data)?;
    (ns == namespace && a.host == rec.publisher && code_for(namespace, &a.host, a.salt) == code).then_some(a)
}

#[derive(Debug)]
pub enum CodeError {
    BadCode,
    NotFound,
    Net(anyhow::Error),
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::BadCode => f.write_str("malformed join code"),
            CodeError::NotFound => f.write_str("no valid session advert for this code"),
            CodeError::Net(e) => write!(f, "lookup failed: {e:#}"),
        }
    }
}

impl std::error::Error for CodeError {}

/// A published advert; republished until dropped.
pub struct Advertisement {
    pub code: String,
    task: JoinHandle<()>,
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Publish a session advert for this node and return its join code.
pub async fn advertise(node: &Node, namespace: &str, addrs: Vec<Multiaddr>) -> anyhow::Result<Advertisement> {
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let advert = Advert { host: node.peer_id(), addrs, salt };
    let code = code_for(namespace, &advert.host, salt);
    let topic = topic(namespace, &code);
    let data = advert.encode(namespace);
    node.publish(&topic, data.clone()).await?;
    let node = node.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH).await;
            if let Err(e) = node.publish(&topic, data.clone()).await {
                tracing::debug!("advert refresh failed: {e:#}");
            }
        }
    });
    Ok(Advertisement { code, task })
}

/// Find the host behind `code`.
pub async fn resolve(node: &Node, namespace: &str, code: &str) -> Result<Advert, CodeError> {
    let code = normalize(code).ok_or(CodeError::BadCode)?;
    let recs = node
        .find_within(&topic(namespace, &code), RESOLVE_DEADLINE)
        .await
        .map_err(CodeError::Net)?;
    let now = now_secs();
    recs.iter()
        .find_map(|r| check(r, namespace, &code, now))
        .ok_or(CodeError::NotFound)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmos_net::Keypair;

    const NS: &str = "cosmos-demo";

    fn signed(k: &Keypair, topic: &str, data: Vec<u8>) -> Record {
        Record::verify(&Record::sign(k, topic, data, Duration::from_secs(300)).unwrap()).unwrap()
    }

    fn host_advert(k: &Keypair) -> (String, Record) {
        let host = k.public().to_peer_id();
        let a = Advert { host, addrs: vec!["/ip4/1.2.3.4/udp/9/quic-v1".parse().unwrap()], salt: 77 };
        let code = code_for(NS, &host, a.salt);
        let rec = signed(k, &topic(NS, &code), a.encode(NS));
        (code, rec)
    }

    #[test]
    fn code_shape_and_normalize() {
        let p = PeerId::random();
        let c = code_for(NS, &p, 1);
        assert_eq!(c.len(), CODE_LEN);
        assert!(c.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(c, code_for(NS, &p, 1));
        assert_ne!(c, code_for(NS, &p, 2));
        assert_ne!(c, code_for("other-game", &p, 1));
        assert_eq!(normalize(&pretty(&c).to_lowercase()), Some(c.clone()));
        assert_eq!(normalize("o1il-23 45"), Some("0111-2345".replace('-', "")));
        assert_eq!(normalize("ABCDEFG"), None);
        assert_eq!(normalize("ABCDEFGU"), None);
        assert_eq!(normalize("ABCDEFGH9"), None);
    }

    #[test]
    fn genuine_advert_accepted() {
        let k = Keypair::generate_ed25519();
        let (code, rec) = host_advert(&k);
        let a = check(&rec, NS, &code, now_secs()).expect("rejected");
        assert_eq!(a.host, k.public().to_peer_id());
        assert_eq!(a.addrs.len(), 1);
    }

    #[test]
    fn forged_advert_rejected() {
        let host = Keypair::generate_ed25519();
        let (code, rec) = host_advert(&host);
        // An attacker re-signs the host's advert under the same code.
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec.topic, rec.data.clone());
        assert!(check(&forged, NS, &code, now_secs()).is_none());
        // Or claims the host's id inside its own advert.
        let lie = Advert { host: host.public().to_peer_id(), addrs: vec![], salt: 77 };
        let forged = signed(&evil, &rec.topic, lie.encode(NS));
        assert!(check(&forged, NS, &code, now_secs()).is_none());
    }

    #[test]
    fn expired_wrong_namespace_or_code_rejected() {
        let k = Keypair::generate_ed25519();
        let (code, rec) = host_advert(&k);
        let expired = Record { expires: now_secs() - 1, ..rec.clone() };
        assert!(check(&expired, NS, &code, now_secs()).is_none());
        assert!(check(&rec, "other-game", &code, now_secs()).is_none());
        let other = code_for(NS, &PeerId::random(), 1);
        assert!(check(&rec, NS, &other, now_secs()).is_none());
        let mut garbage = rec.clone();
        garbage.data.push(0);
        assert!(check(&garbage, NS, &code, now_secs()).is_none());
    }
}
