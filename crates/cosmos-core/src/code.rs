//! Join codes: a short human code resolves, through the DHT, to a
//! host-signed session advert.
//!
//! - The code is bound to the host key through a slow hash:
//!   `code = 40 bits of Argon2id(H(namespace, host, salt))`. A valid advert
//!   must be signed by that host, so forging one for a known code means
//!   grinding ~2^40 Argon2id hashes.
//! - The code never appears in the DHT: the advert topic is derived from
//!   `Argon2id(code)`, so nodes storing it can't read the code off it.
//! - `join_secret(namespace, code)` comes from the same slow hash. Joiners
//!   send it to the host, which admits only code holders.
//! - Two valid adverts naming different hosts make `resolve` fail instead
//!   of picking one. Expired adverts are rejected.

use cosmos_net::{Multiaddr, Node, PeerId, Record};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const CODE_LEN: usize = 8;
/// Crockford base32: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN: &[u8] = b"cosmos-join:v2";
/// Only this many records under one topic get the (slow) code check.
const MAX_CHECKED: usize = 16;
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

fn framed(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Argon2id (OWASP 2023 minimum: 19 MiB, 2 passes). Tens of ms per call,
/// which makes grinding codes or reversing topics impractical.
fn slow(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("argon2 params");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut out)
        .expect("argon2");
    out
}

/// The code a host key and salt produce inside one game namespace.
pub fn code_for(namespace: &str, host: &PeerId, salt: u64) -> String {
    let pw = framed(&[DOMAIN, b"code", namespace.as_bytes(), &host.to_bytes(), &salt.to_be_bytes()]);
    let d = slow(&pw, &framed(&[DOMAIN, b"code-salt", namespace.as_bytes()])[..16]);
    let bits = u64::from_be_bytes(d[..8].try_into().unwrap()) >> (64 - 5 * CODE_LEN);
    (0..CODE_LEN)
        .rev()
        .map(|i| ALPHABET[((bits >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// What a code unlocks: the DHT topic of its advert and the join secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeKeys {
    pub topic: String,
    pub secret: [u8; 16],
}

/// Derive the advert topic and join secret from a (normalized) code.
pub fn keys(namespace: &str, code: &str) -> CodeKeys {
    let d = slow(code.as_bytes(), &framed(&[DOMAIN, b"keys-salt", namespace.as_bytes()])[..16]);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    CodeKeys {
        topic: cosmos_net::topic_for(namespace, &format!("join/{hex}")),
        secret: d[16..].try_into().unwrap(),
    }
}

/// DHT topic of the advert for `code` (game namespace included).
pub fn topic(namespace: &str, code: &str) -> String {
    keys(namespace, code).topic
}

/// Secret a joiner proves to the host that it holds the code.
pub fn join_secret(namespace: &str, code: &str) -> [u8; 16] {
    keys(namespace, code).secret
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
    check_with(rec, namespace, code, &topic(namespace, code), now_secs, code_for)
}

fn check_with(
    rec: &Record,
    namespace: &str,
    code: &str,
    topic: &str,
    now_secs: u64,
    derive: fn(&str, &PeerId, u64) -> String,
) -> Option<Advert> {
    if rec.topic != topic || rec.expires <= now_secs {
        return None;
    }
    let (ns, a) = Advert::decode(&rec.data)?;
    if ns != namespace || a.host != rec.publisher {
        return None;
    }
    (derive(namespace, &a.host, a.salt) == code).then_some(a)
}

/// The one host a set of records names for `code`. Several distinct valid
/// hosts is a conflict (someone forged a code), never a silent pick.
pub fn pick(recs: &[Record], namespace: &str, code: &str, now_secs: u64) -> Result<Advert, CodeError> {
    pick_by(recs, namespace, code, &topic(namespace, code), now_secs, code_for)
}

fn pick_by(
    recs: &[Record],
    namespace: &str,
    code: &str,
    topic: &str,
    now_secs: u64,
    derive: fn(&str, &PeerId, u64) -> String,
) -> Result<Advert, CodeError> {
    let mut found: Option<Advert> = None;
    for r in recs.iter().filter(|r| r.topic == topic).take(MAX_CHECKED) {
        let Some(a) = check_with(r, namespace, code, topic, now_secs, derive) else {
            continue;
        };
        match &found {
            Some(f) if f.host != a.host => return Err(CodeError::Conflict),
            Some(_) => {}
            None => found = Some(a),
        }
    }
    found.ok_or(CodeError::NotFound)
}

#[derive(Debug)]
pub enum CodeError {
    BadCode,
    NotFound,
    /// Valid adverts for this code name different hosts.
    Conflict,
    Net(anyhow::Error),
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::BadCode => f.write_str("malformed join code"),
            CodeError::NotFound => f.write_str("no valid session advert for this code"),
            CodeError::Conflict => f.write_str("conflicting session adverts for this code"),
            CodeError::Net(e) => write!(f, "lookup failed: {e:#}"),
        }
    }
}

impl std::error::Error for CodeError {}

/// A published advert; republished until dropped.
pub struct Advertisement {
    pub code: String,
    /// Joiners must present this (see `join_secret`).
    pub secret: [u8; 16],
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
    let (ns, host) = (namespace.to_string(), advert.host);
    let code = tokio::task::spawn_blocking(move || code_for(&ns, &host, salt)).await?;
    let (ns, c) = (namespace.to_string(), code.clone());
    let CodeKeys { topic, secret } = tokio::task::spawn_blocking(move || keys(&ns, &c)).await?;
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
    Ok(Advertisement { code, secret, task })
}

/// Find the host behind `code`.
pub async fn resolve(node: &Node, namespace: &str, code: &str) -> Result<Advert, CodeError> {
    let code = normalize(code).ok_or(CodeError::BadCode)?;
    let (ns, c) = (namespace.to_string(), code.clone());
    let topic = tokio::task::spawn_blocking(move || topic(&ns, &c))
        .await
        .map_err(|e| CodeError::Net(e.into()))?;
    let recs = node
        .find_within(&topic, RESOLVE_DEADLINE)
        .await
        .map_err(CodeError::Net)?;
    let ns = namespace.to_string();
    tokio::task::spawn_blocking(move || pick(&recs, &ns, &code, now_secs()))
        .await
        .map_err(|e| CodeError::Net(e.into()))?
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
    fn topic_hides_the_code_and_secret_differs_per_code() {
        let p = PeerId::random();
        let c = code_for(NS, &p, 5);
        let k = keys(NS, &c);
        assert!(!k.topic.contains(&c), "code readable in the DHT topic");
        assert_eq!(k, keys(NS, &c));
        let other = code_for(NS, &p, 6);
        assert_ne!(k.secret, keys(NS, &other).secret);
        assert_ne!(k.topic, keys("other-game", &c).topic);
    }

    #[test]
    fn pick_fails_on_two_valid_hosts_and_ignores_junk() {
        let a = Keypair::generate_ed25519();
        let (code, rec_a) = host_advert(&a);
        let now = now_secs();
        assert_eq!(pick(&[rec_a.clone()], NS, &code, now).unwrap().host, a.public().to_peer_id());
        // Junk and forged records next to the real one don't change the pick.
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec_a.topic, rec_a.data.clone());
        let junk = signed(&evil, &rec_a.topic, vec![1, 2, 3]);
        assert_eq!(pick(&[forged, junk, rec_a.clone()], NS, &code, now).unwrap().host, a.public().to_peer_id());
        // Two valid adverts for one code from different hosts (as if a
        // 2^40 grind succeeded; simulated with a derive that ignores keys).
        fn same(_: &str, _: &PeerId, _: u64) -> String {
            "AAAAAAAA".into()
        }
        let b = Keypair::generate_ed25519();
        let t = "t";
        let adv = |k: &Keypair| {
            let host = k.public().to_peer_id();
            signed(k, t, Advert { host, addrs: vec![], salt: 1 }.encode(NS))
        };
        let (ra, rb) = (adv(&a), adv(&b));
        assert!(pick_by(&[ra.clone()], NS, "AAAAAAAA", t, now, same).is_ok());
        assert!(matches!(pick_by(&[ra.clone(), ra.clone()], NS, "AAAAAAAA", t, now, same), Ok(_)));
        assert!(matches!(pick_by(&[ra, rb], NS, "AAAAAAAA", t, now, same), Err(CodeError::Conflict)));
        assert!(matches!(pick(&[], NS, &code, now), Err(CodeError::NotFound)));
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
