//! Join codes: a short human code resolves, through the DHT, to a
//! host-signed, encrypted session advert.
//!
//! - The code is bound to the host key through a slow hash:
//!   `code = 40 bits of Argon2id(H(namespace, host, salt))` with a random
//!   128-bit salt that only travels inside the encrypted advert. Without the
//!   advert body nobody can compute the code; with it (code holders only),
//!   forging an advert for another host means grinding ~2^40 Argon2id hashes.
//! - The code never appears in the DHT. `Argon2id(code)` gives the advert
//!   topic, the join secret, the advert's AEAD key and a session key (shared
//!   by every member, e.g. to gate the Steam handshake).
//! - The advert body (host, addrs, salt) is XChaCha20-Poly1305 encrypted, so
//!   DHT and gossip nodes see only a signed blob under an opaque topic.
//! - Junk under a topic is rejected by the AEAD tag before any slow hash, and
//!   at most `MAX_CHECKED` distinct hosts get the slow check.
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
const DOMAIN: &[u8] = b"cosmos-join:v3";
/// Records under one topic that get the (cheap) AEAD check.
const MAX_OPENED: usize = 64;
/// Distinct hosts that get the (slow) code check.
const MAX_CHECKED: usize = 4;
const VERSION: u8 = 2;
pub const SALT_LEN: usize = 16;
const MAX_ADDRS: usize = 16;
/// Republish interval; must stay under the node's record TTL.
const REFRESH: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(5);
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
fn slow<const N: usize>(password: &[u8], salt: &[u8]) -> [u8; N] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(N)).expect("argon2 params");
    let mut out = [0u8; N];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut out)
        .expect("argon2");
    out
}

/// A fresh secret advert salt.
pub fn new_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    getrandom::fill(&mut s).expect("os rng");
    s
}

/// The code a host key and secret salt produce inside one game namespace.
pub fn code_for(namespace: &str, host: &PeerId, salt: &[u8; SALT_LEN]) -> String {
    let pw = framed(&[DOMAIN, b"code", namespace.as_bytes(), &host.to_bytes(), salt]);
    let d: [u8; 8] = slow(&pw, &framed(&[DOMAIN, b"code-salt", namespace.as_bytes()])[..16]);
    let bits = u64::from_be_bytes(d) >> (64 - 5 * CODE_LEN);
    (0..CODE_LEN)
        .rev()
        .map(|i| ALPHABET[((bits >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// What a code unlocks.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeKeys {
    /// DHT topic of the advert.
    pub topic: String,
    /// Joiners prove they hold the code with this.
    pub secret: [u8; 16],
    /// Advert AEAD key.
    key: [u8; 32],
    /// Shared by every session member (Steam handshake gate, private records).
    pub session: [u8; 32],
}

impl fmt::Debug for CodeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeKeys").field("topic", &self.topic).finish_non_exhaustive()
    }
}

/// Derive the topic and keys from a (normalized) code. Slow (Argon2id).
pub fn keys(namespace: &str, code: &str) -> CodeKeys {
    let d: [u8; 96] = slow(code.as_bytes(), &framed(&[DOMAIN, b"keys-salt", namespace.as_bytes()])[..16]);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    CodeKeys {
        topic: cosmos_net::topic_for(namespace, &format!("join/{hex}")),
        secret: d[16..32].try_into().unwrap(),
        key: d[32..64].try_into().unwrap(),
        session: d[64..96].try_into().unwrap(),
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
    pub salt: [u8; SALT_LEN],
}

impl Advert {
    /// Plaintext body.
    fn encode(&self, namespace: &str) -> Vec<u8> {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.salt);
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

    /// The record payload: `nonce || AEAD(body)`, bound to the topic.
    pub fn seal(&self, namespace: &str, k: &CodeKeys) -> Vec<u8> {
        crate::sealed::seal(&k.key, k.topic.as_bytes(), &self.encode(namespace))
    }

    fn open(data: &[u8], k: &CodeKeys) -> Option<Vec<u8>> {
        crate::sealed::open(&k.key, k.topic.as_bytes(), data)
    }

    fn decode(b: &[u8]) -> Option<(String, Advert)> {
        let (&ver, rest) = b.split_first()?;
        if ver != VERSION || rest.len() < SALT_LEN {
            return None;
        }
        let (salt, mut rest) = rest.split_at(SALT_LEN);
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
        Some((ns, Advert { host, addrs, salt: salt.try_into().ok()? }))
    }
}

/// Cheap checks: right topic, not expired, decrypts under the code's key,
/// right namespace, signed by the host it names.
fn opened(rec: &Record, namespace: &str, k: &CodeKeys, now_secs: u64) -> Option<Advert> {
    if rec.topic != k.topic || rec.expires <= now_secs {
        return None;
    }
    let (ns, a) = Advert::decode(&Advert::open(&rec.data, k)?)?;
    (ns == namespace && a.host == rec.publisher).then_some(a)
}

/// Validate a record found under a code's topic (cheap checks, then the code
/// really derives from the signer's key).
pub fn check(rec: &Record, namespace: &str, code: &str, now_secs: u64) -> Option<Advert> {
    let a = opened(rec, namespace, &keys(namespace, code), now_secs)?;
    (code_for(namespace, &a.host, &a.salt) == code).then_some(a)
}

type Derive = fn(&str, &PeerId, &[u8; SALT_LEN]) -> String;

/// The one host a set of records names for `code`. Several distinct valid
/// hosts is a conflict (someone forged a code), never a silent pick.
pub fn pick(recs: &[Record], namespace: &str, code: &str, now_secs: u64) -> Result<Advert, CodeError> {
    pick_by(recs, namespace, code, &keys(namespace, code), now_secs, code_for)
}

fn pick_by(
    recs: &[Record],
    namespace: &str,
    code: &str,
    k: &CodeKeys,
    now_secs: u64,
    derive: Derive,
) -> Result<Advert, CodeError> {
    // One candidate per host (its first decryptable advert), so planted
    // copies can't multiply the slow checks.
    let mut cands: Vec<Advert> = vec![];
    for r in recs.iter().filter(|r| r.topic == k.topic).take(MAX_OPENED) {
        if let Some(a) = opened(r, namespace, k, now_secs)
            && !cands.iter().any(|c| c.host == a.host)
        {
            cands.push(a);
        }
    }
    let mut found: Option<Advert> = None;
    for a in cands.into_iter().take(MAX_CHECKED) {
        if derive(namespace, &a.host, &a.salt) != code {
            continue;
        }
        if found.is_some() {
            return Err(CodeError::Conflict);
        }
        found = Some(a);
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
    /// The code's session key (see `CodeKeys::session`).
    pub session: [u8; 32],
    task: JoinHandle<()>,
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Publish a session advert for this node and return its join code.
pub async fn advertise(node: &Node, namespace: &str, addrs: Vec<Multiaddr>) -> anyhow::Result<Advertisement> {
    let advert = Advert { host: node.peer_id(), addrs, salt: new_salt() };
    let (ns, a) = (namespace.to_string(), advert.clone());
    let (code, k) = tokio::task::spawn_blocking(move || {
        let code = code_for(&ns, &a.host, &a.salt);
        let k = keys(&ns, &code);
        (code, k)
    })
    .await?;
    let data = advert.seal(namespace, &k);
    let topic = k.topic.clone();
    // A lone host (empty mesh) cannot reach a DHT quorum. The record is
    // already held locally and served to whoever finds us, so keep hosting
    // and retry quickly until a put lands.
    let mut stored = match node.publish(&topic, data.clone()).await {
        Ok(()) => true,
        Err(e) => {
            tracing::info!("advert not stored on the DHT yet: {e:#}");
            false
        }
    };
    let node = node.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(if stored { REFRESH } else { RETRY }).await;
            match node.publish(&topic, data.clone()).await {
                Ok(()) => stored = true,
                Err(e) => tracing::debug!("advert refresh failed: {e:#}"),
            }
        }
    });
    Ok(Advertisement { code, secret: k.secret, session: k.session, task })
}

/// Find the host behind `code`.
pub async fn resolve(node: &Node, namespace: &str, code: &str) -> Result<Advert, CodeError> {
    let code = normalize(code).ok_or(CodeError::BadCode)?;
    let (ns, c) = (namespace.to_string(), code.clone());
    let k = tokio::task::spawn_blocking(move || keys(&ns, &c))
        .await
        .map_err(|e| CodeError::Net(e.into()))?;
    resolve_with(node, namespace, &code, &k).await
}

/// `resolve` with the code's keys already derived (retry loops call this so
/// each attempt costs no Argon2 for the keys).
pub async fn resolve_with(node: &Node, namespace: &str, code: &str, k: &CodeKeys) -> Result<Advert, CodeError> {
    let code = normalize(code).ok_or(CodeError::BadCode)?;
    let recs = node
        .find_within(&k.topic, RESOLVE_DEADLINE)
        .await
        .map_err(CodeError::Net)?;
    let (ns, k) = (namespace.to_string(), k.clone());
    tokio::task::spawn_blocking(move || pick_by(&recs, &ns, &code, &k, now_secs(), code_for))
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

    fn host_advert(k: &Keypair) -> (String, Advert, Record) {
        let host = k.public().to_peer_id();
        let a = Advert { host, addrs: vec!["/ip4/1.2.3.4/udp/9/quic-v1".parse().unwrap()], salt: new_salt() };
        let code = code_for(NS, &host, &a.salt);
        let keys = keys(NS, &code);
        let rec = signed(k, &keys.topic, a.seal(NS, &keys));
        (code, a, rec)
    }

    #[test]
    fn code_shape_and_normalize() {
        let p = PeerId::random();
        let s = new_salt();
        let c = code_for(NS, &p, &s);
        assert_eq!(c.len(), CODE_LEN);
        assert!(c.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(c, code_for(NS, &p, &s));
        assert_ne!(c, code_for(NS, &p, &new_salt()));
        assert_ne!(c, code_for("other-game", &p, &s));
        assert_eq!(normalize(&pretty(&c).to_lowercase()), Some(c.clone()));
        assert_eq!(normalize("o1il-23 45"), Some("0111-2345".replace('-', "")));
        assert_eq!(normalize("ABCDEFG"), None);
        assert_eq!(normalize("ABCDEFGU"), None);
        assert_eq!(normalize("ABCDEFGH9"), None);
    }

    /// Audit finding 1: a DHT or gossip node holding the advert must not be
    /// able to compute the code (the old advert carried host + salt in clear).
    #[test]
    fn advert_record_does_not_reveal_host_salt_or_code() {
        let k = Keypair::generate_ed25519();
        let (code, a, rec) = host_advert(&k);
        let hay = &rec.data;
        let has = |needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(!has(&a.salt), "salt readable in the record");
        assert!(!has(&a.host.to_bytes()), "host id readable in the body");
        assert!(!has(&a.addrs[0].to_vec()), "addrs readable in the record");
        assert!(!has(NS.as_bytes()), "namespace readable in the body");
        assert!(!has(code.as_bytes()));
        // Without the code's key the body does not open.
        let wrong = keys(NS, "00000000");
        assert!(Advert::open(&rec.data, &CodeKeys { topic: rec.topic.clone(), ..wrong }).is_none());
    }

    #[test]
    fn genuine_advert_accepted() {
        let k = Keypair::generate_ed25519();
        let (code, _, rec) = host_advert(&k);
        let a = check(&rec, NS, &code, now_secs()).expect("rejected");
        assert_eq!(a.host, k.public().to_peer_id());
        assert_eq!(a.addrs.len(), 1);
    }

    #[test]
    fn forged_advert_rejected() {
        let host = Keypair::generate_ed25519();
        let (code, a, rec) = host_advert(&host);
        let keys = keys(NS, &code);
        // An attacker re-signs the host's advert under the same code.
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec.topic, rec.data.clone());
        assert!(check(&forged, NS, &code, now_secs()).is_none());
        // A code holder claims the host's id inside its own advert.
        let lie = Advert { addrs: vec![], ..a.clone() };
        let forged = signed(&evil, &rec.topic, lie.seal(NS, &keys));
        assert!(check(&forged, NS, &code, now_secs()).is_none());
        // Or names itself with the real salt: the code does not derive.
        let me = Advert { host: evil.public().to_peer_id(), ..a };
        let forged = signed(&evil, &rec.topic, me.seal(NS, &keys));
        assert!(check(&forged, NS, &code, now_secs()).is_none());
    }

    #[test]
    fn topic_hides_the_code_and_keys_differ_per_code() {
        let p = PeerId::random();
        let c = code_for(NS, &p, &new_salt());
        let k = keys(NS, &c);
        assert!(!k.topic.contains(&c), "code readable in the DHT topic");
        assert_eq!(k, keys(NS, &c));
        let other = code_for(NS, &p, &new_salt());
        let ko = keys(NS, &other);
        assert_ne!(k.secret, ko.secret);
        assert_ne!(k.session, ko.session);
        assert_ne!(k.topic, keys("other-game", &c).topic);
        assert_ne!(&k.secret[..], &k.session[..16]);
    }

    #[test]
    fn pick_fails_on_two_valid_hosts_and_ignores_junk() {
        let a = Keypair::generate_ed25519();
        let (code, _, rec_a) = host_advert(&a);
        let now = now_secs();
        assert_eq!(pick(&[rec_a.clone()], NS, &code, now).unwrap().host, a.public().to_peer_id());
        // Junk and forged records next to the real one don't change the pick.
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec_a.topic, rec_a.data.clone());
        let junk = signed(&evil, &rec_a.topic, vec![1, 2, 3]);
        assert_eq!(pick(&[forged, junk, rec_a.clone()], NS, &code, now).unwrap().host, a.public().to_peer_id());
        // Two valid adverts for one code from different hosts (as if a
        // 2^40 grind succeeded; simulated with a derive that ignores keys).
        fn same(_: &str, _: &PeerId, _: &[u8; SALT_LEN]) -> String {
            "AAAAAAAA".into()
        }
        let k = keys(NS, "AAAAAAAA");
        let b = Keypair::generate_ed25519();
        let adv = |kp: &Keypair| {
            let host = kp.public().to_peer_id();
            signed(kp, &k.topic, Advert { host, addrs: vec![], salt: [1; SALT_LEN] }.seal(NS, &k))
        };
        let (ra, rb) = (adv(&a), adv(&b));
        assert!(pick_by(&[ra.clone()], NS, "AAAAAAAA", &k, now, same).is_ok());
        assert!(pick_by(&[ra.clone(), ra.clone()], NS, "AAAAAAAA", &k, now, same).is_ok());
        assert!(matches!(pick_by(&[ra, rb], NS, "AAAAAAAA", &k, now, same), Err(CodeError::Conflict)));
        assert!(matches!(pick(&[], NS, &code, now), Err(CodeError::NotFound)));
    }

    /// Audit finding 8: planted records must not each cost a slow hash.
    #[test]
    fn planted_records_cost_no_slow_hashes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting(_: &str, _: &PeerId, _: &[u8; SALT_LEN]) -> String {
            CALLS.fetch_add(1, Ordering::SeqCst);
            "ZZZZZZZZ".into()
        }
        let k = keys(NS, "AAAAAAAA");
        let now = now_secs();
        let mut recs = vec![];
        // Outsiders (no code): random salts, but they can't encrypt.
        for i in 0..40u8 {
            let kp = Keypair::generate_ed25519();
            let host = kp.public().to_peer_id();
            let mut body = vec![VERSION];
            body.extend_from_slice(&[i; SALT_LEN]);
            body.extend_from_slice(&host.to_bytes());
            recs.push(signed(&kp, &k.topic, body));
        }
        // One code holder planting many copies with different salts.
        let kp = Keypair::generate_ed25519();
        let host = kp.public().to_peer_id();
        for i in 0..40u8 {
            recs.push(signed(&kp, &k.topic, Advert { host, addrs: vec![], salt: [i; SALT_LEN] }.seal(NS, &k)));
        }
        let _ = pick_by(&recs, NS, "AAAAAAAA", &k, now, counting);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "slow checks per resolve");
    }

    #[test]
    fn expired_wrong_namespace_or_code_rejected() {
        let k = Keypair::generate_ed25519();
        let (code, _, rec) = host_advert(&k);
        let expired = Record { expires: now_secs() - 1, ..rec.clone() };
        assert!(check(&expired, NS, &code, now_secs()).is_none());
        assert!(check(&rec, "other-game", &code, now_secs()).is_none());
        let other = code_for(NS, &PeerId::random(), &new_salt());
        assert!(check(&rec, NS, &other, now_secs()).is_none());
        let mut garbage = rec.clone();
        garbage.data.push(0);
        assert!(check(&garbage, NS, &code, now_secs()).is_none());
    }
}
