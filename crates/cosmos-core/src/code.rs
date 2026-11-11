//! Join codes: a short human code resolves, through the DHT, to a
//! host-signed, encrypted session advert.
//!
//! - The code is bound to the host key through a slow hash:
//!   `code = 40 bits of Argon2id(H(namespace, host, salt))` with a random
//!   128-bit salt that only travels inside the encrypted advert. Without the
//!   advert body nobody can compute the code; with it (code holders only),
//!   forging an advert for another host means grinding ~2^40 Argon2id hashes.
//! - The code never appears in the DHT. `Argon2id(code, namespace, UTC day)`
//!   gives the advert topic and its AEAD key. The day in the salt makes a
//!   precomputed code -> topic table go stale every day. The host publishes
//!   under yesterday's, today's and tomorrow's topics, so a joiner whose
//!   clock is off by up to a day still finds it with one derivation.
//! - The advert body (host, addrs, salt, join secret, session key) is
//!   XChaCha20-Poly1305 encrypted. The join secret and session key are random
//!   per session, not a function of the code: reading them needs that
//!   session's advert plus a ~2^40 Argon2id table for one of its three days.

//! - Junk under a topic is rejected by the AEAD tag before any slow hash.
//!   More distinct decryptable hosts than `MAX_CHECKED` is a conflict.
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
const DOMAIN: &[u8] = b"cosmos-join:v4";
/// Records under one topic that get the (cheap) AEAD check.
const MAX_OPENED: usize = 64;
/// Distinct hosts that get the (slow) code check.
const MAX_CHECKED: usize = 4;
const VERSION: u8 = 3;
pub const SALT_LEN: usize = 16;
const MAX_ADDRS: usize = 16;
/// Republish interval; must stay under the node's record TTL.
const REFRESH: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(5);
const RESOLVE_DEADLINE: Duration = Duration::from_secs(20);
const DAY_SECS: u64 = 86_400;

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

fn random<const N: usize>() -> [u8; N] {
    let mut s = [0u8; N];
    getrandom::fill(&mut s).expect("os rng");
    s
}

/// A fresh secret advert salt.
pub fn new_salt() -> [u8; SALT_LEN] {
    random()
}

/// The UTC day number (the epoch in the topic salt).
pub fn today() -> u64 {
    now_secs() / DAY_SECS
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

/// Where a code's advert lives on one UTC day, and how it is sealed.
#[derive(Clone, PartialEq, Eq)]
pub struct DayKeys {
    pub day: u64,
    /// DHT topic of the advert.
    pub topic: String,
    /// Advert AEAD key.
    key: [u8; 32],
}

impl fmt::Debug for DayKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DayKeys").field("day", &self.day).field("topic", &self.topic).finish_non_exhaustive()
    }
}

/// Derive a (normalized) code's topic and advert key for `day`. Slow.
pub fn day_keys(namespace: &str, code: &str, day: u64) -> DayKeys {
    let salt = framed(&[DOMAIN, b"keys-salt", namespace.as_bytes(), &day.to_be_bytes()]);
    let d: [u8; 48] = slow(code.as_bytes(), &salt[..16]);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    DayKeys {
        day,
        topic: cosmos_net::topic_for(namespace, &format!("join/{hex}")),
        key: d[16..48].try_into().unwrap(),
    }
}

/// What a joiner learns from a valid advert.
#[derive(Clone, PartialEq, Eq)]
pub struct Advert {
    pub host: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub salt: [u8; SALT_LEN],
    /// Joiners present this to the host (random per session).
    pub secret: [u8; 16],
    /// Shared by every member: Steam handshake gate, private records.
    pub session: [u8; 32],
}

impl fmt::Debug for Advert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Advert").field("host", &self.host).field("addrs", &self.addrs).finish_non_exhaustive()
    }
}

impl Advert {
    /// Plaintext body.
    fn encode(&self, namespace: &str) -> Vec<u8> {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.secret);
        b.extend_from_slice(&self.session);
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
    pub fn seal(&self, namespace: &str, k: &DayKeys) -> Vec<u8> {
        crate::sealed::seal(&k.key, k.topic.as_bytes(), &self.encode(namespace))
    }

    fn open(data: &[u8], k: &DayKeys) -> Option<Vec<u8>> {
        crate::sealed::open(&k.key, k.topic.as_bytes(), data)
    }

    fn decode(b: &[u8]) -> Option<(String, Advert)> {
        let (&ver, rest) = b.split_first()?;
        if ver != VERSION || rest.len() < SALT_LEN + 16 + 32 {
            return None;
        }
        let (salt, rest) = rest.split_at(SALT_LEN);
        let (secret, rest) = rest.split_at(16);
        let (session, mut rest) = rest.split_at(32);
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
        Some((
            ns,
            Advert {
                host,
                addrs,
                salt: salt.try_into().ok()?,
                secret: secret.try_into().ok()?,
                session: session.try_into().ok()?,
            },
        ))
    }
}

/// Cheap checks: right topic, not expired, decrypts under the day key,
/// right namespace, signed by the host it names.
fn opened(rec: &Record, namespace: &str, k: &DayKeys, now_secs: u64) -> Option<Advert> {
    if rec.topic != k.topic || rec.expires <= now_secs {
        return None;
    }
    let (ns, a) = Advert::decode(&Advert::open(&rec.data, k)?)?;
    (ns == namespace && a.host == rec.publisher).then_some(a)
}

/// Validate a record found under a code's topic for `day` (cheap checks,
/// then the code really derives from the signer's key).
pub fn check(rec: &Record, namespace: &str, code: &str, day: u64, now_secs: u64) -> Option<Advert> {
    let a = opened(rec, namespace, &day_keys(namespace, code, day), now_secs)?;
    (code_for(namespace, &a.host, &a.salt) == code).then_some(a)
}

type Derive = fn(&str, &PeerId, &[u8; SALT_LEN]) -> String;

/// The one host a set of records names for `code`. Several distinct valid
/// hosts is a conflict (someone forged a code), never a silent pick.
pub fn pick(recs: &[Record], namespace: &str, code: &str, k: &DayKeys, now_secs: u64) -> Result<Advert, CodeError> {
    pick_by(recs, namespace, code, k, now_secs, code_for)
}

fn pick_by(
    recs: &[Record],
    namespace: &str,
    code: &str,
    k: &DayKeys,
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
    // Only code holders can make decryptable adverts; more hosts than we
    // check means one of them is flooding: say so instead of maybe missing
    // the real host.
    if cands.len() > MAX_CHECKED {
        return Err(CodeError::Conflict);
    }
    let mut found: Option<Advert> = None;
    for a in cands {
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
    /// Joiners must present this.
    pub secret: [u8; 16],
    /// The session key (see `Advert::session`).
    pub session: [u8; 32],
    task: JoinHandle<()>,
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Seal `advert` under the topics of `day`-1, `day` and `day`+1.
fn sealed_for(namespace: &str, code: &str, advert: &Advert, day: u64) -> Vec<(String, Vec<u8>)> {
    [day.saturating_sub(1), day, day + 1]
        .into_iter()
        .map(|d| {
            let k = day_keys(namespace, code, d);
            let data = advert.seal(namespace, &k);
            (k.topic, data)
        })
        .collect()
}

async fn publish_all(node: &Node, recs: &[(String, Vec<u8>)]) -> bool {
    let mut ok = true;
    for (topic, data) in recs {
        if let Err(e) = node.publish(topic, data.clone()).await {
            tracing::debug!("advert put: {e:#}");
            ok = false;
        }
    }
    ok
}

/// Publish a session advert for this node and return its join code.
pub async fn advertise(node: &Node, namespace: &str, addrs: Vec<Multiaddr>) -> anyhow::Result<Advertisement> {
    let advert = Advert { host: node.peer_id(), addrs, salt: new_salt(), secret: random(), session: random() };
    let (ns, a) = (namespace.to_string(), advert.clone());
    let (code, mut day, mut recs) = tokio::task::spawn_blocking(move || {
        let code = code_for(&ns, &a.host, &a.salt);
        let day = today();
        let recs = sealed_for(&ns, &code, &a, day);
        (code, day, recs)
    })
    .await?;
    // A lone host (empty mesh) cannot reach a DHT quorum. The records are
    // already held locally and served to whoever finds us, so keep hosting
    // and retry quickly until a put lands.
    let mut stored = publish_all(node, &recs).await;
    if !stored {
        tracing::info!("advert not stored on the DHT yet; retrying");
    }
    let (node, ns, c, a) = (node.clone(), namespace.to_string(), code.clone(), advert.clone());
    let task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(if stored { REFRESH } else { RETRY }).await;
            if today() != day {
                day = today();
                let (ns, c, a) = (ns.clone(), c.clone(), a.clone());
                match tokio::task::spawn_blocking(move || sealed_for(&ns, &c, &a, day)).await {
                    Ok(r) => recs = r,
                    Err(e) => tracing::debug!("advert reseal: {e}"),
                }
            }
            stored = publish_all(&node, &recs).await;
        }
    });
    Ok(Advertisement { code, secret: advert.secret, session: advert.session, task })
}

/// Today's keys for `code` (slow). Retry loops derive once and call
/// `resolve_with`.
pub async fn keys_today(namespace: &str, code: &str) -> Result<DayKeys, CodeError> {
    let code = normalize(code).ok_or(CodeError::BadCode)?;
    let ns = namespace.to_string();
    tokio::task::spawn_blocking(move || day_keys(&ns, &code, today()))
        .await
        .map_err(|e| CodeError::Net(e.into()))
}

/// Find the host behind `code`.
pub async fn resolve(node: &Node, namespace: &str, code: &str) -> Result<Advert, CodeError> {
    let k = keys_today(namespace, code).await?;
    resolve_with(node, namespace, code, &k).await
}

/// `resolve` with the day's keys already derived.
pub async fn resolve_with(node: &Node, namespace: &str, code: &str, k: &DayKeys) -> Result<Advert, CodeError> {
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
    const DAY: u64 = 20_000;

    fn signed(k: &Keypair, topic: &str, data: Vec<u8>) -> Record {
        Record::verify(&Record::sign(k, topic, data, Duration::from_secs(300)).unwrap()).unwrap()
    }

    fn advert(host: PeerId) -> Advert {
        Advert {
            host,
            addrs: vec!["/ip4/1.2.3.4/udp/9/quic-v1".parse().unwrap()],
            salt: new_salt(),
            secret: random(),
            session: random(),
        }
    }

    fn host_advert(k: &Keypair) -> (String, Advert, Record) {
        let a = advert(k.public().to_peer_id());
        let code = code_for(NS, &a.host, &a.salt);
        let keys = day_keys(NS, &code, DAY);
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
    /// able to compute the code or read the session's secrets.
    #[test]
    fn advert_record_does_not_reveal_host_salt_or_secrets() {
        let k = Keypair::generate_ed25519();
        let (code, a, rec) = host_advert(&k);
        let hay = &rec.data;
        let has = |needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(!has(&a.salt), "salt readable in the record");
        assert!(!has(&a.secret) && !has(&a.session), "secrets readable in the record");
        assert!(!has(&a.host.to_bytes()), "host id readable in the body");
        assert!(!has(&a.addrs[0].to_vec()), "addrs readable in the record");
        assert!(!has(code.as_bytes()));
        let wrong = day_keys(NS, "00000000", DAY);
        assert!(Advert::open(&rec.data, &DayKeys { topic: rec.topic.clone(), ..wrong }).is_none());
    }

    /// Review finding 1: the topic and key change every day, so a
    /// precomputed code -> topic table goes stale.
    #[test]
    fn day_keys_rotate_daily() {
        let a = day_keys(NS, "7K3QM9XA", DAY);
        let b = day_keys(NS, "7K3QM9XA", DAY + 1);
        assert_ne!(a.topic, b.topic);
        assert_ne!(a.key, b.key);
        assert_eq!(a, day_keys(NS, "7K3QM9XA", DAY));
        assert_ne!(a.topic, day_keys("other-game", "7K3QM9XA", DAY).topic);
    }

    #[test]
    fn host_seals_for_neighbour_days() {
        let a = advert(PeerId::random());
        let recs = sealed_for(NS, "7K3QM9XA", &a, DAY);
        let topics: Vec<_> = recs.iter().map(|r| r.0.clone()).collect();
        let want: Vec<_> = [DAY - 1, DAY, DAY + 1].iter().map(|d| day_keys(NS, "7K3QM9XA", *d).topic).collect();
        assert_eq!(topics, want);
    }

    #[test]
    fn genuine_advert_accepted() {
        let k = Keypair::generate_ed25519();
        let (code, a, rec) = host_advert(&k);
        let got = check(&rec, NS, &code, DAY, now_secs()).expect("rejected");
        assert_eq!(got, a);
        assert!(check(&rec, NS, &code, DAY + 1, now_secs()).is_none(), "wrong day accepted");
    }

    #[test]
    fn forged_advert_rejected() {
        let host = Keypair::generate_ed25519();
        let (code, a, rec) = host_advert(&host);
        let keys = day_keys(NS, &code, DAY);
        // An attacker re-signs the host's advert under the same code.
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec.topic, rec.data.clone());
        assert!(check(&forged, NS, &code, DAY, now_secs()).is_none());
        // A code holder claims the host's id inside its own advert.
        let lie = Advert { addrs: vec![], ..a.clone() };
        let forged = signed(&evil, &rec.topic, lie.seal(NS, &keys));
        assert!(check(&forged, NS, &code, DAY, now_secs()).is_none());
        // Or names itself with the real salt: the code does not derive.
        let me = Advert { host: evil.public().to_peer_id(), ..a };
        let forged = signed(&evil, &rec.topic, me.seal(NS, &keys));
        assert!(check(&forged, NS, &code, DAY, now_secs()).is_none());
    }

    #[test]
    fn pick_fails_on_two_valid_hosts_and_ignores_junk() {
        let a = Keypair::generate_ed25519();
        let (code, _, rec_a) = host_advert(&a);
        let k = day_keys(NS, &code, DAY);
        let now = now_secs();
        assert_eq!(pick(&[rec_a.clone()], NS, &code, &k, now).unwrap().host, a.public().to_peer_id());
        let evil = Keypair::generate_ed25519();
        let forged = signed(&evil, &rec_a.topic, rec_a.data.clone());
        let junk = signed(&evil, &rec_a.topic, vec![1, 2, 3]);
        assert_eq!(pick(&[forged, junk, rec_a.clone()], NS, &code, &k, now).unwrap().host, a.public().to_peer_id());
        fn same(_: &str, _: &PeerId, _: &[u8; SALT_LEN]) -> String {
            "AAAAAAAA".into()
        }
        let k = day_keys(NS, "AAAAAAAA", DAY);
        let b = Keypair::generate_ed25519();
        let adv = |kp: &Keypair| signed(kp, &k.topic, advert(kp.public().to_peer_id()).seal(NS, &k));
        let (ra, rb) = (adv(&a), adv(&b));
        assert!(pick_by(&[ra.clone()], NS, "AAAAAAAA", &k, now, same).is_ok());
        assert!(pick_by(&[ra.clone(), ra.clone()], NS, "AAAAAAAA", &k, now, same).is_ok());
        assert!(matches!(pick_by(&[ra, rb], NS, "AAAAAAAA", &k, now, same), Err(CodeError::Conflict)));
        assert!(matches!(pick(&[], NS, &code, &k, now), Err(CodeError::NotFound)));
    }

    /// Audit finding 8 and review finding 2: planted records cost no slow
    /// hashes, and a Sybil flood of decryptable adverts is a conflict, not a
    /// silent NotFound that hides the real host.
    #[test]
    fn planted_records_cost_no_slow_hashes_and_floods_conflict() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting(_: &str, _: &PeerId, _: &[u8; SALT_LEN]) -> String {
            CALLS.fetch_add(1, Ordering::SeqCst);
            "ZZZZZZZZ".into()
        }
        let k = day_keys(NS, "AAAAAAAA", DAY);
        let now = now_secs();
        let mut recs = vec![];
        // Outsiders (no code): they can't encrypt.
        for i in 0..40u8 {
            let kp = Keypair::generate_ed25519();
            let mut body = vec![VERSION];
            body.extend_from_slice(&[i; 64]);
            recs.push(signed(&kp, &k.topic, body));
        }
        // One code holder planting many copies.
        let kp = Keypair::generate_ed25519();
        for _ in 0..40 {
            recs.push(signed(&kp, &k.topic, advert(kp.public().to_peer_id()).seal(NS, &k)));
        }
        let _ = pick_by(&recs, NS, "AAAAAAAA", &k, now, counting);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "slow checks per resolve");
        // Code holders with MAX_CHECKED+1 Sybil keys.
        let flood: Vec<_> = (0..=MAX_CHECKED)
            .map(|_| {
                let kp = Keypair::generate_ed25519();
                signed(&kp, &k.topic, advert(kp.public().to_peer_id()).seal(NS, &k))
            })
            .collect();
        assert!(matches!(pick_by(&flood, NS, "AAAAAAAA", &k, now, counting), Err(CodeError::Conflict)));
    }

    #[test]
    fn expired_wrong_namespace_or_code_rejected() {
        let k = Keypair::generate_ed25519();
        let (code, _, rec) = host_advert(&k);
        let expired = Record { expires: now_secs() - 1, ..rec.clone() };
        assert!(check(&expired, NS, &code, DAY, now_secs()).is_none());
        assert!(check(&rec, "other-game", &code, DAY, now_secs()).is_none());
        let other = code_for(NS, &PeerId::random(), &new_salt());
        assert!(check(&rec, NS, &other, DAY, now_secs()).is_none());
        let mut garbage = rec.clone();
        garbage.data.push(0);
        assert!(check(&garbage, NS, &code, DAY, now_secs()).is_none());
    }
}
