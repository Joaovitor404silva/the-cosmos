//! C ABI over the SDK (M5): `cosmos.dll` + `include/cosmos.h`.
//!
//! Poll-based: background tasks on an internal tokio runtime push events
//! into a bounded queue; `cosmos_poll` hands them out one at a time. Every
//! export catches panics and null-checks its pointers.

#![allow(clippy::missing_safety_doc)]

use cosmos_core::code::{self, Advertisement, CodeError};
use cosmos_core::records::{self, Entry, RecordError, Records, RecordsConfig};
use cosmos_core::{
    Delivery, JoinError, NetTransport, PathConfig, PathSet, PeerId, SendError, Session, SessionConfig, SessionEvent,
    Transport,
};
use cosmos_net::{Config, Keypair, Multiaddr, Node};
use cosmos_steam::{DhtDirectory, SteamApi, SteamConfig};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, c_char, c_void};
use std::fmt::Display;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

#[cfg(test)]
mod tests;

/// Success.
pub const COSMOS_OK: i32 = 0;
/// A required pointer was NULL.
pub const COSMOS_E_NULL: i32 = -1;
/// Bad argument: not UTF-8, malformed join code, bad record kind/key/ttl.
pub const COSMOS_E_INVALID: i32 = -2;
/// The library panicked inside the call; the handle may still be usable.
pub const COSMOS_E_PANIC: i32 = -3;
/// Wrong state: no session yet, or this handle already used its session.
pub const COSMOS_E_STATE: i32 = -4;
/// Unknown peer handle, join code, or subscription.
pub const COSMOS_E_NOT_FOUND: i32 = -5;
/// The session already has 4 players.
pub const COSMOS_E_FULL: i32 = -6;
pub const COSMOS_E_TIMEOUT: i32 = -7;
/// Network failure (no route, DHT publish failed, ...). Often worth a retry.
pub const COSMOS_E_NET: i32 = -8;
/// Message or record over its size cap.
pub const COSMOS_E_TOO_LARGE: i32 = -9;
/// Too many record puts; retry later.
pub const COSMOS_E_RATE_LIMITED: i32 = -10;
/// Send queue to that peer is full.
pub const COSMOS_E_BACKLOG: i32 = -11;
/// The session is over (the host left).
pub const COSMOS_E_ENDED: i32 = -12;
/// Output buffer too small.
pub const COSMOS_E_BUFFER: i32 = -13;
/// Reading or writing a file (the key file) failed.
pub const COSMOS_E_IO: i32 = -14;

/// No event (`cosmos_poll` returned 0).
pub const COSMOS_EV_NONE: i32 = 0;
/// `peer` joined the session.
pub const COSMOS_EV_PEER_JOINED: i32 = 1;
/// `peer` left the session.
pub const COSMOS_EV_PEER_LEFT: i32 = 2;
/// Message from `peer` on `channel`: `data`/`len`, `reliable`.
pub const COSMOS_EV_MESSAGE: i32 = 3;
/// Traffic to `peer` moved to `path` (`COSMOS_PATH_*`).
pub const COSMOS_EV_PATH_CHANGED: i32 = 4;
/// Answer to `cosmos_record_query` number `req_id`: one event per record,
/// `index` of `count`; `count == 0` means none found, `error < 0` failed.
pub const COSMOS_EV_RECORD_RESULT: i32 = 5;
/// New record on subscription `req_id` (the id `cosmos_record_subscribe` returned).
pub const COSMOS_EV_RECORD_UPDATE: i32 = 6;
/// The host left; the session is over.
pub const COSMOS_EV_SESSION_ENDED: i32 = 7;
/// Background error `error` (about `peer` if nonzero), text in `message`.
pub const COSMOS_EV_ERROR: i32 = 8;

pub const COSMOS_PATH_UNKNOWN: i32 = 0;
/// Direct or hole-punched connection.
pub const COSMOS_PATH_DIRECT: i32 = 1;
/// Steam Datagram Relay.
pub const COSMOS_PATH_RELAY: i32 = 2;

/// `cosmos_send` peer: everyone. `cosmos_peer_id` peer: this instance.
pub const COSMOS_BROADCAST: u32 = 0;
/// Buffer size for a join code ("XXXX-XXXX" + NUL fits).
pub const COSMOS_CODE_MAX: usize = 12;
/// Buffer size that fits any peer id (38 bytes today).
pub const COSMOS_PEER_ID_MAX: usize = 64;

const DEFAULT_QUEUE: usize = 1024;
/// Largest `event_queue` honoured.
const QUEUE_MAX: usize = 65536;
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
const STEAM_REPUBLISH: Duration = Duration::from_secs(240);

/// Settings for `cosmos_init`. Zero everything you don't set.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CosmosConfig {
    /// Required. Game id, namespaces join codes and records:
    /// 1-64 chars of `A-Z a-z 0-9 _ . -`.
    pub game_id: *const c_char,
    /// File with this player's key, created if missing. NULL: new key each run.
    pub key_path: *const c_char,
    /// IP to listen on, e.g. "127.0.0.1" for tests. NULL: all interfaces.
    pub listen: *const c_char,
    /// Comma-separated multiaddrs to bootstrap from. NULL: none.
    pub bootstrap: *const c_char,
    /// Directory for the record cache. NULL: memory only.
    pub cache_dir: *const c_char,
    /// Nonzero: LAN discovery (mDNS) and UPnP port mapping.
    pub lan: i32,
    /// Nonzero: add the Steam relay path when Steam is running. When it is
    /// not, the path stays off without an error.
    pub steam: i32,
    /// Absolute path of steam_api64.dll. NULL: the one next to the exe.
    pub steam_dll: *const c_char,
    /// AppID for our own Steam init (ignored when the game already runs
    /// Steam). 0: 480.
    pub steam_app_id: u32,
    /// Events kept before the oldest are dropped. 0: 1024.
    pub event_queue: u32,
}

impl Default for CosmosConfig {
    fn default() -> Self {
        CosmosConfig {
            game_id: null(),
            key_path: null(),
            listen: null(),
            bootstrap: null(),
            cache_dir: null(),
            lan: 0,
            steam: 0,
            steam_dll: null(),
            steam_app_id: 0,
            event_queue: 0,
        }
    }
}

/// One event from `cosmos_poll`. Pointers stay valid until the next
/// `cosmos_poll` or `cosmos_shutdown` on the same handle.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CosmosEvent {
    /// `COSMOS_EV_*`.
    pub kind: i32,
    /// Peer handle (see `cosmos_peer_id`), 0 if none.
    pub peer: u32,
    pub channel: u8,
    /// 1 if sent reliable.
    pub reliable: u8,
    /// `COSMOS_PATH_*` for `COSMOS_EV_PATH_CHANGED`.
    pub path: i32,
    /// Query request id or subscription id.
    pub req_id: u32,
    /// `COSMOS_OK` or a `COSMOS_E_*` code.
    pub error: i32,
    /// Message or record payload.
    pub data: *const u8,
    pub len: usize,
    /// NUL-terminated record kind and key.
    pub record_kind: *const c_char,
    pub record_key: *const c_char,
    /// Record publisher's peer id bytes.
    pub publisher: *const u8,
    pub publisher_len: usize,
    /// Record signing time (Unix ms) and expiry (Unix s).
    pub issued_ms: u64,
    pub expires_s: u64,
    /// Record result position: `index` of `count`.
    pub index: u32,
    pub count: u32,
    /// NUL-terminated error text, or NULL.
    pub message: *const c_char,
}

impl Default for CosmosEvent {
    fn default() -> Self {
        CosmosEvent {
            kind: COSMOS_EV_NONE,
            peer: 0,
            channel: 0,
            reliable: 0,
            path: COSMOS_PATH_UNKNOWN,
            req_id: 0,
            error: COSMOS_OK,
            data: null(),
            len: 0,
            record_kind: null(),
            record_key: null(),
            publisher: null(),
            publisher_len: 0,
            issued_ms: 0,
            expires_s: 0,
            index: 0,
            count: 0,
            message: null(),
        }
    }
}

// ---- errors and the panic guard ----

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

#[cfg(test)]
thread_local! {
    static INJECT_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test hook: the next guarded call on this thread panics inside the guard.
#[cfg(test)]
fn inject_panic() {
    INJECT_PANIC.with(|c| c.set(true));
}

fn set_error(msg: &str) {
    let c = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = c);
}

struct Fail(i32, String);

fn fail(code: i32, msg: impl Display) -> Fail {
    Fail(code, msg.to_string())
}

/// Run `f`, turning a panic into `on_panic` (and the last-error text).
fn guard<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    let r = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        if INJECT_PANIC.with(|c| c.replace(false)) {
            panic!("injected test panic");
        }
        f()
    }));
    r.unwrap_or_else(|p| {
        let msg = p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        set_error(&format!("panic: {msg}"));
        on_panic
    })
}

/// Guarded call returning a status code.
fn call(f: impl FnOnce() -> Result<i32, Fail>) -> i32 {
    guard(COSMOS_E_PANIC, || {
        f().unwrap_or_else(|Fail(code, msg)| {
            set_error(&msg);
            code
        })
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

unsafe fn handle<'a>(c: *const Cosmos) -> Result<&'a Cosmos, Fail> {
    unsafe { c.as_ref() }.ok_or_else(|| fail(COSMOS_E_NULL, "null cosmos handle"))
}

unsafe fn opt_str(p: *const c_char, what: &str) -> Result<Option<String>, Fail> {
    if p.is_null() {
        return Ok(None);
    }
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().map(|s| Some(s.to_string())).map_err(|_| fail(COSMOS_E_INVALID, format!("{what} is not UTF-8")))
}

unsafe fn req_str(p: *const c_char, what: &str) -> Result<String, Fail> {
    unsafe { opt_str(p, what) }?.ok_or_else(|| fail(COSMOS_E_NULL, format!("{what} is null")))
}

unsafe fn bytes<'a>(p: *const c_void, len: usize) -> Result<&'a [u8], Fail> {
    match (p.is_null(), len) {
        (_, 0) => Ok(&[]),
        (true, _) => Err(fail(COSMOS_E_NULL, "data is null")),
        (false, n) => Ok(unsafe { std::slice::from_raw_parts(p.cast(), n) }),
    }
}

/// Copy `s` plus a NUL into `out`; returns the length without the NUL.
unsafe fn write_str(s: &str, out: *mut c_char, cap: usize) -> Result<i32, Fail> {
    if out.is_null() {
        return Err(fail(COSMOS_E_NULL, "output buffer is null"));
    }
    if s.len() + 1 > cap {
        return Err(fail(COSMOS_E_BUFFER, format!("need {} bytes", s.len() + 1)));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), out.cast(), s.len());
        *out.add(s.len()) = 0;
    }
    Ok(s.len() as i32)
}

fn join_err(e: JoinError) -> Fail {
    let code = match e {
        JoinError::Full => COSMOS_E_FULL,
        JoinError::Timeout => COSMOS_E_TIMEOUT,
        JoinError::NoPath(_) | JoinError::Transport(_) => COSMOS_E_NET,
    };
    fail(code, e)
}

fn send_err(e: SendError) -> Fail {
    let code = match e {
        SendError::NotMember => COSMOS_E_NOT_FOUND,
        SendError::TooLarge { .. } => COSMOS_E_TOO_LARGE,
        SendError::Backlog => COSMOS_E_BACKLOG,
        SendError::Ended => COSMOS_E_ENDED,
    };
    fail(code, e)
}

fn record_err(e: RecordError) -> Fail {
    let code = match e {
        RecordError::BadName | RecordError::BadTtl => COSMOS_E_INVALID,
        RecordError::TooLarge => COSMOS_E_TOO_LARGE,
        RecordError::RateLimited => COSMOS_E_RATE_LIMITED,
        RecordError::Net(_) => COSMOS_E_NET,
    };
    fail(code, e)
}

fn path_kind(name: &str) -> i32 {
    match name {
        "direct" => COSMOS_PATH_DIRECT,
        cosmos_steam::PATH_NAME => COSMOS_PATH_RELAY,
        _ => COSMOS_PATH_UNKNOWN,
    }
}

// ---- events ----

struct Rec {
    kind: CString,
    key: CString,
    publisher: Vec<u8>,
    data: Vec<u8>,
    issued: u64,
    expires: u64,
}

impl From<Entry> for Rec {
    fn from(e: Entry) -> Rec {
        Rec {
            kind: CString::new(e.kind).unwrap_or_default(),
            key: CString::new(e.key).unwrap_or_default(),
            publisher: e.publisher.to_bytes(),
            data: e.data,
            issued: e.issued,
            expires: e.expires,
        }
    }
}

enum Ev {
    Joined(u32),
    Left(u32),
    Message { peer: u32, channel: u8, reliable: bool, data: Vec<u8> },
    Path { peer: u32, path: i32 },
    Ended,
    RecordResult { req_id: u32, error: i32, message: Option<CString>, rec: Option<Rec>, index: u32, count: u32 },
    RecordUpdate { sub: u32, rec: Rec },
    Error { peer: u32, code: i32, message: CString },
}

impl Ev {
    /// Data events a full queue may drop.
    fn droppable(&self) -> bool {
        matches!(self, Ev::Message { .. } | Ev::RecordUpdate { .. })
    }

    /// Point `out` into `self`; valid while `self` lives.
    fn fill(&self, out: &mut CosmosEvent) {
        *out = CosmosEvent::default();
        let rec = |out: &mut CosmosEvent, r: &Rec| {
            out.data = r.data.as_ptr();
            out.len = r.data.len();
            out.record_kind = r.kind.as_ptr();
            out.record_key = r.key.as_ptr();
            out.publisher = r.publisher.as_ptr();
            out.publisher_len = r.publisher.len();
            out.issued_ms = r.issued;
            out.expires_s = r.expires;
        };
        match self {
            Ev::Joined(p) => (out.kind, out.peer) = (COSMOS_EV_PEER_JOINED, *p),
            Ev::Left(p) => (out.kind, out.peer) = (COSMOS_EV_PEER_LEFT, *p),
            Ev::Message { peer, channel, reliable, data } => {
                out.kind = COSMOS_EV_MESSAGE;
                out.peer = *peer;
                out.channel = *channel;
                out.reliable = *reliable as u8;
                out.data = data.as_ptr();
                out.len = data.len();
            }
            Ev::Path { peer, path } => (out.kind, out.peer, out.path) = (COSMOS_EV_PATH_CHANGED, *peer, *path),
            Ev::Ended => out.kind = COSMOS_EV_SESSION_ENDED,
            Ev::RecordResult { req_id, error, message, rec: r, index, count } => {
                out.kind = COSMOS_EV_RECORD_RESULT;
                out.req_id = *req_id;
                out.error = *error;
                out.message = message.as_ref().map_or(null(), |m| m.as_ptr());
                out.index = *index;
                out.count = *count;
                if let Some(r) = r {
                    rec(out, r);
                }
            }
            Ev::RecordUpdate { sub, rec: r } => {
                out.kind = COSMOS_EV_RECORD_UPDATE;
                out.req_id = *sub;
                rec(out, r);
            }
            Ev::Error { peer, code, message } => {
                out.kind = COSMOS_EV_ERROR;
                out.peer = *peer;
                out.error = *code;
                out.message = message.as_ptr();
            }
        }
    }
}

struct Queue {
    q: VecDeque<Ev>,
    cap: usize,
    dropped: u64,
}

#[derive(Default)]
struct Peers {
    ids: Vec<PeerId>,
    by_id: HashMap<PeerId, u32>,
}

/// State background tasks share with the handle.
struct Shared {
    queue: Mutex<Queue>,
    peers: Mutex<Peers>,
}

impl Shared {
    /// Queue `e`. When full, the oldest message / record update goes first;
    /// control events (joins, leaves, end, path, errors, query results) are
    /// kept unless they alone fill twice the cap.
    fn push(&self, e: Ev) {
        let mut q = lock(&self.queue);
        if q.q.len() >= q.cap {
            match q.q.iter().position(Ev::droppable) {
                Some(i) => drop(q.q.remove(i)),
                None if e.droppable() => {
                    q.dropped += 1;
                    return;
                }
                None if q.q.len() >= q.cap.saturating_mul(2) => drop(q.q.pop_front()),
                None => {
                    q.q.push_back(e);
                    return;
                }
            }
            q.dropped += 1;
        }
        q.q.push_back(e);
    }

    /// Stable handle for `p` (1, 2, ...; never reused within an instance).
    fn handle(&self, p: PeerId) -> u32 {
        let mut ps = lock(&self.peers);
        if let Some(h) = ps.by_id.get(&p) {
            return *h;
        }
        ps.ids.push(p);
        let h = ps.ids.len() as u32;
        ps.by_id.insert(p, h);
        h
    }

    fn peer(&self, h: u32) -> Option<PeerId> {
        lock(&self.peers).ids.get((h as usize).checked_sub(1)?).copied()
    }

    fn session_event(&self, e: SessionEvent) -> Ev {
        match e {
            SessionEvent::Joined(p) => Ev::Joined(self.handle(p)),
            SessionEvent::Left(p) => Ev::Left(self.handle(p)),
            SessionEvent::Message { from, channel, delivery, data } => Ev::Message {
                peer: self.handle(from),
                channel,
                reliable: delivery == Delivery::Reliable,
                data,
            },
            SessionEvent::Ended => Ev::Ended,
            SessionEvent::PathSwitch { peer, to, .. } => Ev::Path { peer: self.handle(peer), path: path_kind(&to) },
            SessionEvent::Overflow(p) => Ev::Error {
                peer: self.handle(p),
                code: COSMOS_E_BACKLOG,
                message: CString::new("peer left too much reliable data unacknowledged; dropped").unwrap(),
            },
        }
    }
}

// ---- the handle ----

struct State {
    ns: String,
    node: Node,
    records: Arc<Records>,
    shared: Arc<Shared>,
    /// Taken by the one session this handle may run.
    transport: Mutex<Option<Arc<dyn Transport>>>,
    session: Mutex<Option<Arc<Session>>>,
    advert: Mutex<Option<Advertisement>>,
    /// A host/join is in progress or done (only one per handle).
    starting: std::sync::atomic::AtomicBool,
    /// The event last handed out by `cosmos_poll`.
    current: Mutex<Option<Ev>>,
    subs: Mutex<HashMap<u32, JoinHandle<()>>>,
    next_sub: AtomicU32,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    steam: Option<Arc<SteamApi>>,
}

/// Opaque instance handle.
pub struct Cosmos {
    st: State,
    rt: Runtime,
}

fn load_key(path: Option<String>) -> Result<Keypair, Fail> {
    let Some(path) = path else { return Ok(Keypair::generate_ed25519()) };
    let path = PathBuf::from(path);
    match std::fs::read(&path) {
        Ok(b) => Keypair::from_protobuf_encoding(&b).map_err(|e| fail(COSMOS_E_INVALID, format!("key file: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = Keypair::generate_ed25519();
            let b = k.to_protobuf_encoding().map_err(|e| fail(COSMOS_E_IO, e))?;
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| fail(COSMOS_E_IO, format!("key dir: {e}")))?;
            }
            std::fs::write(&path, b).map_err(|e| fail(COSMOS_E_IO, format!("key file: {e}")))?;
            Ok(k)
        }
        Err(e) => Err(fail(COSMOS_E_IO, format!("key file: {e}"))),
    }
}

fn listen_addrs(ip: &str) -> Result<Vec<Multiaddr>, Fail> {
    let ip: std::net::IpAddr = ip.parse().map_err(|_| fail(COSMOS_E_INVALID, format!("bad listen ip {ip}")))?;
    let p = if ip.is_ipv6() { "ip6" } else { "ip4" };
    Ok(vec![
        format!("/{p}/{ip}/udp/0/quic-v1").parse().unwrap(),
        format!("/{p}/{ip}/tcp/0").parse().unwrap(),
    ])
}

unsafe fn init(cfg: *const CosmosConfig) -> Result<Box<Cosmos>, Fail> {
    let cfg = unsafe { cfg.as_ref() }.ok_or_else(|| fail(COSMOS_E_NULL, "null config"))?;
    let ns = unsafe { req_str(cfg.game_id, "game_id") }?;
    let key = load_key(unsafe { opt_str(cfg.key_path, "key_path") }?)?;
    let listen = unsafe { opt_str(cfg.listen, "listen") }?;
    let bootstrap = unsafe { opt_str(cfg.bootstrap, "bootstrap") }?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<Multiaddr>().map_err(|_| fail(COSMOS_E_INVALID, format!("bad bootstrap addr {s}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let cache_dir = unsafe { opt_str(cfg.cache_dir, "cache_dir") }?.map(PathBuf::from);
    let steam_dll = unsafe { opt_str(cfg.steam_dll, "steam_dll") }?.map(PathBuf::from);
    let rcfg = RecordsConfig { cache_dir, ..RecordsConfig::new(&ns) };
    // Reject a bad game id before starting anything.
    records::topic(&ns, "k", "k").map_err(|_| fail(COSMOS_E_INVALID, "game_id: 1-64 chars of A-Z a-z 0-9 _ . -"))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("cosmos")
        .enable_all()
        .build()
        .map_err(|e| fail(COSMOS_E_IO, format!("runtime: {e}")))?;
    let net = Config {
        keypair: Some(key.clone()),
        listen: match &listen {
            Some(ip) => listen_addrs(ip)?,
            None => Config::default().listen,
        },
        bootstrap,
        mdns: cfg.lan != 0,
        upnp: cfg.lan != 0,
        ..Config::default()
    };
    let node = rt.block_on(Node::start(net)).map_err(|e| fail(COSMOS_E_NET, format!("node: {e:#}")))?;
    if listen.is_some() {
        // An explicit IP is reachable as is (LAN, loopback tests).
        for a in rt.block_on(node.listen_addrs()) {
            node.add_external_addr(a);
        }
    }

    let _g = rt.enter();
    let mut tasks = vec![];
    let direct = NetTransport::new(node.clone()).map_err(|e| fail(COSMOS_E_NET, e))?;
    let mut paths: Vec<(String, Arc<dyn Transport>)> = vec![("direct".into(), direct)];
    let mut steam = None;
    if cfg.steam != 0 {
        let dll = steam_dll.or_else(|| Some(std::env::current_exe().ok()?.parent()?.join(cosmos_steam::DLL_NAME)));
        let scfg = SteamConfig { app_id: if cfg.steam_app_id == 0 { 480 } else { cfg.steam_app_id }, dll };
        let dir = Arc::new(DhtDirectory { node: node.clone() });
        if let Some((name, t, api)) = cosmos_steam::steam_path(&scfg, key.clone(), dir) {
            paths.push((name, t));
            let (n, a) = (node.clone(), api.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Err(e) = cosmos_steam::publish_steam_id(&n, a.steam_id(), a.app_id()).await {
                        tracing::debug!("steam id publish: {e:#}");
                    }
                    tokio::time::sleep(STEAM_REPUBLISH).await;
                }
            }));
            steam = Some(api);
        }
    }
    let built = PathSet::new(paths, PathConfig::default())
        .map_err(|e| fail(COSMOS_E_NET, e))
        .and_then(|t| Ok((t, Arc::new(Records::new(node.clone(), rcfg).map_err(record_err)?))));
    let (transport, records): (Arc<dyn Transport>, _) = match built {
        Ok((t, r)) => (t as Arc<dyn Transport>, r),
        Err(e) => {
            if let Some(api) = &steam {
                api.release();
            }
            return Err(e);
        }
    };
    let cap = if cfg.event_queue == 0 { DEFAULT_QUEUE } else { (cfg.event_queue as usize).min(QUEUE_MAX) };
    let st = State {
        ns,
        node,
        records,
        shared: Arc::new(Shared {
            queue: Mutex::new(Queue { q: VecDeque::new(), cap, dropped: 0 }),
            peers: Mutex::new(Peers::default()),
        }),
        transport: Mutex::new(Some(transport)),
        session: Mutex::new(None),
        advert: Mutex::new(None),
        starting: std::sync::atomic::AtomicBool::new(false),
        current: Mutex::new(None),
        subs: Mutex::new(HashMap::new()),
        next_sub: AtomicU32::new(1),
        tasks: Mutex::new(tasks),
        steam,
    };
    drop(_g);
    Ok(Box::new(Cosmos { st, rt }))
}

impl Cosmos {
    #[cfg(test)]
    fn push(&self, e: Ev) {
        self.st.shared.push(e);
    }

    /// The unused transport, or `E_STATE`.
    fn take_transport(&self) -> Result<Arc<dyn Transport>, Fail> {
        lock(&self.st.transport)
            .take()
            .ok_or_else(|| fail(COSMOS_E_STATE, "this handle already started a session; create a new one"))
    }

    fn start_session(&self, mut s: Session) {
        let mut rx = s.take_events().expect("fresh session");
        let shared = self.st.shared.clone();
        let pump = self.rt.spawn(async move {
            while let Some(e) = rx.recv().await {
                let ev = shared.session_event(e);
                shared.push(ev);
            }
        });
        lock(&self.st.tasks).push(pump);
        *lock(&self.st.session) = Some(Arc::new(s));
    }

    /// Claim the handle's one host/join, or `E_STATE`.
    fn begin(&self) -> Result<(), Fail> {
        if self.st.starting.swap(true, Ordering::AcqRel) || lock(&self.st.transport).is_none() {
            return Err(fail(COSMOS_E_STATE, "this handle already started a session; create a new one"));
        }
        Ok(())
    }

    fn host(&self) -> Result<String, Fail> {
        self.begin()?;
        let r = self.host_inner();
        if r.is_err() && lock(&self.st.transport).is_some() {
            // Failed before the session took the transport: may retry.
            self.st.starting.store(false, Ordering::Release);
        }
        r
    }

    fn host_inner(&self) -> Result<String, Fail> {
        let t = lock(&self.st.transport).clone().unwrap();
        let st = &self.st;
        let adv = self.rt.block_on(async {
            let addrs = t.local_addrs().await;
            code::advertise(&st.node, &st.ns, addrs).await
        });
        let adv = adv.map_err(|e| fail(COSMOS_E_NET, format!("advertise: {e:#}")))?;
        let t = self.take_transport()?;
        let cfg = SessionConfig { join_secret: Some(adv.secret), ..SessionConfig::default() };
        let s = self.rt.block_on(Session::host(t, cfg)).map_err(join_err)?;
        self.start_session(s);
        let code = code::pretty(&adv.code);
        *lock(&self.st.advert) = Some(adv);
        Ok(code)
    }

    fn join(&self, code: &str) -> Result<(), Fail> {
        let code = code::normalize(code).ok_or_else(|| fail(COSMOS_E_INVALID, "malformed join code"))?;
        self.begin()?;
        let r = self.join_inner(code);
        if r.is_err() && lock(&self.st.transport).is_some() {
            self.st.starting.store(false, Ordering::Release);
        }
        r
    }

    fn join_inner(&self, code: String) -> Result<(), Fail> {
        let st = &self.st;
        let start = Instant::now();
        let advert = self.rt.block_on(async {
            loop {
                match code::resolve(&st.node, &st.ns, &code).await {
                    Ok(a) => return Ok(a),
                    Err(e @ (CodeError::NotFound | CodeError::Net(_))) => {
                        if start.elapsed() > JOIN_TIMEOUT {
                            let c = if matches!(e, CodeError::NotFound) { COSMOS_E_NOT_FOUND } else { COSMOS_E_NET };
                            return Err(fail(c, e));
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e @ CodeError::BadCode) => return Err(fail(COSMOS_E_INVALID, e)),
                    Err(e @ CodeError::Conflict) => return Err(fail(COSMOS_E_NOT_FOUND, e)),
                }
            }
        })?;
        let (ns, c) = (st.ns.clone(), code.clone());
        let secret = self
            .rt
            .block_on(async { tokio::task::spawn_blocking(move || code::join_secret(&ns, &c)).await })
            .map_err(|e| fail(COSMOS_E_PANIC, e))?;
        let t = self.take_transport()?;
        let cfg = SessionConfig { join_secret: Some(secret), join_timeout: JOIN_TIMEOUT, ..SessionConfig::default() };
        let s = self.rt.block_on(Session::join(t, cfg, advert.host, advert.addrs)).map_err(join_err)?;
        self.start_session(s);
        Ok(())
    }

    fn session(&self) -> Result<Arc<Session>, Fail> {
        lock(&self.st.session).clone().ok_or_else(|| fail(COSMOS_E_STATE, "no session: host or join first"))
    }

    fn query(&self, kind: String, key: String, req_id: u32) -> Result<(), Fail> {
        records::topic(&self.st.ns, &kind, &key).map_err(record_err)?;
        let (r, shared) = (self.st.records.clone(), self.st.shared.clone());
        let task = self.rt.spawn(async move {
            match r.query(&kind, &key).await {
                Ok(v) if v.is_empty() => shared.push(Ev::RecordResult {
                    req_id,
                    error: COSMOS_OK,
                    message: None,
                    rec: None,
                    index: 0,
                    count: 0,
                }),
                Ok(v) => {
                    let count = v.len() as u32;
                    for (i, e) in v.into_iter().enumerate() {
                        shared.push(Ev::RecordResult {
                            req_id,
                            error: COSMOS_OK,
                            message: None,
                            rec: Some(e.into()),
                            index: i as u32,
                            count,
                        });
                    }
                }
                Err(e) => {
                    let Fail(code, msg) = record_err(e);
                    shared.push(Ev::RecordResult {
                        req_id,
                        error: code,
                        message: CString::new(msg).ok(),
                        rec: None,
                        index: 0,
                        count: 0,
                    });
                }
            }
        });
        let mut tasks = lock(&self.st.tasks);
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
        Ok(())
    }

    fn subscribe(&self, kind: &str, key: &str) -> Result<i32, Fail> {
        let _g = self.rt.enter();
        let mut sub = self.st.records.subscribe(kind, key).map_err(record_err)?;
        let id = self.st.next_sub.fetch_add(1, Ordering::Relaxed);
        if id > i32::MAX as u32 {
            return Err(fail(COSMOS_E_STATE, "out of subscription ids"));
        }
        let shared = self.st.shared.clone();
        let task = tokio::spawn(async move {
            while let Some(e) = sub.next().await {
                shared.push(Ev::RecordUpdate { sub: id, rec: e.into() });
            }
        });
        lock(&self.st.subs).insert(id, task);
        Ok(id as i32)
    }

    fn close(self) {
        let Cosmos { st, rt } = self;
        // Called from inside some other tokio runtime: we can neither
        // block_on nor drop a runtime there.
        let nested = tokio::runtime::Handle::try_current().is_ok();
        {
            let _g = rt.enter();
            if let Some(s) = lock(&st.session).take() {
                s.leave();
                if nested {
                    std::thread::sleep(Duration::from_millis(200));
                } else {
                    // Let the goodbye frames go out before the runtime stops.
                    rt.block_on(tokio::time::sleep(Duration::from_millis(200)));
                }
            }
            for (_, t) in lock(&st.subs).drain() {
                t.abort();
            }
            for t in lock(&st.tasks).drain(..) {
                t.abort();
            }
            if let Some(api) = &st.steam {
                api.release();
            }
            drop(st);
        }
        if nested {
            rt.shutdown_background();
        } else {
            rt.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

// ---- exports ----

/// Library version, e.g. "0.1.0". Static string.
#[unsafe(no_mangle)]
pub extern "C" fn cosmos_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Text of the last error on the calling thread ("" if none). Valid until
/// the next failing call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn cosmos_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Name of a `COSMOS_OK` / `COSMOS_E_*` code. Static string.
#[unsafe(no_mangle)]
pub extern "C" fn cosmos_error_name(code: i32) -> *const c_char {
    let s: &CStr = match code {
        COSMOS_OK => c"COSMOS_OK",
        COSMOS_E_NULL => c"COSMOS_E_NULL",
        COSMOS_E_INVALID => c"COSMOS_E_INVALID",
        COSMOS_E_PANIC => c"COSMOS_E_PANIC",
        COSMOS_E_STATE => c"COSMOS_E_STATE",
        COSMOS_E_NOT_FOUND => c"COSMOS_E_NOT_FOUND",
        COSMOS_E_FULL => c"COSMOS_E_FULL",
        COSMOS_E_TIMEOUT => c"COSMOS_E_TIMEOUT",
        COSMOS_E_NET => c"COSMOS_E_NET",
        COSMOS_E_TOO_LARGE => c"COSMOS_E_TOO_LARGE",
        COSMOS_E_RATE_LIMITED => c"COSMOS_E_RATE_LIMITED",
        COSMOS_E_BACKLOG => c"COSMOS_E_BACKLOG",
        COSMOS_E_ENDED => c"COSMOS_E_ENDED",
        COSMOS_E_BUFFER => c"COSMOS_E_BUFFER",
        COSMOS_E_IO => c"COSMOS_E_IO",
        _ => c"COSMOS_E_UNKNOWN",
    };
    s.as_ptr()
}

/// Start an instance (node, runtime, record store). NULL on failure; see
/// `cosmos_last_error`. One instance runs at most one session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_init(cfg: *const CosmosConfig) -> *mut Cosmos {
    guard(null_mut(), || match unsafe { init(cfg) } {
        Ok(c) => Box::into_raw(c),
        Err(Fail(_, msg)) => {
            set_error(&msg);
            null_mut()
        }
    })
}

/// Host a session. Blocks while the join code is published, then writes the
/// code ("XXXX-XXXX") to `code_out` (`COSMOS_CODE_MAX` bytes is enough).
/// `COSMOS_E_NET` right after start-up usually means no DHT peers yet: retry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_host(c: *mut Cosmos, code_out: *mut c_char, cap: usize) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        if code_out.is_null() {
            return Err(fail(COSMOS_E_NULL, "code_out is null"));
        }
        if cap < 10 {
            return Err(fail(COSMOS_E_BUFFER, "code_out needs 10 bytes"));
        }
        let code = c.host()?;
        unsafe { write_str(&code, code_out, cap) }?;
        Ok(COSMOS_OK)
    })
}

/// Join the session behind `code`. Blocks until admitted (up to ~30 s each
/// for the code lookup and the handshake). `PEER_JOINED` events follow for
/// the host and every member.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_join(c: *mut Cosmos, code: *const c_char) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let code = unsafe { req_str(code, "code") }?;
        c.join(&code)?;
        Ok(COSMOS_OK)
    })
}

/// Send `len` bytes to `peer` (`COSMOS_BROADCAST`: every member) on
/// `channel`. `reliable` nonzero: ordered, no loss. Never blocks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_send(
    c: *mut Cosmos,
    peer: u32,
    channel: u8,
    data: *const c_void,
    len: usize,
    reliable: i32,
) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let data = unsafe { bytes(data, len) }?;
        let s = c.session()?;
        let d = if reliable != 0 { Delivery::Reliable } else { Delivery::Unreliable };
        if peer == COSMOS_BROADCAST {
            s.broadcast(channel, data, d).map_err(send_err)?;
        } else {
            let p = c.st.shared.peer(peer).ok_or_else(|| fail(COSMOS_E_NOT_FOUND, format!("unknown peer {peer}")))?;
            s.send(p, channel, data, d).map_err(send_err)?;
        }
        Ok(COSMOS_OK)
    })
}

/// Take the next event into `ev`. Returns 1 if there was one, 0 if the queue
/// is empty (`ev->kind == COSMOS_EV_NONE`), or an error. Pointers in `ev`
/// stay valid until the next `cosmos_poll` / `cosmos_shutdown` on `c`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_poll(c: *mut Cosmos, ev: *mut CosmosEvent) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let out = unsafe { ev.as_mut() }.ok_or_else(|| fail(COSMOS_E_NULL, "event is null"))?;
        let next = lock(&c.st.shared.queue).q.pop_front();
        let mut cur = lock(&c.st.current);
        *cur = next;
        match cur.as_ref() {
            Some(e) => {
                e.fill(out);
                Ok(1)
            }
            None => {
                *out = CosmosEvent::default();
                Ok(0)
            }
        }
    })
}

/// Events dropped because the queue was full (oldest go first).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_dropped_events(c: *const Cosmos) -> u64 {
    guard(0, || unsafe { c.as_ref() }.map_or(0, |c| lock(&c.st.shared.queue).dropped))
}

/// Write the id of `peer` (`COSMOS_BROADCAST` / 0: this instance) into
/// `out`. Returns its length (38 for today's keys) or an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_peer_id(c: *mut Cosmos, peer: u32, out: *mut u8, cap: usize) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        if out.is_null() {
            return Err(fail(COSMOS_E_NULL, "out is null"));
        }
        let id = if peer == 0 {
            c.st.node.peer_id()
        } else {
            c.st.shared.peer(peer).ok_or_else(|| fail(COSMOS_E_NOT_FOUND, format!("unknown peer {peer}")))?
        };
        let b = id.to_bytes();
        if b.len() > cap {
            return Err(fail(COSMOS_E_BUFFER, format!("need {} bytes", b.len())));
        }
        unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len()) };
        Ok(b.len() as i32)
    })
}

/// Comma-separated listen multiaddrs of this instance (usable as another
/// instance's `bootstrap`). Returns the string length or an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_listen_addrs(c: *mut Cosmos, out: *mut c_char, cap: usize) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let addrs = c.rt.block_on(c.st.node.listen_addrs());
        let s = addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        unsafe { write_str(&s, out, cap) }
    })
}

/// Sign and publish a record under (`kind`, `key`) for `ttl_s` seconds;
/// replaces this player's previous record there. Blocks for the publish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_record_put(
    c: *mut Cosmos,
    kind: *const c_char,
    key: *const c_char,
    data: *const c_void,
    len: usize,
    ttl_s: u32,
) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let kind = unsafe { req_str(kind, "kind") }?;
        let key = unsafe { req_str(key, "key") }?;
        let data = unsafe { bytes(data, len) }?.to_vec();
        let ttl = Duration::from_secs(ttl_s as u64);
        c.rt.block_on(c.st.records.put(&kind, &key, data, ttl)).map_err(record_err)?;
        Ok(COSMOS_OK)
    })
}

/// Look up records under (`kind`, `key`). Returns at once; results arrive
/// as `COSMOS_EV_RECORD_RESULT` events tagged with `req_id`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_record_query(c: *mut Cosmos, kind: *const c_char, key: *const c_char, req_id: u32) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let kind = unsafe { req_str(kind, "kind") }?;
        let key = unsafe { req_str(key, "key") }?;
        c.query(kind, key, req_id)?;
        Ok(COSMOS_OK)
    })
}

/// Watch (`kind`, `key`) for new records: `COSMOS_EV_RECORD_UPDATE` events
/// with `req_id` = the returned subscription id (> 0), or an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_record_subscribe(c: *mut Cosmos, kind: *const c_char, key: *const c_char) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let kind = unsafe { req_str(kind, "kind") }?;
        let key = unsafe { req_str(key, "key") }?;
        c.subscribe(&kind, &key)
    })
}

/// Stop subscription `sub`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_record_unsubscribe(c: *mut Cosmos, sub: i32) -> i32 {
    call(|| {
        let c = unsafe { handle(c) }?;
        let t = lock(&c.st.subs)
            .remove(&(sub as u32))
            .ok_or_else(|| fail(COSMOS_E_NOT_FOUND, format!("unknown subscription {sub}")))?;
        t.abort();
        Ok(COSMOS_OK)
    })
}

/// Leave the session, stop everything and free `c`. NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosmos_shutdown(c: *mut Cosmos) {
    if c.is_null() {
        return;
    }
    let c = unsafe { Box::from_raw(c) };
    guard((), move || c.close());
}
