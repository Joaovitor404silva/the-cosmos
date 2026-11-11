//! The only unsafe code in the crate: `steam_api64.dll` loaded at runtime and
//! the few flat-API calls the Steam path needs.
//!
//! If the process already initialized Steam (a Steam game), its instance is
//! reused and never shut down by us. If the game loaded Steam but has not
//! initialized it yet, we stay off (`GameSteamNotReady`) rather than init it
//! as another AppID. Otherwise we load our bundled DLL, by absolute path
//! only, and init with the configured AppID (480, Spacewar, by default);
//! that only needs the Steam client running and logged in. Anything missing
//! comes back as `Unavailable`, never a panic.
//!
//! Reusing the game's Steam leaves its networking alone: we chain to its
//! session callbacks instead of replacing them, never close its per-user
//! sessions, and (if it set its own accept policy) only accept users Cosmos
//! is talking to.

use crate::backend::{SendError, SteamBackend, SteamEvent, SteamId};
use libloading::Library;
use std::ffi::c_void;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

#[cfg(windows)]
pub const DLL_NAME: &str = "steam_api64.dll";
#[cfg(target_os = "linux")]
pub const DLL_NAME: &str = "libsteam_api.so";
#[cfg(target_os = "macos")]
pub const DLL_NAME: &str = "libsteam_api.dylib";

/// Env var with a full path to the Steam API library (debug builds only).
pub const DLL_ENV: &str = "COSMOS_STEAM_API";

#[derive(Clone, Debug)]
pub struct SteamConfig {
    /// AppID for our own init; ignored when reusing the game's Steam. 0:
    /// none, so the path stays off unless the game already runs Steam.
    pub app_id: u32,
    /// Absolute path of the library to load (e.g. the copy shipped next to
    /// the exe). Debug builds fall back to `COSMOS_STEAM_API`. No search path
    /// is used.
    pub dll: Option<PathBuf>,
}

impl Default for SteamConfig {
    fn default() -> Self {
        Self { app_id: 480, dll: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    DllMissing(String),
    MissingSymbol(&'static str),
    SteamNotRunning,
    InitFailed(String),
    NotLoggedOn,
    /// The process loaded Steam but hasn't initialized it: a Steam game that
    /// is still starting. Try again later.
    GameSteamNotReady,
    /// We would init Steam ourselves but no AppID was configured.
    NoAppId,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unavailable::DllMissing(e) => write!(f, "Steam API library not loadable: {e}"),
            Unavailable::MissingSymbol(s) => write!(f, "Steam API library lacks {s}"),
            Unavailable::SteamNotRunning => f.write_str("Steam client not running"),
            Unavailable::InitFailed(e) => write!(f, "Steam init failed: {e}"),
            Unavailable::NotLoggedOn => f.write_str("Steam user not logged on"),
            Unavailable::GameSteamNotReady => f.write_str("the game loaded Steam but has not initialized it yet"),
            Unavailable::NoAppId => f.write_str("no AppID configured for our own Steam init"),
        }
    }
}

impl std::error::Error for Unavailable {}

// ---- flat API types (steamnetworkingtypes.h, SDK 1.6x) ----

const IDENTITY_STEAMID: i32 = 16;
const SEND_UNRELIABLE_NO_NAGLE: i32 = 1;
const SEND_RELIABLE_NO_NAGLE: i32 = 9;
const SEND_AUTO_RESTART: i32 = 32;
const CB_SESSION_REQUEST: i32 = 1251;
const CB_SESSION_FAILED: i32 = 1252;
const CFG_CALLBACK_SESSION_REQUEST: i32 = 204;
const CFG_CALLBACK_SESSION_FAILED: i32 = 205;
const CFG_SEND_BUFFER_SIZE: i32 = 9;
const CFG_SCOPE_GLOBAL: i32 = 1;
const CFG_GET_OK: i32 = 1;
/// Our send buffer per session when we own Steam (default is 512 KiB).
const SEND_BUFFER: i32 = 4 << 20;
const E_OK: i32 = 1;
const E_NO_CONNECTION: i32 = 3;
const E_BUSY: i32 = 10;
const E_LIMIT_EXCEEDED: i32 = 25;
const RECV_BATCH: usize = 64;

/// `SteamNetworkingIdentity` (pack 1, 136 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct Identity {
    kind: i32,
    size: i32,
    data: [u8; 128],
}

impl Identity {
    fn steam(id: SteamId) -> Identity {
        let mut data = [0u8; 128];
        data[..8].copy_from_slice(&id.to_le_bytes());
        Identity { kind: IDENTITY_STEAMID, size: 8, data }
    }

    fn steam_id(&self) -> Option<SteamId> {
        (self.kind == IDENTITY_STEAMID).then(|| u64::from_le_bytes(self.data[..8].try_into().unwrap()))
    }
}

/// `SteamNetworkingMessage_t` (pack 8); only the head is read.
#[repr(C)]
struct Message {
    data: *mut c_void,
    size: i32,
    conn: u32,
    peer: Identity,
    conn_user_data: i64,
    received: i64,
    number: i64,
    free_data: *mut c_void,
    release: *mut c_void,
    channel: i32,
    flags: i32,
    user_data: i64,
    lane: u16,
    pad: u16,
}

/// `CallbackMsg_t`.
#[repr(C)]
struct CallbackMsg {
    user: i32,
    id: i32,
    param: *mut u8,
    size: i32,
}

const _: () = assert!(std::mem::size_of::<Identity>() == 136);
const _: () = assert!(std::mem::offset_of!(Message, peer) == 16);
const _: () = assert!(std::mem::offset_of!(Message, flags) == 196);
const _: () = assert!(std::mem::size_of::<CallbackMsg>() == 24);

type Iface = *mut c_void;
type FnInt = unsafe extern "C" fn() -> i32;
type FnBool = unsafe extern "C" fn() -> bool;
type FnVoid = unsafe extern "C" fn();
type FnInitFlat = unsafe extern "C" fn(*mut u8) -> i32;
type FnAccessor = unsafe extern "C" fn() -> Iface;
type FnU64 = unsafe extern "C" fn(Iface) -> u64;
type FnU32 = unsafe extern "C" fn(Iface) -> u32;
type FnIfaceBool = unsafe extern "C" fn(Iface) -> bool;
type FnIfaceVoid = unsafe extern "C" fn(Iface);
type FnSend = unsafe extern "C" fn(Iface, *const Identity, *const c_void, u32, i32, i32) -> i32;
type FnRecv = unsafe extern "C" fn(Iface, i32, *mut *mut Message, i32) -> i32;
type FnSession = unsafe extern "C" fn(Iface, *const Identity) -> bool;
type FnRelease = unsafe extern "C" fn(*mut Message);
type FnSetGlobalPtr = unsafe extern "C" fn(Iface, i32, *mut c_void) -> bool;
type FnSetGlobalI32 = unsafe extern "C" fn(Iface, i32, i32) -> bool;
type FnGetConfig = unsafe extern "C" fn(Iface, i32, i32, isize, *mut i32, *mut c_void, *mut usize) -> i32;
type FnRelayStatus = unsafe extern "C" fn(Iface, *mut c_void) -> i32;
type FnPipe = unsafe extern "C" fn(i32);
type FnNextCb = unsafe extern "C" fn(i32, *mut CallbackMsg) -> bool;

struct Fns {
    send: FnSend,
    recv: FnRecv,
    accept: FnSession,
    close: FnSession,
    release: FnRelease,
    relay_status: FnRelayStatus,
    run_frame: Option<FnPipe>,
    next_cb: Option<FnNextCb>,
    free_cb: Option<FnPipe>,
}

/// A loaded, initialized Steam API (one per process).
pub struct SteamApi {
    _lib: Library,
    fns: Fns,
    msgs: Iface,
    utils: Iface,
    pipe: i32,
    steam_id: SteamId,
    app_id: u32,
    borrowed: bool,
    pump: Mutex<()>,
    /// Ours to shut down (None when borrowed); `down` once we did.
    shutdown: Option<FnVoid>,
    down: RwLock<bool>,
}

// The networking-messages interface is thread safe; callback pumping is
// serialized by `pump`.
unsafe impl Send for SteamApi {}
unsafe impl Sync for SteamApi {}

/// Borrowed Steam: `AcceptSessionWithUser` + interface, and the game's own
/// callbacks we chain to (0 = none). Steam callbacks carry no user pointer.
static ACCEPT: OnceLock<(usize, usize)> = OnceLock::new();
static PREV_REQUEST: AtomicUsize = AtomicUsize::new(0);
static PREV_FAILED: AtomicUsize = AtomicUsize::new(0);
/// SteamIDs Cosmos talks to; with a game accept policy, only these are
/// accepted by us.
static ALLOWED: Mutex<Vec<SteamId>> = Mutex::new(Vec::new());
const ALLOWED_MAX: usize = 256;
/// Session-failed queues, one per channel, all fed by every failure.
static FAILED: Mutex<Vec<Weak<Mutex<Vec<SteamId>>>>> = Mutex::new(Vec::new());

fn note_failed(id: SteamId) {
    let mut subs = FAILED.lock().unwrap();
    subs.retain(|w| w.strong_count() > 0);
    for q in subs.iter().filter_map(Weak::upgrade) {
        q.lock().unwrap().push(id);
    }
}

/// SAFETY: `p` is null or a callback struct whose first field is the remote
/// `SteamNetworkingIdentity` (true for the session request and failure ones).
unsafe fn remote_of(p: *const c_void) -> Option<Identity> {
    (!p.is_null()).then(|| unsafe { std::ptr::read_unaligned(p as *const Identity) })
}

unsafe extern "C" fn on_session_request(req: *mut c_void) {
    let prev = PREV_REQUEST.load(Ordering::Acquire);
    if prev != 0 {
        // SAFETY: `prev` is the callback the game installed, same signature.
        unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void)>(prev)(req) };
    }
    // SAFETY: Steam passes a `SteamNetworkingMessagesSessionRequest_t`.
    let Some(id) = (unsafe { remote_of(req) }) else { return };
    let ours = id.steam_id().is_some_and(|s| ALLOWED.lock().unwrap().contains(&s));
    if let Some(&(f, iface)) = ACCEPT.get()
        && (prev == 0 || ours)
    {
        // SAFETY: `f` is `AcceptSessionWithUser` from the loaded library.
        unsafe {
            let accept: FnSession = std::mem::transmute(f);
            accept(iface as Iface, &id);
        }
    }
}

unsafe extern "C" fn on_session_failed(info: *mut c_void) {
    // SAFETY: Steam passes a `SteamNetworkingMessagesSessionFailed_t`.
    if let Some(s) = unsafe { remote_of(info) }.and_then(|i| i.steam_id()) {
        note_failed(s);
    }
    let prev = PREV_FAILED.load(Ordering::Acquire);
    if prev != 0 {
        // SAFETY: the game's own callback, same signature.
        unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void)>(prev)(info) };
    }
}

fn sym<T: Copy>(lib: &Library, name: &'static str) -> Result<T, Unavailable> {
    let c = format!("{name}\0");
    // SAFETY: each caller names the flat-API symbol with its declared type.
    unsafe { lib.get::<T>(c.as_bytes()).map(|s| *s).map_err(|_| Unavailable::MissingSymbol(name)) }
}

fn sym_any<T: Copy>(lib: &Library, names: &[&'static str]) -> Result<T, Unavailable> {
    names.iter().find_map(|n| sym(lib, n).ok()).ok_or(Unavailable::MissingSymbol(names[0]))
}

#[cfg(windows)]
fn already_loaded() -> Option<Library> {
    libloading::os::windows::Library::open_already_loaded(DLL_NAME).ok().map(Into::into)
}

#[cfg(not(windows))]
fn already_loaded() -> Option<Library> {
    // TODO(linux/macos): RTLD_NOLOAD probe for a game's own libsteam_api.
    None
}

fn open_lib(cfg: &SteamConfig) -> Result<Library, Unavailable> {
    let env = if cfg!(debug_assertions) { std::env::var_os(DLL_ENV).map(PathBuf::from) } else { None };
    let path = cfg
        .dll
        .clone()
        .or(env)
        .ok_or_else(|| Unavailable::DllMissing("no Steam API path configured".into()))?;
    if !path.is_absolute() {
        return Err(Unavailable::DllMissing(format!("{}: path must be absolute", path.display())));
    }
    // SAFETY: loading the Steamworks redistributable runs only its own init.
    unsafe { load_abs(&path) }.map_err(|e| Unavailable::DllMissing(format!("{}: {e}", path.display())))
}

/// SAFETY: as `Library::new`. Dependencies resolve from the DLL's folder and
/// System32 only, never the current directory or PATH.
#[cfg(windows)]
unsafe fn load_abs(path: &std::path::Path) -> Result<Library, libloading::Error> {
    use libloading::os::windows::{LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32};
    unsafe {
        libloading::os::windows::Library::load_with_flags(path, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    }
    .map(Into::into)
}

#[cfg(not(windows))]
unsafe fn load_abs(path: &std::path::Path) -> Result<Library, libloading::Error> {
    unsafe { Library::new(path) }
}

/// The loaded API and how many `load`s hold it.
static API: Mutex<Option<(Arc<SteamApi>, usize)>> = Mutex::new(None);

impl SteamApi {
    /// The process-wide Steam API, loading and initializing it on first use.
    /// Later calls return the same instance and ignore `cfg`. Each `load`
    /// takes a reference; give it back with `release`.
    pub fn load(cfg: &SteamConfig) -> Result<Arc<SteamApi>, Unavailable> {
        let mut g = API.lock().unwrap();
        if let Some((a, n)) = &mut *g {
            *n += 1;
            return Ok(a.clone());
        }
        let a = Arc::new(Self::open(cfg)?);
        *g = Some((a.clone(), 1));
        Ok(a)
    }

    /// Give back one `load`. The last one shuts Steam down (if we
    /// initialized it); a later `load` opens it again.
    pub fn release(self: &Arc<Self>) {
        let mut g = API.lock().unwrap();
        let last = match &mut *g {
            Some((a, n)) if Arc::ptr_eq(a, self) => {
                *n -= 1;
                *n == 0
            }
            _ => return,
        };
        if last {
            *g = None;
            self.shutdown();
        }
    }

    fn open(cfg: &SteamConfig) -> Result<SteamApi, Unavailable> {
        let (lib, preloaded) = match already_loaded() {
            Some(l) => (l, true),
            None => (open_lib(cfg)?, false),
        };
        let h_user: FnInt = sym(&lib, "SteamAPI_GetHSteamUser")?;
        // SAFETY: plain getter, valid before and after init.
        let borrowed = preloaded && unsafe { h_user() } != 0;
        if preloaded && !borrowed {
            // A Steam game mid-start: initing now would run it as our AppID.
            return Err(Unavailable::GameSteamNotReady);
        }
        if !borrowed {
            Self::init(&lib, cfg.app_id)?;
        }
        // SAFETY: Steam is initialized (ours or the game's) past this point.
        match unsafe { Self::bind(lib, borrowed) } {
            Ok(a) => Ok(a),
            Err((lib, e)) => {
                if !borrowed && let Ok(shutdown) = sym::<FnVoid>(&lib, "SteamAPI_Shutdown") {
                    // SAFETY: we initialized it above.
                    unsafe { shutdown() };
                }
                Err(e)
            }
        }
    }

    fn init(lib: &Library, app_id: u32) -> Result<(), Unavailable> {
        if app_id == 0 {
            return Err(Unavailable::NoAppId);
        }
        let running: FnBool = sym(lib, "SteamAPI_IsSteamRunning")?;
        // SAFETY: plain query, valid before init.
        if !unsafe { running() } {
            return Err(Unavailable::SteamNotRunning);
        }
        let id = app_id.to_string();
        let preset = std::env::var("SteamAppId").ok();
        if preset.as_deref() != Some(&id) {
            set_app_env(Some(&id))?;
        }
        let r = Self::init_call(lib);
        if preset.as_deref() != Some(&id) {
            // Don't leak our AppID into child processes.
            set_app_env(None)?;
        }
        r
    }

    fn init_call(lib: &Library) -> Result<(), Unavailable> {
        if let Ok(init) = sym::<FnInitFlat>(lib, "SteamAPI_InitFlat") {
            let mut err = [0u8; 1024];
            // SAFETY: `err` is the 1024-byte SteamErrMsg buffer.
            let r = unsafe { init(err.as_mut_ptr()) };
            if r != 0 {
                let end = err.iter().position(|&b| b == 0).unwrap_or(err.len());
                return Err(Unavailable::InitFailed(format!("{r}: {}", String::from_utf8_lossy(&err[..end]))));
            }
        } else {
            let init: FnBool = sym(lib, "SteamAPI_InitSafe")?;
            // SAFETY: legacy init, no arguments.
            if !unsafe { init() } {
                return Err(Unavailable::InitFailed("SteamAPI_InitSafe returned false".into()));
            }
        }
        Ok(())
    }

    /// SAFETY: Steam must be initialized in this process.
    unsafe fn bind(lib: Library, borrowed: bool) -> Result<SteamApi, (Library, Unavailable)> {
        macro_rules! t {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(e) => return Err((lib, e)),
                }
            };
        }
        let user_acc: FnAccessor = t!(sym_any(
            &lib,
            &["SteamAPI_SteamUser_v023", "SteamAPI_SteamUser_v022", "SteamAPI_SteamUser_v021", "SteamAPI_SteamUser_v020"]
        ));
        let get_id: FnU64 = t!(sym(&lib, "SteamAPI_ISteamUser_GetSteamID"));
        let logged_on: FnIfaceBool = t!(sym(&lib, "SteamAPI_ISteamUser_BLoggedOn"));
        let msgs_acc: FnAccessor = t!(sym(&lib, "SteamAPI_SteamNetworkingMessages_SteamAPI_v002"));
        let utils_acc: FnAccessor = t!(sym_any(
            &lib,
            &["SteamAPI_SteamNetworkingUtils_SteamAPI_v004", "SteamAPI_SteamNetworkingUtils_SteamAPI_v003"]
        ));
        let fns = Fns {
            send: t!(sym(&lib, "SteamAPI_ISteamNetworkingMessages_SendMessageToUser")),
            recv: t!(sym(&lib, "SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel")),
            accept: t!(sym(&lib, "SteamAPI_ISteamNetworkingMessages_AcceptSessionWithUser")),
            close: t!(sym(&lib, "SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser")),
            release: t!(sym(&lib, "SteamAPI_SteamNetworkingMessage_t_Release")),
            relay_status: t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_GetRelayNetworkStatus")),
            run_frame: None,
            next_cb: None,
            free_cb: None,
        };
        let init_relay: FnIfaceVoid = t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_InitRelayNetworkAccess"));
        let set_ptr: FnSetGlobalPtr = t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValuePtr"));
        let set_i32: FnSetGlobalI32 = t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueInt32"));
        let get_cfg: FnGetConfig = t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_GetConfigValue"));
        let h_pipe: FnInt = t!(sym(&lib, "SteamAPI_GetHSteamPipe"));
        let shutdown: Option<FnVoid> = if borrowed { None } else { Some(t!(sym(&lib, "SteamAPI_Shutdown"))) };
        // SAFETY (whole block): Steam is initialized; accessors return live
        // interface pointers or null, checked before use.
        unsafe {
            let (user, msgs, utils) = (user_acc(), msgs_acc(), utils_acc());
            if user.is_null() || msgs.is_null() || utils.is_null() {
                return Err((lib, Unavailable::MissingSymbol("Steam interface accessor returned null")));
            }
            if !logged_on(user) {
                return Err((lib, Unavailable::NotLoggedOn));
            }
            let steam_id = get_id(user);
            let app_id = sym_any::<FnAccessor>(&lib, &["SteamAPI_SteamUtils_v010", "SteamAPI_SteamUtils_v009"])
                .ok()
                .zip(sym::<FnU32>(&lib, "SteamAPI_ISteamUtils_GetAppID").ok())
                .map(|(acc, get)| {
                    let u = acc();
                    if u.is_null() { 0 } else { get(u) }
                })
                .unwrap_or(0);
            init_relay(utils);
            let mut fns = fns;
            if borrowed {
                // The game pumps callbacks; we hook in from its thread,
                // chaining to whatever it installed.
                let _ = ACCEPT.set((fns.accept as usize, msgs as usize));
                let prev = |v: i32| {
                    let (mut kind, mut out, mut n) = (0i32, 0usize, std::mem::size_of::<usize>());
                    let r = get_cfg(utils, v, CFG_SCOPE_GLOBAL, 0, &mut kind, (&raw mut out).cast(), &mut n);
                    if r == CFG_GET_OK { out } else { 0 }
                };
                PREV_REQUEST.store(prev(CFG_CALLBACK_SESSION_REQUEST), Ordering::Release);
                PREV_FAILED.store(prev(CFG_CALLBACK_SESSION_FAILED), Ordering::Release);
                let req: unsafe extern "C" fn(*mut c_void) = on_session_request;
                let fail: unsafe extern "C" fn(*mut c_void) = on_session_failed;
                set_ptr(utils, CFG_CALLBACK_SESSION_REQUEST, req as *mut c_void);
                set_ptr(utils, CFG_CALLBACK_SESSION_FAILED, fail as *mut c_void);
            } else {
                set_i32(utils, CFG_SEND_BUFFER_SIZE, SEND_BUFFER);
                let md_init: FnVoid = t!(sym(&lib, "SteamAPI_ManualDispatch_Init"));
                md_init();
                fns.run_frame = Some(t!(sym(&lib, "SteamAPI_ManualDispatch_RunFrame")));
                fns.next_cb = Some(t!(sym(&lib, "SteamAPI_ManualDispatch_GetNextCallback")));
                fns.free_cb = Some(t!(sym(&lib, "SteamAPI_ManualDispatch_FreeLastCallback")));
            }
            Ok(SteamApi {
                pipe: h_pipe(),
                _lib: lib,
                fns,
                msgs,
                utils,
                steam_id,
                app_id,
                borrowed,
                pump: Mutex::new(()),
                shutdown,
                down: RwLock::new(false),
            })
        }
    }

    pub fn steam_id(&self) -> SteamId {
        self.steam_id
    }

    /// The AppID Steam runs us under (the game's when borrowed).
    pub fn app_id(&self) -> u32 {
        self.app_id
    }

    /// True when the game initialized Steam and we only reuse it.
    pub fn is_borrowed(&self) -> bool {
        self.borrowed
    }

    /// `ESteamNetworkingAvailability` of the relay network (100 = current).
    pub fn relay_status(&self) -> i32 {
        let mut buf = [0u64; 128];
        // SAFETY: `buf` (1 KiB) is larger than SteamRelayNetworkStatus_t.
        unsafe { (self.fns.relay_status)(self.utils, buf.as_mut_ptr().cast()) }
    }

    /// Our own Steam callbacks: accept session requests, note failures.
    /// No-op when the game owns Steam (it pumps; we accept via a global
    /// callback).
    fn pump(&self) {
        let (Some(run), Some(next), Some(free)) = (self.fns.run_frame, self.fns.next_cb, self.fns.free_cb) else {
            return;
        };
        let _g = self.pump.lock().unwrap();
        let down = self.down.read().unwrap();
        if *down {
            return;
        }
        let mut msg = CallbackMsg { user: 0, id: 0, param: std::ptr::null_mut(), size: 0 };
        // SAFETY: manual dispatch protocol from steam_api.h; each callback is
        // freed before the next is fetched; params are read within bounds.
        unsafe {
            run(self.pipe);
            while next(self.pipe, &mut msg) {
                let ident = (!msg.param.is_null() && msg.size as usize >= std::mem::size_of::<Identity>())
                    .then(|| std::ptr::read_unaligned(msg.param as *const Identity));
                match (msg.id, ident) {
                    (CB_SESSION_REQUEST, Some(id)) => {
                        (self.fns.accept)(self.msgs, &id);
                    }
                    (CB_SESSION_FAILED, Some(id)) => {
                        if let Some(s) = id.steam_id() {
                            note_failed(s);
                        }
                    }
                    _ => {}
                }
                free(self.pipe);
            }
        }
    }

    fn send_to(&self, channel: i32, to: SteamId, data: &[u8], reliable: bool) -> Result<(), SendError> {
        let down = self.down.read().unwrap();
        if *down {
            return Err(SendError::NoConnection);
        }
        let id = Identity::steam(to);
        let mut flags = if reliable { SEND_RELIABLE_NO_NAGLE } else { SEND_UNRELIABLE_NO_NAGLE };
        if self.borrowed {
            // We never close the game's sessions; let Steam restart broken ones.
            flags |= SEND_AUTO_RESTART;
        }
        // SAFETY: valid identity and buffer for the duration of the call.
        let r = unsafe { (self.fns.send)(self.msgs, &id, data.as_ptr().cast(), data.len() as u32, flags, channel) };
        match r {
            E_OK => Ok(()),
            E_NO_CONNECTION => Err(SendError::NoConnection),
            E_LIMIT_EXCEEDED | E_BUSY => Err(SendError::Full),
            e => Err(SendError::Other(e)),
        }
    }

    fn receive(&self, channel: i32, out: &mut Vec<SteamEvent>) {
        let down = self.down.read().unwrap();
        if *down {
            return;
        }
        let mut ptrs: [*mut Message; RECV_BATCH] = [std::ptr::null_mut(); RECV_BATCH];
        loop {
            // SAFETY: `ptrs` holds RECV_BATCH slots; every returned message is
            // copied out and released exactly once.
            let n = unsafe { (self.fns.recv)(self.msgs, channel, ptrs.as_mut_ptr(), RECV_BATCH as i32) };
            if n <= 0 {
                return;
            }
            for &p in &ptrs[..n as usize] {
                unsafe {
                    let m = &*p;
                    if let Some(from) = m.peer.steam_id()
                        && !m.data.is_null()
                        && m.size >= 0
                    {
                        let data = std::slice::from_raw_parts(m.data as *const u8, m.size as usize).to_vec();
                        out.push(SteamEvent::Message { from, data });
                    }
                    (self.fns.release)(p);
                }
            }
            if (n as usize) < RECV_BATCH {
                return;
            }
        }
    }

    /// Shut Steam down if we initialized it (no-op when borrowed). Every
    /// Steam path in the process goes dead; prefer `release`.
    pub fn shutdown(&self) {
        let mut down = self.down.write().unwrap();
        if let (false, Some(f)) = (*down, self.shutdown) {
            // SAFETY: we initialized Steam; no call is in flight (write lock).
            unsafe { f() };
        }
        *down = true;
    }

    /// Close our session with `peer`. Not when borrowed: the session is per
    /// user and shared with the game's own channels.
    fn close_with(&self, peer: SteamId) {
        let down = self.down.read().unwrap();
        if *down || self.borrowed {
            return;
        }
        let id = Identity::steam(peer);
        // SAFETY: valid identity for the duration of the call.
        unsafe { (self.fns.close)(self.msgs, &id) };
    }

    /// A backend on one networking-messages channel.
    pub fn channel(self: &Arc<Self>, channel: i32) -> Arc<SteamChannel> {
        let failed = Arc::new(Mutex::new(vec![]));
        FAILED.lock().unwrap().push(Arc::downgrade(&failed));
        Arc::new(SteamChannel { api: self.clone(), channel, failed })
    }
}

#[cfg(windows)]
fn set_app_env(v: Option<&str>) -> Result<(), Unavailable> {
    // SAFETY: Windows environment calls are thread safe (the process
    // environment is locked by the OS), so concurrent readers are fine.
    unsafe {
        for k in ["SteamAppId", "SteamGameId"] {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_app_env(v: Option<&str>) -> Result<(), Unavailable> {
    // setenv races with getenv in other threads here: require it preset.
    match v {
        Some(_) => Err(Unavailable::InitFailed("set SteamAppId before starting threads".into())),
        None => Ok(()),
    }
}

/// `SteamBackend` over the real Steam API.
pub struct SteamChannel {
    api: Arc<SteamApi>,
    channel: i32,
    failed: Arc<Mutex<Vec<SteamId>>>,
}

impl SteamBackend for SteamChannel {
    fn steam_id(&self) -> SteamId {
        self.api.steam_id
    }

    fn send(&self, to: SteamId, data: &[u8], reliable: bool) -> Result<(), SendError> {
        self.api.send_to(self.channel, to, data, reliable)
    }

    fn poll(&self, out: &mut Vec<SteamEvent>) {
        self.api.pump();
        out.extend(self.failed.lock().unwrap().drain(..).map(|remote| SteamEvent::SessionFailed { remote }));
        self.api.receive(self.channel, out);
    }

    fn close(&self, peer: SteamId) {
        self.api.close_with(peer);
    }

    fn allow(&self, peer: SteamId) {
        let mut a = ALLOWED.lock().unwrap();
        if !a.contains(&peer) {
            if a.len() >= ALLOWED_MAX {
                a.remove(0);
            }
            a.push(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dll_is_unavailable() {
        // Only the loader: this can never init a Steam instance.
        let cfg = SteamConfig { app_id: 480, dll: Some(PathBuf::from("Z:/nope/not_steam_api64.dll")) };
        assert!(matches!(open_lib(&cfg), Err(Unavailable::DllMissing(_))));
        let rel = SteamConfig { app_id: 480, dll: Some(PathBuf::from(DLL_NAME)) };
        match open_lib(&rel) {
            Err(Unavailable::DllMissing(e)) => assert!(e.contains("absolute"), "{e}"),
            r => panic!("relative path not refused: {:?}", r.err()),
        }
    }

    #[test]
    fn identity_roundtrip() {
        let id = Identity::steam(76561198000000001);
        assert_eq!(id.steam_id(), Some(76561198000000001));
        let mut other = id;
        other.kind = 1;
        assert_eq!(other.steam_id(), None);
    }
}
