//! The only unsafe code in the crate: `steam_api64.dll` loaded at runtime and
//! the few flat-API calls the Steam path needs.
//!
//! If the process already initialized Steam (a Steam game), its instance is
//! reused and never shut down by us. Otherwise we load our bundled DLL and
//! init with the configured AppID (480, Spacewar, by default); that only
//! needs the Steam client running and logged in. Anything missing comes back
//! as `Unavailable`, never a panic.

use crate::backend::{SendError, SteamBackend, SteamEvent, SteamId};
use libloading::Library;
use std::ffi::c_void;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

#[cfg(windows)]
pub const DLL_NAME: &str = "steam_api64.dll";
#[cfg(target_os = "linux")]
pub const DLL_NAME: &str = "libsteam_api.so";
#[cfg(target_os = "macos")]
pub const DLL_NAME: &str = "libsteam_api.dylib";

/// Env var with a full path to the Steam API library (dev builds).
pub const DLL_ENV: &str = "COSMOS_STEAM_API";

#[derive(Clone, Debug)]
pub struct SteamConfig {
    /// AppID for our own init; ignored when reusing the game's Steam.
    pub app_id: u32,
    /// Library to load; default: `COSMOS_STEAM_API`, then the normal search
    /// (next to the exe first).
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
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unavailable::DllMissing(e) => write!(f, "Steam API library not loadable: {e}"),
            Unavailable::MissingSymbol(s) => write!(f, "Steam API library lacks {s}"),
            Unavailable::SteamNotRunning => f.write_str("Steam client not running"),
            Unavailable::InitFailed(e) => write!(f, "Steam init failed: {e}"),
            Unavailable::NotLoggedOn => f.write_str("Steam user not logged on"),
        }
    }
}

impl std::error::Error for Unavailable {}

// ---- flat API types (steamnetworkingtypes.h, SDK 1.6x) ----

const IDENTITY_STEAMID: i32 = 16;
const SEND_UNRELIABLE_NO_NAGLE: i32 = 1;
const SEND_RELIABLE_NO_NAGLE: i32 = 9;
const CB_SESSION_REQUEST: i32 = 1251;
const CB_SESSION_FAILED: i32 = 1252;
const CFG_CALLBACK_SESSION_REQUEST: i32 = 204;
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
    failed: Mutex<Vec<SteamId>>,
    /// Ours to shut down (None when borrowed); `down` once we did.
    shutdown: Option<FnVoid>,
    down: RwLock<bool>,
}

// The networking-messages interface is thread safe; callback pumping is
// serialized by `pump`.
unsafe impl Send for SteamApi {}
unsafe impl Sync for SteamApi {}

/// For the borrowed-Steam session-request callback (no user pointer there).
static ACCEPT: OnceLock<(usize, usize)> = OnceLock::new();

unsafe extern "C" fn on_session_request(req: *mut Identity) {
    if let Some(&(f, iface)) = ACCEPT.get()
        && !req.is_null()
    {
        // SAFETY: `f` is `AcceptSessionWithUser` from the loaded library and
        // `req` points at the callback's identity.
        unsafe {
            let accept: FnSession = std::mem::transmute(f);
            accept(iface as Iface, req);
        }
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
    let path = cfg
        .dll
        .clone()
        .or_else(|| std::env::var_os(DLL_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DLL_NAME));
    // SAFETY: loading the Steamworks redistributable runs only its own init.
    unsafe { Library::new(&path) }.map_err(|e| Unavailable::DllMissing(format!("{}: {e}", path.display())))
}

impl SteamApi {
    /// The process-wide Steam API, loading and initializing it on first use.
    /// Later calls return the same instance and ignore `cfg`.
    pub fn load(cfg: &SteamConfig) -> Result<Arc<SteamApi>, Unavailable> {
        static API: Mutex<Option<Arc<SteamApi>>> = Mutex::new(None);
        let mut g = API.lock().unwrap();
        if let Some(a) = &*g {
            return Ok(a.clone());
        }
        let a = Arc::new(Self::open(cfg)?);
        *g = Some(a.clone());
        Ok(a)
    }

    fn open(cfg: &SteamConfig) -> Result<SteamApi, Unavailable> {
        let (lib, preloaded) = match already_loaded() {
            Some(l) => (l, true),
            None => (open_lib(cfg)?, false),
        };
        let h_user: FnInt = sym(&lib, "SteamAPI_GetHSteamUser")?;
        // SAFETY: plain getter, valid before and after init.
        let borrowed = preloaded && unsafe { h_user() } != 0;
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
        let running: FnBool = sym(lib, "SteamAPI_IsSteamRunning")?;
        // SAFETY: plain query, valid before init.
        if !unsafe { running() } {
            return Err(Unavailable::SteamNotRunning);
        }
        // SAFETY: set before any Steam thread starts; Steam reads these at init.
        unsafe {
            std::env::set_var("SteamAppId", app_id.to_string());
            std::env::set_var("SteamGameId", app_id.to_string());
        }
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
                // The game pumps callbacks; accept sessions from its thread.
                let set: FnSetGlobalPtr = t!(sym(&lib, "SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValuePtr"));
                let _ = ACCEPT.set((fns.accept as usize, msgs as usize));
                let cb: unsafe extern "C" fn(*mut Identity) = on_session_request;
                set(utils, CFG_CALLBACK_SESSION_REQUEST, cb as *mut c_void);
            } else {
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
                failed: Mutex::new(vec![]),
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
                            self.failed.lock().unwrap().push(s);
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
        let flags = if reliable { SEND_RELIABLE_NO_NAGLE } else { SEND_UNRELIABLE_NO_NAGLE };
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
    /// Steam path in the process goes dead; call at process exit.
    pub fn shutdown(&self) {
        let mut down = self.down.write().unwrap();
        if let (false, Some(f)) = (*down, self.shutdown) {
            // SAFETY: we initialized Steam; no call is in flight (write lock).
            unsafe { f() };
        }
        *down = true;
    }

    fn close_with(&self, peer: SteamId) {
        let down = self.down.read().unwrap();
        if *down {
            return;
        }
        let id = Identity::steam(peer);
        // SAFETY: valid identity for the duration of the call.
        unsafe { (self.fns.close)(self.msgs, &id) };
    }

    /// A backend on one networking-messages channel.
    pub fn channel(self: &Arc<Self>, channel: i32) -> Arc<SteamChannel> {
        Arc::new(SteamChannel { api: self.clone(), channel })
    }
}

/// `SteamBackend` over the real Steam API.
pub struct SteamChannel {
    api: Arc<SteamApi>,
    channel: i32,
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
        out.extend(self.api.failed.lock().unwrap().drain(..).map(|remote| SteamEvent::SessionFailed { remote }));
        self.api.receive(self.channel, out);
    }

    fn close(&self, peer: SteamId) {
        self.api.close_with(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dll_is_unavailable() {
        let cfg = SteamConfig { app_id: 480, dll: Some(PathBuf::from("Z:/nope/not_steam_api64.dll")) };
        match SteamApi::open(&cfg) {
            Err(Unavailable::DllMissing(_)) => {}
            // A Steam game test host could have it loaded already.
            Err(e) => panic!("unexpected {e}"),
            Ok(_) => {}
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
