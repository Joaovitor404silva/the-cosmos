//! The API exercised only through its C functions.

use super::*;
use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

const NS: &CStr = c"cosmos-ffi-test";

fn last_error() -> String {
    unsafe { CStr::from_ptr(cosmos_last_error()) }.to_string_lossy().into_owned()
}

/// Config strings kept alive while `cfg` points at them.
struct Cfg {
    _s: Vec<CString>,
    cfg: CosmosConfig,
}

fn cfg(bootstrap: Option<&str>) -> Cfg {
    let boot = bootstrap.map(|b| CString::new(b).unwrap());
    let mut c = Cfg { _s: vec![], cfg: CosmosConfig::default() };
    c.cfg.game_id = NS.as_ptr();
    c.cfg.listen = c"127.0.0.1".as_ptr();
    c.cfg.bootstrap = boot.as_ref().map_or(null(), |b| b.as_ptr());
    c._s.extend(boot);
    c
}

fn init(bootstrap: Option<&str>) -> *mut Cosmos {
    let c = cfg(bootstrap);
    let h = unsafe { cosmos_init(&c.cfg) };
    assert!(!h.is_null(), "init failed: {}", last_error());
    h
}

fn listen(c: *mut Cosmos) -> String {
    let mut buf = [0 as c_char; 1024];
    let n = unsafe { cosmos_listen_addrs(c, buf.as_mut_ptr(), buf.len()) };
    assert!(n > 0, "listen addrs: {n} {}", last_error());
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap().to_string()
}

fn peer_id(c: *mut Cosmos, peer: u32) -> Vec<u8> {
    let mut buf = [0u8; COSMOS_PEER_ID_MAX];
    let n = unsafe { cosmos_peer_id(c, peer, buf.as_mut_ptr(), buf.len()) };
    assert!(n > 0, "peer id {peer}: {n}");
    buf[..n as usize].to_vec()
}

/// Owned copy of one polled event.
#[derive(Debug, Clone, Default)]
struct Got {
    kind: i32,
    peer: u32,
    channel: u8,
    reliable: u8,
    req_id: u32,
    error: i32,
    data: Vec<u8>,
    record_kind: String,
    record_key: String,
    publisher: Vec<u8>,
    count: u32,
    path: i32,
}

unsafe fn bytes(p: *const u8, n: usize) -> Vec<u8> {
    if p.is_null() { vec![] } else { unsafe { std::slice::from_raw_parts(p, n) }.to_vec() }
}

unsafe fn text(p: *const c_char) -> String {
    if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

fn poll(c: *mut Cosmos) -> Option<Got> {
    let mut e = CosmosEvent::default();
    let r = unsafe { cosmos_poll(c, &mut e) };
    assert!(r >= 0, "poll: {r} {}", last_error());
    if r == 0 {
        assert_eq!(e.kind, COSMOS_EV_NONE);
        return None;
    }
    unsafe {
        Some(Got {
            kind: e.kind,
            peer: e.peer,
            channel: e.channel,
            reliable: e.reliable,
            req_id: e.req_id,
            error: e.error,
            data: bytes(e.data, e.len),
            record_kind: text(e.record_kind),
            record_key: text(e.record_key),
            publisher: bytes(e.publisher, e.publisher_len),
            count: e.count,
            path: e.path,
        })
    }
}

fn wait(c: *mut Cosmos, secs: u64, mut f: impl FnMut(&Got) -> bool) -> Got {
    let start = Instant::now();
    loop {
        match poll(c) {
            Some(g) if f(&g) => return g,
            Some(_) => {}
            None => {
                assert!(start.elapsed() < Duration::from_secs(secs), "event wait timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn host(c: *mut Cosmos) -> CString {
    let mut code = [0 as c_char; COSMOS_CODE_MAX];
    let start = Instant::now();
    loop {
        let r = unsafe { cosmos_host(c, code.as_mut_ptr(), code.len()) };
        if r == COSMOS_OK {
            return unsafe { CStr::from_ptr(code.as_ptr()) }.to_owned();
        }
        assert!(r == COSMOS_E_NET && start.elapsed() < Duration::from_secs(30), "host: {r} {}", last_error());
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn version_and_error_names() {
    let v = unsafe { CStr::from_ptr(cosmos_version()) };
    assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    let name = |e| unsafe { CStr::from_ptr(cosmos_error_name(e)) }.to_str().unwrap().to_string();
    assert_eq!(name(COSMOS_OK), "COSMOS_OK");
    assert_eq!(name(COSMOS_E_FULL), "COSMOS_E_FULL");
    assert_eq!(name(COSMOS_E_PANIC), "COSMOS_E_PANIC");
    assert_eq!(name(-999), "COSMOS_E_UNKNOWN");
}

#[test]
fn null_pointers_are_errors_not_crashes() {
    assert!(unsafe { cosmos_init(null()) }.is_null());
    assert!(last_error().contains("null"), "{}", last_error());
    let mut e = CosmosEvent::default();
    unsafe {
        assert_eq!(cosmos_poll(null_mut(), &mut e), COSMOS_E_NULL);
        assert_eq!(cosmos_send(null_mut(), 0, 0, null(), 0, 1), COSMOS_E_NULL);
        assert_eq!(cosmos_host(null_mut(), null_mut(), 0), COSMOS_E_NULL);
        assert_eq!(cosmos_join(null_mut(), null()), COSMOS_E_NULL);
        assert_eq!(cosmos_record_put(null_mut(), null(), null(), null(), 0, 1), COSMOS_E_NULL);
        assert_eq!(cosmos_record_query(null_mut(), null(), null(), 1), COSMOS_E_NULL);
        assert_eq!(cosmos_record_subscribe(null_mut(), null(), null()), COSMOS_E_NULL);
        assert_eq!(cosmos_record_unsubscribe(null_mut(), 1), COSMOS_E_NULL);
        assert_eq!(cosmos_peer_id(null_mut(), 0, null_mut(), 0), COSMOS_E_NULL);
        assert_eq!(cosmos_dropped_events(null()), 0);
        cosmos_shutdown(null_mut());
    }
    // A config with no game id.
    let mut c = cfg(None);
    c.cfg.game_id = null();
    assert!(unsafe { cosmos_init(&c.cfg) }.is_null());

    let h = init(None);
    unsafe {
        assert_eq!(cosmos_poll(h, null_mut()), COSMOS_E_NULL);
        assert_eq!(cosmos_send(h, 0, 0, null(), 4, 1), COSMOS_E_NULL);
        // Zero-length sends may pass NULL data, but need a session.
        assert_eq!(cosmos_send(h, 0, 0, null(), 0, 1), COSMOS_E_STATE);
        assert_eq!(cosmos_join(h, c"bad!".as_ptr()), COSMOS_E_INVALID);
        assert_eq!(cosmos_record_put(h, c"bad kind!".as_ptr(), c"k".as_ptr(), null(), 0, 60), COSMOS_E_INVALID);
        let mut small = [0u8; 4];
        assert_eq!(cosmos_peer_id(h, 0, small.as_mut_ptr(), small.len()), COSMOS_E_BUFFER);
        assert_eq!(cosmos_peer_id(h, 99, null_mut(), 0), COSMOS_E_NULL);
        let mut big = [0u8; COSMOS_PEER_ID_MAX];
        assert_eq!(cosmos_peer_id(h, 99, big.as_mut_ptr(), big.len()), COSMOS_E_NOT_FOUND);
        cosmos_shutdown(h);
    }
}

#[test]
fn panic_inside_a_call_returns_an_error() {
    let h = init(None);
    let mut e = CosmosEvent::default();
    inject_panic();
    assert_eq!(unsafe { cosmos_poll(h, &mut e) }, COSMOS_E_PANIC);
    assert!(last_error().contains("injected"), "{}", last_error());
    inject_panic();
    assert!(unsafe { cosmos_init(&cfg(None).cfg) }.is_null());
    // The handle still works afterwards.
    assert_eq!(unsafe { cosmos_poll(h, &mut e) }, 0);
    assert_eq!(peer_id(h, 0).len(), 38);
    unsafe { cosmos_shutdown(h) };
}

#[test]
fn full_queue_drops_the_oldest_and_counts() {
    let c = cfg(None);
    let mut c2 = c.cfg;
    c2.event_queue = 4;
    let h = unsafe { cosmos_init(&c2) };
    assert!(!h.is_null());
    let me = unsafe { &*h };
    for i in 0..10u8 {
        me.push(Ev::Message { peer: 1, channel: i, reliable: true, data: vec![i] });
    }
    assert_eq!(unsafe { cosmos_dropped_events(h) }, 6);
    let got: Vec<u8> = std::iter::from_fn(|| poll(h)).map(|g| g.channel).collect();
    assert_eq!(got, vec![6, 7, 8, 9]);
    unsafe { cosmos_shutdown(h) };
}

#[test]
fn steam_on_without_steam_runs_direct_only() {
    let mut c = cfg(None);
    c.cfg.steam = 1;
    c.cfg.steam_dll = c"C:\\nowhere\\steam_api64.dll".as_ptr();
    c.cfg.steam_app_id = 480;
    let h = unsafe { cosmos_init(&c.cfg) };
    assert!(!h.is_null(), "{}", last_error());
    unsafe { cosmos_shutdown(h) };
}

#[test]
fn key_file_keeps_the_identity() {
    let dir = std::env::temp_dir().join(format!("cosmos-ffi-key-{}", std::process::id()));
    let path = CString::new(dir.join("id.key").to_str().unwrap()).unwrap();
    let mut c = cfg(None);
    c.cfg.key_path = path.as_ptr();
    let ids: Vec<_> = (0..2)
        .map(|_| {
            let h = unsafe { cosmos_init(&c.cfg) };
            assert!(!h.is_null(), "{}", last_error());
            let id = peer_id(h, 0);
            unsafe { cosmos_shutdown(h) };
            id
        })
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn host_join_send_and_records_over_loopback() {
    let a = init(None);
    let b = init(Some(&listen(a)));
    let code = host(a);
    assert_eq!(code.to_bytes().len(), 9, "pretty code XXXX-XXXX");
    assert_eq!(unsafe { cosmos_host(a, null_mut(), 0) }, COSMOS_E_NULL);
    let mut again = [0 as c_char; COSMOS_CODE_MAX];
    assert_eq!(unsafe { cosmos_host(a, again.as_mut_ptr(), again.len()) }, COSMOS_E_STATE);

    let r = unsafe { cosmos_join(b, code.as_ptr()) };
    assert_eq!(r, COSMOS_OK, "join: {}", last_error());

    let jb = wait(b, 20, |g| g.kind == COSMOS_EV_PEER_JOINED);
    let ja = wait(a, 20, |g| g.kind == COSMOS_EV_PEER_JOINED);
    assert_eq!(peer_id(b, jb.peer), peer_id(a, 0), "b's handle names a");
    assert_eq!(peer_id(a, ja.peer), peer_id(b, 0), "a's handle names b");
    assert_eq!(unsafe { cosmos_host_peer(b) }, jb.peer, "b's host is a");
    assert_eq!(unsafe { cosmos_host_peer(a) }, 0, "a is the host");
    assert_eq!(unsafe { cosmos_host_peer(null()) }, 0);
    // Each side learns the first path right after the join.
    for (h, p) in [(a, ja.peer), (b, jb.peer)] {
        let e = wait(h, 5, |g| g.kind == COSMOS_EV_PATH_CHANGED);
        assert_eq!((e.peer, e.path), (p, COSMOS_PATH_DIRECT));
    }

    let msg = b"ping";
    let r = unsafe { cosmos_send(b, jb.peer, 3, msg.as_ptr().cast(), msg.len(), 1) };
    assert_eq!(r, COSMOS_OK);
    let m = wait(a, 10, |g| g.kind == COSMOS_EV_MESSAGE);
    assert_eq!((m.peer, m.channel, m.reliable, m.data.as_slice()), (ja.peer, 3, 1, &msg[..]));

    let r = unsafe { cosmos_send(a, COSMOS_BROADCAST, 2, b"pong".as_ptr().cast(), 4, 0) };
    assert_eq!(r, COSMOS_OK);
    let m = wait(b, 10, |g| g.kind == COSMOS_EV_MESSAGE);
    assert_eq!((m.channel, m.reliable, m.data.as_slice()), (2, 0, &b"pong"[..]));
    let r = unsafe { cosmos_send(a, 77, 2, b"x".as_ptr().cast(), 1, 0) };
    assert_eq!(r, COSMOS_E_NOT_FOUND);

    // Records: put on a, query on b, tagged with the request id.
    let note = b"hello";
    let put = |key: &CStr| {
        let r = unsafe { cosmos_record_put(a, c"note".as_ptr(), key.as_ptr(), note.as_ptr().cast(), note.len(), 60) };
        assert_eq!(r, COSMOS_OK, "put: {}", last_error());
    };
    put(c"lobby");
    let start = Instant::now();
    let found = loop {
        assert_eq!(unsafe { cosmos_record_query(b, c"note".as_ptr(), c"lobby".as_ptr(), 7) }, COSMOS_OK);
        let g = wait(b, 20, |g| g.kind == COSMOS_EV_RECORD_RESULT);
        assert_eq!((g.req_id, g.error), (7, COSMOS_OK));
        if g.count > 0 {
            break g;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "record never found");
        std::thread::sleep(Duration::from_millis(300));
    };
    assert_eq!(found.data, note);
    assert_eq!((found.record_kind.as_str(), found.record_key.as_str()), ("note", "lobby"));
    assert_eq!(found.publisher, peer_id(a, 0));

    // Subscribe on b, put on a until the update arrives.
    let sub = unsafe { cosmos_record_subscribe(b, c"note".as_ptr(), c"live".as_ptr()) };
    assert!(sub > 0, "subscribe: {sub}");
    let start = Instant::now();
    let upd = loop {
        put(c"live");
        let t = Instant::now();
        let got = loop {
            match poll(b) {
                Some(g) if g.kind == COSMOS_EV_RECORD_UPDATE => break Some(g),
                Some(_) => {}
                None if t.elapsed() > Duration::from_millis(1500) => break None,
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        if let Some(g) = got {
            break g;
        }
        assert!(start.elapsed() < Duration::from_secs(25), "no record update");
    };
    assert_eq!((upd.req_id, upd.data.as_slice(), upd.record_key.as_str()), (sub as u32, &note[..], "live"));
    assert_eq!(unsafe { cosmos_record_unsubscribe(b, sub) }, COSMOS_OK);
    assert_eq!(unsafe { cosmos_record_unsubscribe(b, sub) }, COSMOS_E_NOT_FOUND);

    // Host leaves: b sees a leave and the session end.
    unsafe { cosmos_shutdown(a) };
    let left = wait(b, 20, |g| g.kind == COSMOS_EV_PEER_LEFT);
    assert_eq!(left.peer, jb.peer);
    wait(b, 10, |g| g.kind == COSMOS_EV_SESSION_ENDED);
    unsafe { cosmos_shutdown(b) };
}

#[test]
fn path_names_map_to_kinds() {
    assert_eq!(path_kind("direct"), COSMOS_PATH_DIRECT);
    assert_eq!(path_kind(cosmos_steam::PATH_NAME), COSMOS_PATH_RELAY);
    assert_eq!(path_kind("?"), COSMOS_PATH_UNKNOWN);
}

#[test]
fn full_queue_never_drops_control_events() {
    let c = cfg(None);
    let mut c2 = c.cfg;
    c2.event_queue = 4;
    let h = unsafe { cosmos_init(&c2) };
    assert!(!h.is_null());
    let me = unsafe { &*h };
    me.push(Ev::Joined(1));
    for i in 0..10u8 {
        me.push(Ev::Message { peer: 1, channel: i, reliable: false, data: vec![i] });
    }
    me.push(Ev::Left(1));
    me.push(Ev::Ended);
    let kinds: Vec<i32> = std::iter::from_fn(|| poll(h)).map(|g| g.kind).collect();
    assert_eq!(kinds.first(), Some(&COSMOS_EV_PEER_JOINED), "{kinds:?}");
    assert!(kinds.contains(&COSMOS_EV_PEER_LEFT) && kinds.contains(&COSMOS_EV_SESSION_ENDED), "{kinds:?}");
    assert!(kinds.len() <= 4, "queue grew past its cap: {kinds:?}");
    unsafe { cosmos_shutdown(h) };
}

#[test]
fn event_queue_size_is_clamped() {
    let c = cfg(None);
    let mut c2 = c.cfg;
    c2.event_queue = u32::MAX;
    let h = unsafe { cosmos_init(&c2) };
    assert!(!h.is_null());
    assert_eq!(lock(&unsafe { &*h }.st.shared.queue).cap, QUEUE_MAX);
    unsafe { cosmos_shutdown(h) };
}

#[test]
fn shutdown_inside_a_tokio_runtime_does_not_abort() {
    let h = init(None) as usize;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    rt.block_on(async move { unsafe { cosmos_shutdown(h as *mut Cosmos) } });
}
