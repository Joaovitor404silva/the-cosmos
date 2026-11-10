//! What the Steam path needs from Steam, behind a trait, plus an in-process
//! fake so tests run without the Steam client.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// A 64-bit Steam ID (`CSteamID::ConvertToUint64`).
pub type SteamId = u64;

/// Largest message `ISteamNetworkingMessages` sends
/// (`k_cbMaxSteamNetworkingSocketsMessageSizeSend`).
pub const MAX_MESSAGE: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SteamEvent {
    /// A message on our channel. `from` is authenticated by Steam.
    Message { from: SteamId, data: Vec<u8> },
    /// The session with `remote` failed or broke.
    SessionFailed { remote: SteamId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Steam's queue to this user is full.
    Full,
    /// No session (broken, closed by us, or the user is unreachable).
    NoConnection,
    /// Any other `EResult`.
    Other(i32),
}

/// One Steam networking-messages channel.
pub trait SteamBackend: Send + Sync + 'static {
    fn steam_id(&self) -> SteamId;
    /// Reliable: in order, exactly once per session. Unreliable: may drop.
    fn send(&self, to: SteamId, data: &[u8], reliable: bool) -> Result<(), SendError>;
    /// Run pending Steam callbacks and append what arrived.
    fn poll(&self, out: &mut Vec<SteamEvent>);
    /// Drop the session with `peer`.
    fn close(&self, peer: SteamId);
}

/// In-process stand-in for Steam: every `FakeSteam` on one net can message
/// every other by Steam ID.
#[derive(Default)]
pub struct FakeSteamNet {
    inner: Mutex<FakeInner>,
}

#[derive(Default)]
struct FakeInner {
    inboxes: HashMap<SteamId, VecDeque<SteamEvent>>,
    down: bool,
    drop_unreliable: bool,
}

impl FakeSteamNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn backend(self: &Arc<Self>, id: SteamId) -> Arc<FakeSteam> {
        self.inner.lock().unwrap().inboxes.entry(id).or_default();
        Arc::new(FakeSteam { net: self.clone(), id })
    }

    /// Steam outage: sends fail with `NoConnection`, every session fails.
    pub fn cut(&self) {
        let mut i = self.inner.lock().unwrap();
        i.down = true;
        let ids: Vec<SteamId> = i.inboxes.keys().copied().collect();
        for (me, q) in i.inboxes.iter_mut() {
            for remote in ids.iter().filter(|r| *r != me) {
                q.push_back(SteamEvent::SessionFailed { remote: *remote });
            }
        }
    }

    pub fn restore(&self) {
        self.inner.lock().unwrap().down = false;
    }

    /// Drop every unreliable message.
    pub fn drop_unreliable(&self, on: bool) {
        self.inner.lock().unwrap().drop_unreliable = on;
    }

    /// Deliver `data` to `to` as if `from` sent it (Steam authenticates
    /// `from`, so only tests can do this).
    pub fn inject(&self, from: SteamId, to: SteamId, data: Vec<u8>) {
        if let Some(q) = self.inner.lock().unwrap().inboxes.get_mut(&to) {
            q.push_back(SteamEvent::Message { from, data });
        }
    }
}

pub struct FakeSteam {
    net: Arc<FakeSteamNet>,
    id: SteamId,
}

impl SteamBackend for FakeSteam {
    fn steam_id(&self) -> SteamId {
        self.id
    }

    fn send(&self, to: SteamId, data: &[u8], reliable: bool) -> Result<(), SendError> {
        if data.len() > MAX_MESSAGE {
            return Err(SendError::Other(8));
        }
        let mut i = self.net.inner.lock().unwrap();
        if i.down {
            return Err(SendError::NoConnection);
        }
        if !reliable && i.drop_unreliable {
            return Ok(());
        }
        let q = i.inboxes.get_mut(&to).ok_or(SendError::NoConnection)?;
        q.push_back(SteamEvent::Message { from: self.id, data: data.to_vec() });
        Ok(())
    }

    fn poll(&self, out: &mut Vec<SteamEvent>) {
        if let Some(q) = self.net.inner.lock().unwrap().inboxes.get_mut(&self.id) {
            out.extend(q.drain(..));
        }
    }

    fn close(&self, _: SteamId) {}
}
