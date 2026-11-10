//! Optional Steam relay path (SDR over `ISteamNetworkingMessages`).
//!
//! Works for any game, Steam build or not: the only need is the Steam client
//! running and logged in. If the game process already initialized Steam it
//! is reused; otherwise our bundled `steam_api64.dll` inits with AppID 480
//! (Spacewar) or the configured one. Steam missing = `Unavailable`, the
//! session just runs without this path.
//!
//! The Cosmos key stays the identity: a SteamID only counts once the peer
//! signed (its SteamID, our SteamID, our nonce) with its Cosmos key (`bind`).
//! Peers find each other's SteamID through a signed DHT record (`record`).
//!
//! Dev setup: the Steamworks redistributable is not committed (Valve SDK
//! license). Put `steam_api64.dll` from the Steamworks SDK
//! (`redistributable_bin/win64/`, also shipped in the `steamworks-sys` crate
//! under `lib/steam/redistributable_bin/win64/`) at `vendor/steam/` in the
//! repo root, next to the exe, or point `COSMOS_STEAM_API` at it.
//!
//! TODO(M3 lobby): Steam lobby invite -> join code needs `ISteamMatchmaking`
//! (CreateLobby call results, lobby data) and the overlay's
//! `GameLobbyJoinRequested_t`; not built yet. `SteamTransport::connect_steam`
//! is the hook it will use once an invite yields a SteamID.

#![deny(unsafe_code)]

pub mod backend;
pub mod bind;
#[allow(unsafe_code)]
mod ffi;
pub mod record;
pub mod transport;

pub use backend::{FakeSteam, FakeSteamNet, MAX_MESSAGE, SendError, SteamBackend, SteamEvent, SteamId};
pub use ffi::{DLL_ENV, DLL_NAME, SteamApi, SteamChannel, SteamConfig, Unavailable};
pub use record::{DhtDirectory, STEAM_TOPIC, StaticDirectory, SteamDirectory, publish_steam_id};
pub use transport::{MAX_FRAME, SteamTransport, SteamTransportConfig};

use cosmos_core::Transport;
use cosmos_net::Keypair;
use std::sync::Arc;

/// Steam networking-messages channel Cosmos uses (games keep 0 and up).
pub const COSMOS_CHANNEL: i32 = 0x436f; // "Co"

/// Path name `PathSet` shows for this path.
pub const PATH_NAME: &str = "steam";

/// The Steam relay path, or `None` (logged) when Steam is not available.
/// Put it last in the `PathSet`: `[direct, steam]`.
pub fn steam_path(
    cfg: &SteamConfig,
    key: Keypair,
    dir: Arc<dyn SteamDirectory>,
) -> Option<(String, Arc<dyn Transport>, Arc<SteamApi>)> {
    match SteamApi::load(cfg) {
        Ok(api) => {
            let t = SteamTransport::new(api.channel(COSMOS_CHANNEL), key, dir, SteamTransportConfig::default());
            Some((PATH_NAME.to_string(), t as Arc<dyn Transport>, api))
        }
        Err(e) => {
            tracing::info!("Steam relay path off: {e}");
            None
        }
    }
}
