# The Cosmos SDK — design

Date: 2026-11-10. Status: draft for user review.

## Goal

A serverless online SDK that any game with **2–4 players** can plug into: no hosted game server, no matchmaking server. Generalizes bb-node (Bloodborne, now a game port) into a reusable library.

Non-goals: MMO or >4 players, anti-cheat, dedicated servers, ranked matchmaking.

## Two planes

| Plane | Carries | Transport | Lag tolerance |
|---|---|---|---|
| **Sync** | live session traffic (positions, hits, RPCs) | direct peer links, relay fallback | low, real-time |
| **Async** | anything that doesn't need to be in sync: messages, bloodstains/ghosts, lobby adverts, join codes, profiles, leaderboards-lite | Kademlia DHT + gossipsub, signed records | high, seconds is fine |

Rule for adapters: if the game can live with it arriving late, it goes to the async plane. Lag there never hurts the session.

## Connection ladder

Per peer pair, tried in parallel, best path wins:

1. LAN / IPv6 / UPnP direct.
2. Hole punch (dcutr + port guessing, from bb-p2p `mesh`).
3. **Steam relay (SDR)** — only if Steam is present. Used like Seamless Coop: Steam carries signaling and traffic **until** a direct path is up, then the session migrates to direct and drops Steam. If direct can't hold, it stays on (or falls back to) Steam.
4. Cosmos relay (our Oracle VM / community relays) — last resort for non-Steam games.

While on any relay, the SDK keeps retrying direct in the background and migrates without dropping the session (path migration under the channel layer; sequence numbers make the switch invisible to the game).

### Steam backend details
- Uses `ISteamNetworkingMessages` (SDR) and Steam lobbies for invites/signaling.
- Inside a modded game: reuse the game's already-initialized `steam_api64.dll` and AppID (as Seamless Coop does). Standalone / testing: AppID 480.
- Loaded dynamically: the SDK must run with no Steam at all.
- Peer identity stays the Cosmos key; the SteamID is bound to it by a signed handshake message, never trusted alone.

## Architecture (Rust workspace)

| Crate | Role | Source |
|---|---|---|
| `cosmos-net` | libp2p swarm, DHT, gossipsub, punch/relay ladder, path migration | lifted from bb-p2p `mesh` |
| `cosmos-steam` | optional Steam signaling + SDR relay path (feature `steam`) | new |
| `cosmos-core` | identity keys, session (≤4 peers, host + members), channels (reliable ordered / unreliable), async record API with per-game namespaces, limits | new + bb-p2p `node` trust/limits |
| `cosmos-ffi` | C ABI + generated `cosmos.h` (cbindgen); poll-based, no callbacks across threads | new |
| `cosmos-node` | optional daemon process hosting facades for unchanged games | from bb-p2p `node` |
| `facades/*` | fake an existing backend (first: shadNet; later Steam P2P/EOS shims) | bb-p2p `facade` (generic parts only) |

Game-specific logic (Bloodborne world/chalice) stays in a game port, which becomes the first consumer.

### C API shape (sketch)
```c
cosmos_t*  cosmos_init(const cosmos_config_t*);        // game id, key path, steam on/off
int        cosmos_host(cosmos_t*, char code_out[12]);  // join code
int        cosmos_join(cosmos_t*, const char* code);
int        cosmos_send(cosmos_t*, peer_t to, uint8_t chan, const void*, size_t, int reliable);
int        cosmos_poll(cosmos_t*, cosmos_event_t* ev); // peer joined/left, msg, path changed
int        cosmos_record_put(cosmos_t*, const char* kind, const void*, size_t, uint32_t ttl_s);
int        cosmos_record_query(cosmos_t*, const char* kind, const char* key, uint32_t req_id);
void       cosmos_shutdown(cosmos_t*);
```

## Session model
- Max 4 peers, enforced by the host and by connection limits.
- Topology: full mesh between ≤4 peers (6 links max); host is authority for membership.
- Join codes: short code → DHT key → host-signed session advert (addresses + Steam id if any). Steam lobby invite as an alternative when Steam present.

## Security baseline (carried from bb-p2p audit)
- Peer id = public key; all records signed; game namespace in every record key.
- Size and rate caps on every inbound path; connection limits; relay reservations limited.
- Nothing from the network is passed raw to game memory; adapters validate.
- Full security audit before any public release.

## Testing
- Unit TDD per crate; loopback 4-peer integration test (sync + async + forced relay → direct migration).
- 2-PC test (two LAN PCs), cross-network test (a remote friend), Steam path test with two Steam accounts.
- Proof game: Bloodborne via a game port on the SDK, then one non-emulated Steam game.

## Repos
- No GPL code.

## Open questions
1. Second proof game (non-emulated, Steam, ≤4 players) — user to pick.
2. Engine bindings later (Unity C#, UE plugin, UE4SS Lua) — after the C ABI is stable.
