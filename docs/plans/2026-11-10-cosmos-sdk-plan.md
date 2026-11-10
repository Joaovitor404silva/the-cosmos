# The Cosmos SDK — implementation plan

Spec: `docs/specs/2026-11-10-cosmos-sdk-design.md`. Workflow: unit TDD per task (red test first), opus medium implements new pieces, one opus review per milestone, live tests run by the supervisor. Build with `CARGO_BUILD_JOBS=2`.

## M0 — Skeleton
- [x] Workspace `cosmos-net`, `cosmos-core`, `cosmos-steam`, `cosmos-ffi`; CI-free `cargo test` green.
- [x] Copy (not move) bb-p2p `mesh` into `cosmos-net`; strip Bloodborne names and the relay server/client + DEFAULT_RELAYS; remaining tests pass.
- [x] DHT-signaled hole punch (signed observed addresses + simultaneous dial) replaces relay-coordinated dcutr; `NO_PATH` error when nothing works.

## M1 — Sync plane over libp2p
- [x] `cosmos-core::Session`: host/join, ≤4 peers (5th rejected — test), membership events.
- [x] Channels: reliable-ordered + unreliable, per-channel caps (tests for order, loss tolerance, oversize drop).
- [x] Join codes via DHT session advert (signed; forged advert rejected — test).
- [x] Loopback 4-peer integration test: all pairs exchange 1k msgs.

## M2 — Path migration
- [x] Channel layer with sequence numbers independent of the path.
- [x] Background direct retry while relayed; migrate on success, fall back on loss.
- [x] Test: start on a Steam-relay test double, open direct, no lost/duplicated reliable messages across the switch; then kill direct → back to Steam relay.

## M3 — Steam path
- [ ] Dynamic load of bundled `steam_api64.dll`: reuse the game's in-process Steam if present, else init with AppID 480 (configurable). Steam client not running = path off, no error.
- [ ] Signaling over `ISteamNetworkingMessages`: exchange signed Cosmos addresses, bind SteamID ↔ Cosmos key.
- [ ] SDR as the only relay path; dropped after direct is stable.
- [ ] Steam lobby invite → join code.
- [ ] Live: two Steam accounts, two PCs (AppID 480), measure time-to-direct and fallback.

## M4 — Async plane
- [ ] Record API: put/query/subscribe by `(game, kind, key)`, signed, TTL, size/rate caps, disk cache.
- [ ] Tests: namespace isolation, tamper rejection, TTL expiry, cap enforcement.

## M5 — C ABI
- [ ] `cosmos-ffi` poll API per spec; cbindgen `cosmos.h`; C example (`examples/chat.c`) with 4 instances.
- [ ] DLL builds for Windows x64; panic-safe boundary (test).

## M6 — Cosmos Demo (example game, ships in the SDK)
- [ ] `examples/cosmos-demo`, C + raylib: arena + stars + join code (sync), notes + ghosts (async), path HUD.
- [ ] Live: 4 instances on 2 PCs, then cross-network with a remote friend; record a short showcase clip.

## M7 — Hardening
- [ ] Security audit of the whole SDK before any public release.

## Later (not in this plan)
- `cosmos-node` daemon + facades, then other games (Bloodborne via a game port first).

Done = each milestone's tests green, opus review clean, live checks passed and recorded here.
