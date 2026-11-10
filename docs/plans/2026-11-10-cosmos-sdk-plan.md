# The Cosmos SDK — implementation plan

Spec: `docs/specs/2026-11-10-cosmos-sdk-design.md`. Workflow: unit TDD per task (red test first), opus medium implements new pieces, one opus review per milestone, live tests run by the supervisor. Build with `CARGO_BUILD_JOBS=2`.

## M0 — Skeleton
- [ ] Workspace `cosmos-net`, `cosmos-core`, `cosmos-steam`, `cosmos-ffi`, `cosmos-node`; CI-free `cargo test` green.
- [ ] Copy (not move) bb-p2p `mesh` into `cosmos-net`; strip Bloodborne names and the relay server/client + DEFAULT_RELAYS; remaining tests pass.
- [ ] DHT-signaled hole punch (signed observed addresses + simultaneous dial) replaces relay-coordinated dcutr; `NO_PATH` error when nothing works.

## M1 — Sync plane over libp2p
- [ ] `cosmos-core::Session`: host/join, ≤4 peers (5th rejected — test), membership events.
- [ ] Channels: reliable-ordered + unreliable, per-channel caps (tests for order, loss tolerance, oversize drop).
- [ ] Join codes via DHT session advert (signed; forged advert rejected — test).
- [ ] Loopback 4-peer integration test: all pairs exchange 1k msgs.

## M2 — Path migration
- [ ] Channel layer with sequence numbers independent of the path.
- [ ] Background direct retry while relayed; migrate on success, fall back on loss.
- [ ] Test: start on a Steam-relay test double, open direct, no lost/duplicated reliable messages across the switch; then kill direct → back to Steam relay.

## M3 — Steam path
- [ ] Dynamic load of bundled `steam_api64.dll`: reuse the game's in-process Steam if present, else init with AppID 480 (configurable); also usable from `cosmos-node` out of process. Steam client not running = path off, no error.
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

## M6 — Bloodborne on the SDK
- [ ] a game port swaps its `mesh` for `cosmos-net`/`cosmos-core`; world records via the record API; shadNet facade moves to `cosmos-node` facades.
- [ ] Live: same summon + messages test as 2026-10-25 (this PC + a remote friend), plus cross-network.

## M7 — Second game + hardening
- [ ] Second proof game (user picks) via a native hook mod using the C ABI.
- [ ] Security audit of the whole SDK before any public release.

Done = each milestone's tests green, opus review clean, live checks passed and recorded here.
