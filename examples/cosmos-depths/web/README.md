# Cosmos Depths in the browser

The same C game, built with emscripten, with a JavaScript Cosmos backend in
place of the Rust library:

- **Join codes and records** live on public Nostr relays (kind 30078 with a
  NIP-40 expiry). Join adverts sit under a per-day topic and an AES-GCM key
  derived from the code with Argon2id, as in the native SDK; the code is bound
  to the host key (40 bits of Argon2id over host key + salt).
- **Sessions** are WebRTC data channels (one reliable, one unordered with no
  retransmits) signalled over ephemeral Nostr events sealed with the run's
  secret. Same rules as native: the host admits, full mesh, at most 4.
- No server of our own. STUN only, so two players behind strict NATs may not
  connect. Not wire-compatible with native instances.

Files: `src/` backend (bundled to `cosmos-web.js`), `c/` the cosmos.h bridge
(`library_cosmos.js` runs every call on the main thread; host, join and
record put block a worker thread on a futex) and `plat_web.c` (pthreads),
`shell.html` the page (coi-serviceworker gives GitHub Pages the COOP/COEP
headers threads need).

    powershell -ExecutionPolicy Bypass -File examples\cosmos-depths\web\build.ps1
    cd examples\cosmos-depths\web
    npm test                     # 5 backend instances on the live relays
    node test\game.mjs OUTDIR    # built game: bot host + bot joiner, screenshots

URL flags: `?host`, `?public`, `?browse`, `?join=CODE`, `?bot`.
