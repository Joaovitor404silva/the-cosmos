// emscripten --js-library: cosmos.h calls run on the main browser thread
// (WebRTC lives there), proxied synchronously from worker threads.
// The Cosmos objects come from the cosmos-web.js bundle (globalThis.CosmosWeb).
addToLibrary({
  $cwState: { list: new Map(), next: 1 },
  $cwGet: (id) => cwState.list.get(id),
  $cwErr: (e, err) => {
    if (err) stringToUTF8(String((e && e.message) || e), err, 256);
    return (e && typeof e.code === 'number') ? e.code : -3;
  },
  // copies: views on the shared heap cannot go to WebRTC or WebCrypto
  $cwBytes: (p, n) => HEAPU8.slice(p, p + n),

  cw_init__proxy: 'sync',
  cw_init__deps: ['$cwState', '$cwErr'],
  cw_init: (ns, key, queue, err) => {
    try {
      const c = new CosmosWeb.Cosmos({ game_id: UTF8ToString(ns), key_path: key ? UTF8ToString(key) : '', event_queue: queue });
      const id = cwState.next++;
      cwState.list.set(id, c);
      return id;
    } catch (e) {
      return cwErr(e, err);
    }
  },

  // ev: int32[12] kind peer channel reliable path req_id error index count len pub_len has_msg; t: f64[2]
  cw_poll__proxy: 'sync',
  cw_poll__deps: ['$cwGet'],
  cw_poll: (id, ev, t, data, cap, kind, key, pub, msg) => {
    const c = cwGet(id);
    const e = c && c.poll();
    if (!e) return 0;
    const i = ev >> 2;
    const d = e.data || new Uint8Array(0);
    const n = Math.min(d.length, cap);
    HEAP32[i] = e.kind;
    HEAPU32[i + 1] = e.peer || 0;
    HEAP32[i + 2] = e.channel || 0;
    HEAP32[i + 3] = e.reliable || 0;
    HEAP32[i + 4] = e.path || 0;
    HEAPU32[i + 5] = e.req_id || 0;
    HEAP32[i + 6] = e.error || 0;
    HEAPU32[i + 7] = e.index || 0;
    HEAPU32[i + 8] = e.count || 0;
    HEAP32[i + 9] = n;
    HEAPU8.set(d.subarray(0, n), data);
    const p = e.publisher || new Uint8Array(0);
    HEAP32[i + 10] = Math.min(p.length, 64);
    HEAPU8.set(p.subarray(0, 64), pub);
    HEAP32[i + 11] = e.message ? 1 : 0;
    if (e.message) stringToUTF8(e.message, msg, 256);
    stringToUTF8(e.record_kind || '', kind, 72);
    stringToUTF8(e.record_key || '', key, 264);
    HEAPF64[t >> 3] = e.issued_ms || 0;
    HEAPF64[(t >> 3) + 1] = e.expires_s || 0;
    return 1;
  },

  cw_send__proxy: 'sync',
  cw_send__deps: ['$cwGet', '$cwErr', '$cwBytes'],
  cw_send: (id, peer, ch, d, len, rel, err) => {
    try {
      cwGet(id).send(peer >>> 0, ch, cwBytes(d, len), rel);
      return 0;
    } catch (e) {
      return cwErr(e, err);
    }
  },

  // op 1 host, 2 join, 3 put. `w`: int32 done, int32 rc, char code[16], char err[256].
  cw_start__proxy: 'sync',
  cw_start__deps: ['$cwGet', '$cwErr', '$cwBytes'],
  cw_start: (op, id, a, b, d, len, ttl, w) => {
    const c = cwGet(id);
    let p;
    try {
      if (op === 1) p = c.host();
      else if (op === 2) p = c.join(UTF8ToString(a));
      else p = c.recordPut(UTF8ToString(a), UTF8ToString(b), cwBytes(d, len), ttl >>> 0);
    } catch (e) {
      p = Promise.reject(e);
    }
    Promise.resolve(p).then(
      (code) => { if (typeof code === 'string') stringToUTF8(code, w + 8, 16); return 0; },
      (e) => cwErr(e, w + 24),
    ).then((rc) => {
      HEAP32[(w >> 2) + 1] = rc;
      Atomics.store(HEAP32, w >> 2, 1);
      Atomics.notify(HEAP32, w >> 2);
    });
  },

  cw_query__proxy: 'sync',
  cw_query__deps: ['$cwGet', '$cwErr'],
  cw_query: (id, kind, key, req, err) => {
    try {
      cwGet(id).recordQuery(UTF8ToString(kind), UTF8ToString(key), req >>> 0);
      return 0;
    } catch (e) {
      return cwErr(e, err);
    }
  },

  cw_subscribe__proxy: 'sync',
  cw_subscribe__deps: ['$cwGet', '$cwErr'],
  cw_subscribe: (id, kind, key, err) => {
    try {
      return cwGet(id).recordSubscribe(UTF8ToString(kind), UTF8ToString(key));
    } catch (e) {
      return cwErr(e, err);
    }
  },

  cw_unsubscribe__proxy: 'sync',
  cw_unsubscribe__deps: ['$cwGet', '$cwErr'],
  cw_unsubscribe: (id, sub, err) => {
    try {
      cwGet(id).recordUnsubscribe(sub);
      return 0;
    } catch (e) {
      return cwErr(e, err);
    }
  },

  cw_host_peer__proxy: 'sync',
  cw_host_peer__deps: ['$cwGet'],
  cw_host_peer: (id) => cwGet(id)?.hostPeer() || 0,

  cw_dropped__proxy: 'sync',
  cw_dropped__deps: ['$cwGet'],
  cw_dropped: (id) => cwGet(id)?.dropped || 0,

  cw_peer_id__proxy: 'sync',
  cw_peer_id__deps: ['$cwGet', '$cwErr'],
  cw_peer_id: (id, peer, out, cap, err) => {
    try {
      const b = cwGet(id).peerId(peer >>> 0);
      if (b.length > cap) return cwErr({ code: -13, message: 'buffer too small' }, err);
      HEAPU8.set(b, out);
      return b.length;
    } catch (e) {
      return cwErr(e, err);
    }
  },

  cw_shutdown__proxy: 'sync',
  cw_shutdown__deps: ['$cwState'],
  cw_shutdown: (id) => {
    cwState.list.get(id)?.shutdown();
    cwState.list.delete(id);
  },
});
