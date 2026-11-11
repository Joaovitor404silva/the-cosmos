// Cosmos for the browser: the cosmos.h API on public Nostr relays (join
// codes, records, signalling) and WebRTC data channels (sessions).
//
// Sessions copy the native rules: the host is the membership authority, a
// joiner sends join, gets welcome with the members, connects to each of them,
// sends ready, and only then does the host announce it to the rest. Full
// mesh, at most 4 peers. Not wire-compatible with native instances.
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { argon2id } from 'hash-wasm';
import { RelayPool, DEFAULT_RELAYS, signEvent } from './relays.js';

export const OK = 0, E_NULL = -1, E_INVALID = -2, E_PANIC = -3, E_STATE = -4, E_NOT_FOUND = -5, E_FULL = -6,
  E_TIMEOUT = -7, E_NET = -8, E_TOO_LARGE = -9, E_RATE_LIMITED = -10, E_BACKLOG = -11, E_ENDED = -12;
export const EV_PEER_JOINED = 1, EV_PEER_LEFT = 2, EV_MESSAGE = 3, EV_PATH_CHANGED = 4, EV_RECORD_RESULT = 5,
  EV_RECORD_UPDATE = 6, EV_SESSION_ENDED = 7, EV_ERROR = 8;
export const PATH_DIRECT = 1, PATH_RELAY = 2;
export const VERSION = '0.1.0-web';

const KIND_RECORD = 30078; // NIP-78 app data, replaceable per (pubkey, d)
const KIND_SIGNAL = 25050; // ephemeral: relays forward, never store
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const MAX_PEERS = 4;
const RECORD_MAX = 4096;
const MSG_MAX = 64 * 1024;
const RELIABLE_QUEUE = 8 << 20;
const UNRELIABLE_QUEUE = 256 << 10;
const PUT_RATE = 10, PUT_WINDOW = 10000;
const ADVERT_TTL = 180, ADVERT_REFRESH = 60000;
const JOIN_DEADLINE = 30000, RESOLVE_DEADLINE = 20000;
const MAX_CHECKED = 4;
const PING_EVERY = 1000, LINK_DEAD = 10000;
const DAY = 86400;
const ICE = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun.cloudflare.com:3478' }];

const enc = new TextEncoder(), dec = new TextDecoder();
const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

export class CosmosError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
const fail = (code, msg) => { throw new CosmosError(code, msg); };

function framed(parts) {
  const bufs = parts.map((p) => (typeof p === 'string' ? enc.encode(p) : p));
  const out = new Uint8Array(bufs.reduce((n, b) => n + 4 + b.length, 0));
  let o = 0;
  for (const b of bufs) {
    new DataView(out.buffer).setUint32(o, b.length);
    out.set(b, o + 4);
    o += 4 + b.length;
  }
  return sha256(out);
}

const b64 = (u8) => { let s = ''; for (const x of u8) s += String.fromCharCode(x); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function argon(password, salt, len) {
  return argon2id({ password, salt, parallelism: 1, iterations: 2, memorySize: 19 * 1024, hashLength: len, outputType: 'binary' });
}

async function seal(key32, aad, plain) {
  const k = await crypto.subtle.importKey('raw', key32, 'AES-GCM', false, ['encrypt']);
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, k, plain));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

async function open(key32, aad, sealed) {
  try {
    const k = await crypto.subtle.importKey('raw', key32, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12), additionalData: aad }, k, sealed.slice(12)));
  } catch {
    return null;
  }
}

const nameOk = (s) => typeof s === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(s);
const keyOk = (s) => typeof s === 'string' && s.length >= 1 && s.length <= 256 && !/[\u0000-\u001f\u007f]/.test(s);

export function normalizeCode(code) {
  let out = '';
  for (let c of String(code)) {
    if (c === '-' || c === ' ') continue;
    c = c.toUpperCase();
    if (c === 'O') c = '0';
    if (c === 'I' || c === 'L') c = '1';
    if (!ALPHABET.includes(c)) return null;
    out += c;
  }
  return out.length === 8 ? out : null;
}

// code = 40 bits of Argon2id(H(ns, host, salt)): a forged advert for
// someone else's code needs ~2^40 Argon2id hashes.
async function codeFor(ns, hostHex, salt) {
  const h = await argon(framed(['cosmos-web-code:v1', ns, hostHex, salt]), framed(['cosmos-web-code-salt:v1']).slice(0, 16), 8);
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(h[i]);
  let s = '';
  for (let i = 7; i >= 0; i--) s += ALPHABET[Number((bits >> BigInt(i * 5)) & 31n)];
  return s;
}

// The code itself never reaches a relay: adverts sit under a per-day topic
// and key derived from it with Argon2id.
async function dayKeys(ns, code, day) {
  const out = await argon(enc.encode(code), framed(['cosmos-web-join:v1', 'keys-salt', ns, String(day)]).slice(0, 16), 48);
  return { d: bytesToHex(out.slice(0, 16)), key: out.slice(16, 48), day };
}

function loadKey(path) {
  const slot = path ? 'cosmos-key:' + path : null;
  try {
    const hex = slot && globalThis.localStorage?.getItem(slot);
    if (hex && /^[0-9a-f]{64}$/.test(hex)) return hexToBytes(hex);
  } catch {}
  const sk = schnorr.utils.randomPrivateKey();
  try {
    if (slot) globalThis.localStorage?.setItem(slot, bytesToHex(sk));
  } catch {}
  return sk;
}

// One peer connection: channel 0 reliable+ordered, channel 1 unordered with
// no retransmits. Both negotiated, so neither side has to announce them.
class Link {
  constructor(owner, pub, conn) {
    this.owner = owner;
    this.pub = pub;
    this.conn = conn;
    this.pc = new RTCPeerConnection({ iceServers: ICE });
    this.rel = this.pc.createDataChannel('r', { negotiated: true, id: 0, ordered: true });
    this.unrel = this.pc.createDataChannel('u', { negotiated: true, id: 1, ordered: false, maxRetransmits: 0 });
    this.rel.binaryType = this.unrel.binaryType = 'arraybuffer';
    this.lastRx = Date.now();
    this.dead = false;
    this.opened = new Promise((ok) => (this.rel.onopen = ok));
    this.rel.onmessage = (m) => this.rx(new Uint8Array(m.data), true);
    this.unrel.onmessage = (m) => this.rx(new Uint8Array(m.data), false);
    this.rel.onclose = () => this.down('channel closed');
    this.pc.onconnectionstatechange = () => {
      if (['failed', 'closed'].includes(this.pc.connectionState)) this.down('connection ' + this.pc.connectionState);
    };
  }

  async local(desc) {
    await this.pc.setLocalDescription(desc);
    // no trickle: one signalling message per side
    if (this.pc.iceGatheringState !== 'complete')
      await Promise.race([
        new Promise((ok) => this.pc.addEventListener('icegatheringstatechange', () => this.pc.iceGatheringState === 'complete' && ok())),
        sleep(2500),
      ]);
    return this.pc.localDescription.sdp;
  }

  rx(b, reliable) {
    this.lastRx = Date.now();
    if (this.dead || b.length === 0) return;
    this.owner.onFrame(this, b, reliable);
  }

  isOpen() {
    return !this.dead && this.rel.readyState === 'open';
  }

  sendRel(b) {
    if (!this.isOpen()) return E_NOT_FOUND;
    if (this.rel.bufferedAmount + b.length > RELIABLE_QUEUE) return E_BACKLOG;
    try {
      this.rel.send(b);
    } catch {
      return E_BACKLOG;
    }
    return OK;
  }

  sendUnrel(b) {
    if (this.dead || this.unrel.readyState !== 'open') return this.isOpen() ? OK : E_NOT_FOUND;
    if (this.unrel.bufferedAmount + b.length <= UNRELIABLE_QUEUE) try { this.unrel.send(b); } catch {}
    return OK;
  }

  ctrl(obj) {
    const j = enc.encode(JSON.stringify(obj));
    const b = new Uint8Array(1 + j.length);
    b[0] = 0;
    b.set(j, 1);
    return this.sendRel(b);
  }

  down(why) {
    if (this.dead) return;
    this.dead = true;
    try { this.pc.close(); } catch {}
    this.owner.onDown(this, why);
  }

  close() {
    if (this.dead) return;
    this.dead = true;
    // let queued frames (a leave) drain before closing
    const pc = this.pc, rel = this.rel;
    const t0 = Date.now();
    const tick = () => (rel.bufferedAmount > 0 && Date.now() - t0 < 1000 ? setTimeout(tick, 20) : pc.close());
    tick();
  }
}

export class Cosmos {
  static async init(cfg = {}) {
    if (!nameOk(cfg.game_id)) fail(E_INVALID, 'game_id must be 1-64 chars of A-Z a-z 0-9 _ . -');
    const c = new Cosmos(cfg);
    return c;
  }

  constructor(cfg) {
    this.ns = cfg.game_id;
    this.sk = loadKey(cfg.key_path);
    this.pub = bytesToHex(schnorr.getPublicKey(this.sk));
    this.pool = new RelayPool(cfg.relays || DEFAULT_RELAYS);
    this.queueMax = cfg.event_queue || 1024;
    this.events = [];
    this.dropped = 0;
    this.handles = new Map(); // pub -> handle
    this.byHandle = new Map(); // handle -> pub
    this.nextHandle = 1;
    this.puts = [];
    this.subs = new Map(); // sub id -> relay sub id
    this.nextSub = 1;
    this.role = null; // 'host' | 'member'
    this.secret = null;
    this.sigKey = null;
    this.hostPub = null;
    this.links = new Map(); // pub -> Link (members and pending)
    this.members = new Set(); // announced pubs (excluding self)
    this.expected = new Set(); // member: announced by host, link maybe not open yet
    this.pendingAnswers = new Map(); // conn id -> resolve
    this.waiters = new Map(); // pub -> resolve(ctrl) for join handshake
    this.ended = false;
    this.closed = false;
    this.timers = [setInterval(() => this.tick(), PING_EVERY)];
  }

  // ---- events --------------------------------------------------------------
  push(ev) {
    if (this.closed) return;
    this.events.push(ev);
    while (this.events.length > this.queueMax) {
      this.events.shift();
      this.dropped++;
    }
  }

  poll() {
    return this.events.shift() || null;
  }

  handle(pub) {
    let h = this.handles.get(pub);
    if (!h) {
      h = this.nextHandle++;
      this.handles.set(pub, h);
      this.byHandle.set(h, pub);
    }
    return h;
  }

  peerId(handle) {
    if (!handle) return hexToBytes(this.pub);
    const p = this.byHandle.get(handle);
    if (!p) fail(E_NOT_FOUND, 'unknown peer ' + handle);
    return hexToBytes(p);
  }

  hostPeer() {
    return this.role === 'member' && this.hostPub ? this.handle(this.hostPub) : 0;
  }

  // ---- records -------------------------------------------------------------
  recTag(kind, key) {
    if (!nameOk(kind) || !keyOk(key)) fail(E_INVALID, 'bad record kind or key');
    return bytesToHex(framed(['cosmos-rec:v1', this.ns, kind, key]).slice(0, 16));
  }

  async recordPut(kind, key, data, ttl) {
    const d = this.recTag(kind, key);
    if (data.length > RECORD_MAX) fail(E_TOO_LARGE, `record over ${RECORD_MAX} bytes`);
    if (!(ttl > 0)) fail(E_INVALID, 'ttl must be > 0');
    const t = Date.now();
    this.puts = this.puts.filter((x) => t - x < PUT_WINDOW);
    if (this.puts.length >= PUT_RATE) fail(E_RATE_LIMITED, `more than ${PUT_RATE} puts in ${PUT_WINDOW / 1000} s`);
    this.puts.push(t);
    await this.pool.ready();
    const ev = signEvent(this.sk, this.pub, KIND_RECORD, [['d', d], ['expiration', String(now() + ttl)]], b64(data));
    const r = await this.pool.publish(ev);
    if (!r.ok) fail(E_NET, 'publish failed: ' + r.message);
  }

  toRecord(kind, key, ev) {
    const exp = Number(ev.tags.find((t) => t[0] === 'expiration')?.[1] || 0);
    if (!(exp > now())) return null;
    let data;
    try {
      data = unb64(ev.content);
    } catch {
      return null;
    }
    if (data.length > RECORD_MAX) return null;
    return { record_kind: kind, record_key: key, data, publisher: hexToBytes(ev.pubkey), issued_ms: ev.created_at * 1000, expires_s: exp };
  }

  recordQuery(kind, key, reqId) {
    const d = this.recTag(kind, key);
    (async () => {
      await this.pool.ready();
      const best = new Map(); // pubkey -> event (newest wins)
      await new Promise((done) => {
        let id;
        const timer = setTimeout(() => finish(), 6000);
        const finish = () => {
          clearTimeout(timer);
          this.pool.unsub(id);
          done();
        };
        id = this.pool.sub([{ kinds: [KIND_RECORD], '#d': [d], limit: 64 }], (ev) => {
          const old = best.get(ev.pubkey);
          if (!old || ev.created_at > old.created_at) best.set(ev.pubkey, ev);
        }, finish);
      });
      const recs = [...best.values()].map((e) => this.toRecord(kind, key, e)).filter(Boolean).sort((a, b) => a.issued_ms - b.issued_ms);
      if (recs.length === 0) this.push({ kind: EV_RECORD_RESULT, req_id: reqId, error: OK, index: 0, count: 0 });
      recs.forEach((r, i) => this.push({ kind: EV_RECORD_RESULT, req_id: reqId, error: OK, index: i, count: recs.length, ...r }));
    })().catch((e) => this.push({ kind: EV_RECORD_RESULT, req_id: reqId, error: E_NET, message: String(e.message || e), index: 0, count: 0 }));
  }

  recordSubscribe(kind, key) {
    const d = this.recTag(kind, key);
    const sub = this.nextSub++;
    const id = this.pool.sub([{ kinds: [KIND_RECORD], '#d': [d], since: now() - 2 }], (ev) => {
      const r = this.toRecord(kind, key, ev);
      if (r) this.push({ kind: EV_RECORD_UPDATE, req_id: sub, ...r });
    });
    this.subs.set(sub, id);
    return sub;
  }

  recordUnsubscribe(sub) {
    const id = this.subs.get(sub);
    if (!id) fail(E_NOT_FOUND, 'unknown subscription ' + sub);
    this.subs.delete(sub);
    this.pool.unsub(id);
  }

  // ---- join codes ----------------------------------------------------------
  async host() {
    if (this.role || this.ended) fail(E_STATE, 'already in a session');
    if (!(await this.pool.ready())) fail(E_NET, 'no relay reachable');
    const salt = rand(16);
    this.secret = rand(16);
    this.sigKey = framed(['cosmos-web-sig:v1', this.secret]);
    this.code = await codeFor(this.ns, this.pub, salt);
    this.role = 'host';
    this.listenSignals();
    const advert = enc.encode(JSON.stringify({ h: this.pub, s: bytesToHex(salt), k: bytesToHex(this.secret) }));
    const keys = new Map(); // day -> keys
    const publishAll = async () => {
      const today = Math.floor(now() / DAY);
      for (const d of [...keys.keys()]) if (Math.abs(d - today) > 1) keys.delete(d);
      let ok = false;
      for (const day of [today - 1, today, today + 1]) {
        if (!keys.has(day)) keys.set(day, await dayKeys(this.ns, this.code, day));
        const k = keys.get(day);
        const content = b64(await seal(k.key, enc.encode(k.d), advert));
        const ev = signEvent(this.sk, this.pub, KIND_RECORD, [['d', k.d], ['expiration', String(now() + ADVERT_TTL)]], content);
        ok = (await this.pool.publish(ev)).ok || ok;
      }
      return ok;
    };
    if (!(await publishAll())) {
      this.role = null;
      fail(E_NET, 'could not publish the join code');
    }
    this.timers.push(setInterval(() => !this.closed && publishAll().catch(() => {}), ADVERT_REFRESH));
    return this.code.slice(0, 4) + '-' + this.code.slice(4);
  }

  async resolve(code) {
    const today = Math.floor(now() / DAY);
    const k = await dayKeys(this.ns, code, today);
    const deadline = Date.now() + RESOLVE_DEADLINE;
    while (Date.now() < deadline && !this.closed) {
      const found = [];
      await new Promise((done) => {
        let id;
        const timer = setTimeout(() => finish(), 5000);
        const finish = () => { clearTimeout(timer); this.pool.unsub(id); done(); };
        id = this.pool.sub([{ kinds: [KIND_RECORD], '#d': [k.d], limit: 16 }], (ev) => found.push(ev), finish);
      });
      const hosts = new Map();
      for (const ev of found.sort((a, b) => b.created_at - a.created_at)) {
        if (hosts.size >= MAX_CHECKED + 1) break;
        const exp = Number(ev.tags.find((t) => t[0] === 'expiration')?.[1] || 0);
        if (exp <= now() || hosts.has(ev.pubkey)) continue;
        let plain;
        try { plain = await open(k.key, enc.encode(k.d), unb64(ev.content)); } catch { plain = null; }
        if (!plain) continue;
        let a;
        try { a = JSON.parse(dec.decode(plain)); } catch { continue; }
        if (a?.h !== ev.pubkey || !/^[0-9a-f]{32}$/.test(a.s) || !/^[0-9a-f]{32}$/.test(a.k)) continue;
        hosts.set(ev.pubkey, a);
      }
      if (hosts.size > MAX_CHECKED) fail(E_NOT_FOUND, 'too many adverts under this code');
      for (const a of hosts.values())
        if ((await codeFor(this.ns, a.h, hexToBytes(a.s))) === code) return a;
      await sleep(2000);
    }
    fail(E_NOT_FOUND, 'no run found for this code');
  }

  async join(rawCode) {
    if (this.role || this.ended) fail(E_STATE, 'already in a session');
    const code = normalizeCode(rawCode);
    if (!code) fail(E_INVALID, 'a code looks like XXXX-XXXX');
    if (!(await this.pool.ready())) fail(E_NET, 'no relay reachable');
    const a = await this.resolve(code);
    if (a.h === this.pub) fail(E_INVALID, 'that is our own run');
    this.secret = hexToBytes(a.k);
    this.sigKey = framed(['cosmos-web-sig:v1', this.secret]);
    this.hostPub = a.h;
    this.listenSignals();
    const deadline = Date.now() + JOIN_DEADLINE;
    try {
      const host = await this.connect(a.h, deadline);
      let w;
      do {
        if (w) await sleep(1000); // host busy with another joiner
        const reply = this.waitCtrl(a.h, deadline);
        host.ctrl({ t: 'join', s: a.k });
        w = await reply;
      } while (w.t === 'busy');
      if (w.t === 'reject') fail(E_FULL, 'the run is full');
      if (w.t !== 'welcome' || !Array.isArray(w.m) || w.m.length >= MAX_PEERS) fail(E_NET, 'bad welcome');
      const others = w.m.filter((p) => typeof p === 'string' && /^[0-9a-f]{64}$/.test(p) && p !== this.pub && p !== a.h);
      await Promise.all(others.map((p) => this.connect(p, deadline)));
      this.role = 'member';
      host.ctrl({ t: 'ready' });
      for (const p of [a.h, ...others]) this.announce(p);
    } catch (e) {
      for (const l of this.links.values()) l.close();
      this.links.clear();
      this.hostPub = this.secret = null;
      this.role = null;
      if (this.sigSub) this.pool.unsub(this.sigSub);
      this.sigSub = null;
      throw e instanceof CosmosError ? e : new CosmosError(E_NET, String(e.message || e));
    }
  }

  waitCtrl(pub, deadline) {
    return new Promise((ok, no) => {
      const t = setTimeout(() => { this.waiters.delete(pub); no(new CosmosError(E_TIMEOUT, 'host did not answer')); }, Math.max(0, deadline - Date.now()));
      this.waiters.set(pub, (c) => { clearTimeout(t); this.waiters.delete(pub); ok(c); });
    });
  }

  announce(pub) {
    if (this.members.has(pub) || this.closed) return;
    this.members.add(pub);
    const h = this.handle(pub);
    this.push({ kind: EV_PEER_JOINED, peer: h });
    this.push({ kind: EV_PATH_CHANGED, peer: h, path: PATH_DIRECT });
  }

  // ---- signalling ----------------------------------------------------------
  listenSignals() {
    this.sigSub = this.pool.sub([{ kinds: [KIND_SIGNAL], '#p': [this.pub], since: now() - 10 }], (ev) => this.onSignal(ev).catch(() => {}));
  }

  async signal(to, obj) {
    const aad = enc.encode(this.pub + to);
    const content = b64(await seal(this.sigKey, aad, enc.encode(JSON.stringify(obj))));
    this.pool.emit(signEvent(this.sk, this.pub, KIND_SIGNAL, [['p', to], ['expiration', String(now() + 60)]], content));
  }

  async onSignal(ev) {
    if (this.closed || !this.sigKey || ev.pubkey === this.pub || now() - ev.created_at > 30) return;
    const plain = await open(this.sigKey, enc.encode(ev.pubkey + this.pub), unb64(ev.content));
    if (!plain) return; // not a holder of this run's code
    const m = JSON.parse(dec.decode(plain));
    if (m.t === 'answer') {
      this.pendingAnswers.get(m.c)?.(m.sdp);
    } else if (m.t === 'offer' && typeof m.sdp === 'string') {
      // only joiners offer: to the host, or to members the host welcomed them to
      if (this.role !== 'host' && this.role !== 'member') return;
      const old = this.links.get(ev.pubkey);
      if (old && old.conn === m.c) { // a resent offer: our answer may have been lost
        if (old.answer) await this.signal(ev.pubkey, { t: 'answer', c: m.c, sdp: old.answer });
        return;
      }
      old?.close();
      const l = new Link(this, ev.pubkey, m.c);
      this.links.set(ev.pubkey, l);
      await l.pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
      const sdp = await l.local(await l.pc.createAnswer());
      l.answer = sdp;
      await this.signal(ev.pubkey, { t: 'answer', c: m.c, sdp });
      // a stranger the host never announces is dropped
      setTimeout(() => { if (!this.members.has(ev.pubkey) && this.links.get(ev.pubkey) === l) { this.links.delete(ev.pubkey); l.close(); } }, JOIN_DEADLINE);
    }
  }

  async connect(pub, deadline) {
    const conn = bytesToHex(rand(8));
    const l = new Link(this, pub, conn);
    this.links.get(pub)?.close();
    this.links.set(pub, l);
    const answered = new Promise((ok) => this.pendingAnswers.set(conn, ok));
    const sdp = await l.local(await l.pc.createOffer());
    let answer = null;
    for (let i = 0; i < 3 && !answer && Date.now() < deadline; i++) {
      await this.signal(pub, { t: 'offer', c: conn, sdp });
      answer = await Promise.race([answered, sleep(Math.min(5000, Math.max(0, deadline - Date.now())))]);
    }
    this.pendingAnswers.delete(conn);
    if (!answer) fail(E_TIMEOUT, 'peer did not answer the offer');
    await l.pc.setRemoteDescription({ type: 'answer', sdp: answer });
    const opened = await Promise.race([l.opened.then(() => true), sleep(Math.max(0, deadline - Date.now())).then(() => false)]);
    if (!opened || l.dead) fail(E_TIMEOUT, 'no direct connection (strict NAT on one side?)');
    return l;
  }

  // ---- frames --------------------------------------------------------------
  onFrame(l, b, reliable) {
    if (this.links.get(l.pub) !== l) return;
    if (!reliable) {
      if (this.members.has(l.pub) && b.length >= 1)
        this.push({ kind: EV_MESSAGE, peer: this.handle(l.pub), channel: b[0], reliable: 0, data: b.slice(1) });
      return;
    }
    if (b[0] === 2) return; // ping
    if (b[0] === 1) {
      if (this.members.has(l.pub) && b.length >= 2)
        this.push({ kind: EV_MESSAGE, peer: this.handle(l.pub), channel: b[1], reliable: 1, data: b.slice(2) });
      return;
    }
    if (b[0] !== 0) return;
    let c;
    try { c = JSON.parse(dec.decode(b.subarray(1))); } catch { return; }
    this.onCtrl(l, c);
  }

  onCtrl(l, c) {
    const from = l.pub;
    if (this.waiters.has(from)) return this.waiters.get(from)(c);
    if (this.role === 'host') {
      if (c.t === 'join') {
        if (c.s !== bytesToHex(this.secret)) return l.close();
        if (this.members.size + 1 >= MAX_PEERS) { l.ctrl({ t: 'reject' }); setTimeout(() => l.close(), 500); return; }
        // one joiner at a time, so every joiner's welcome lists every member
        const busy = [...this.links.values()].some((x) => x !== l && x.joining && !x.dead && Date.now() - x.joining < 15000);
        if (busy) return l.ctrl({ t: 'busy' });
        l.joining = Date.now();
        l.ctrl({ t: 'welcome', m: [...this.members] });
      } else if (c.t === 'ready' && l.joining && !this.members.has(from)) {
        l.joining = 0;
        if (this.members.size + 1 >= MAX_PEERS) { l.ctrl({ t: 'reject' }); setTimeout(() => l.close(), 500); return; }
        for (const p of this.members) this.links.get(p)?.ctrl({ t: 'joined', p: from });
        this.announce(from);
      } else if (c.t === 'leave') {
        this.drop(from);
      }
    } else if (this.role === 'member') {
      if (from === this.hostPub) {
        if (c.t === 'joined' && typeof c.p === 'string' && c.p !== this.pub) {
          if (this.links.get(c.p)?.isOpen()) this.announce(c.p);
          else this.expected.add(c.p);
        } else if (c.t === 'left' && typeof c.p === 'string') {
          this.drop(c.p);
        } else if (c.t === 'leave') {
          this.end();
        }
      } else if (c.t === 'leave') {
        this.drop(from);
      }
    }
  }

  onDown(l, why) {
    if (this.links.get(l.pub) !== l) return;
    if (this.role === 'member' && l.pub === this.hostPub) return this.end();
    this.drop(l.pub);
  }

  drop(pub) {
    const l = this.links.get(pub);
    this.links.delete(pub);
    this.expected.delete(pub);
    l?.close();
    if (!this.members.delete(pub)) return;
    this.push({ kind: EV_PEER_LEFT, peer: this.handle(pub) });
    if (this.role === 'host') for (const p of this.members) this.links.get(p)?.ctrl({ t: 'left', p: pub });
  }

  end() {
    if (this.ended) return;
    this.ended = true;
    for (const l of this.links.values()) l.close();
    this.links.clear();
    this.members.clear();
    this.role = null;
    this.push({ kind: EV_SESSION_ENDED });
  }

  tick() {
    const t = Date.now();
    for (const [pub, l] of this.links) {
      if (l.dead) continue;
      if (l.isOpen()) {
        l.sendRel(new Uint8Array([2]));
        if (this.expected.has(pub)) { this.expected.delete(pub); this.announce(pub); }
      }
      if (l.isOpen() && t - l.lastRx > LINK_DEAD) l.down('silent for 10 s');
    }
  }

  send(peer, channel, data, reliable) {
    if (!this.role) fail(this.ended ? E_ENDED : E_STATE, 'no session: host or join first');
    if (data.length > MSG_MAX) fail(E_TOO_LARGE, `message over ${MSG_MAX} bytes`);
    const b = new Uint8Array(data.length + (reliable ? 2 : 1));
    if (reliable) { b[0] = 1; b[1] = channel; b.set(data, 2); } else { b[0] = channel; b.set(data, 1); }
    const to = peer ? [this.byHandle.get(peer)] : [...this.members];
    if (peer && (!to[0] || !this.members.has(to[0]))) fail(E_NOT_FOUND, 'unknown peer ' + peer);
    let r = OK;
    for (const p of to) {
      const l = this.links.get(p);
      const x = l ? (reliable ? l.sendRel(b) : l.sendUnrel(b)) : E_NOT_FOUND;
      if (x !== OK && peer) r = x;
    }
    if (r !== OK) fail(r, r === E_BACKLOG ? 'send backlog full' : 'no path to peer');
  }

  shutdown() {
    if (this.closed) return;
    for (const l of this.links.values()) { l.ctrl({ t: 'leave' }); l.close(); }
    this.closed = true;
    this.links.clear();
    for (const t of this.timers) clearInterval(t);
    this.pool.close();
    this.events = [];
  }
}
