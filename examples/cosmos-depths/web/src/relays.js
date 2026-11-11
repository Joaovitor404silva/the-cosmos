// Nostr relay pool: publish to every relay, subscribe on every relay,
// dedupe by event id, reconnect with backoff and replay subscriptions.
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Measured 2026-11-10: these accept kind 30078 (+ NIP-40 expiration),
// answer #d queries and forward ephemeral kind 25050 to live subscribers.
export const DEFAULT_RELAYS = [
  'wss://relay.primal.net',
  'wss://relay.snort.social',
  'wss://offchain.pub',
  'wss://relay.nostr.net',
  'wss://nostr.oxtr.dev',
  'wss://nostr.bitcoiner.social',
];

const enc = new TextEncoder();

export function eventId(ev) {
  return bytesToHex(sha256(enc.encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
}

export function signEvent(sk, pubHex, kind, tags, content, createdAt) {
  const ev = { pubkey: pubHex, created_at: createdAt ?? Math.floor(Date.now() / 1000), kind, tags, content };
  ev.id = eventId(ev);
  ev.sig = bytesToHex(schnorr.sign(ev.id, sk));
  return ev;
}

export function verifyEvent(ev) {
  try {
    if (typeof ev?.id !== 'string' || typeof ev.sig !== 'string' || typeof ev.pubkey !== 'string') return false;
    if (eventId(ev) !== ev.id) return false;
    return schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch {
    return false;
  }
}

class Relay {
  constructor(pool, url) {
    this.pool = pool;
    this.url = url;
    this.ws = null;
    this.open = false;
    this.backoff = 1000;
    this.out = []; // queued while connecting
    this.timer = null;
    this.connect();
  }

  connect() {
    if (this.pool.closed) return;
    let ws;
    try {
      ws = new WebSocket(this.url);
    } catch {
      return this.retry();
    }
    this.ws = ws;
    ws.onopen = () => {
      this.open = true;
      this.backoff = 1000;
      for (const [id, s] of this.pool.subs) this.raw(['REQ', id, ...s.filters]);
      const out = this.out;
      this.out = [];
      for (const m of out) this.raw(m);
    };
    ws.onmessage = (m) => {
      let msg;
      try {
        msg = JSON.parse(m.data);
      } catch {
        return;
      }
      if (Array.isArray(msg)) this.pool.onMessage(this, msg);
    };
    ws.onclose = () => {
      this.open = false;
      if (this.ws === ws) this.retry();
    };
    ws.onerror = () => {};
  }

  retry() {
    if (this.pool.closed) return;
    this.open = false;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.connect(), this.backoff);
    this.backoff = Math.min(this.backoff * 2, 30000);
    // a subscription waiting for EOSE should not wait on a dead relay
    for (const s of this.pool.subs.values()) s.eosed.add(this.url);
    for (const s of this.pool.subs.values()) this.pool.checkEose(s);
  }

  raw(m) {
    if (this.open && this.ws?.readyState === 1) {
      try {
        this.ws.send(JSON.stringify(m));
      } catch {}
    }
  }

  send(m) {
    if (this.open && this.ws?.readyState === 1) this.raw(m);
    else if (m[0] !== 'REQ' && m[0] !== 'CLOSE') this.out.push(m); // REQs replay on open
    if (this.out.length > 64) this.out.shift();
  }

  close() {
    clearTimeout(this.timer);
    const ws = this.ws;
    this.ws = null;
    this.open = false;
    try {
      ws?.close();
    } catch {}
  }
}

export class RelayPool {
  constructor(urls = DEFAULT_RELAYS) {
    this.closed = false;
    this.subs = new Map(); // id -> {filters, onEvent, onEose, seen, eosed}
    this.pending = new Map(); // event id -> {resolve, yes, no}
    this.next = 1;
    this.relays = urls.map((u) => new Relay(this, u));
  }

  openCount() {
    return this.relays.filter((r) => r.open).length;
  }

  // Resolves once `n` relays are open (or after `ms`): queries made before
  // any relay is up would see an instant, empty EOSE.
  async ready(n = 2, ms = 6000) {
    const until = Date.now() + ms;
    while (this.openCount() < Math.min(n, this.relays.length) && Date.now() < until && !this.closed)
      await new Promise((r) => setTimeout(r, 50));
    return this.openCount() > 0;
  }

  onMessage(relay, msg) {
    const [t, a, b, c] = msg;
    if (t === 'EVENT') {
      const s = this.subs.get(a);
      if (!s || !b || s.seen.has(b.id) || s.got >= s.max) return; // a hostile relay can't grow a query without bound
      if (!verifyEvent(b)) return;
      s.seen.add(b.id);
      s.got++;
      if (s.seen.size > 4096) s.seen = new Set([...s.seen].slice(-2048));
      s.onEvent(b);
    } else if (t === 'EOSE' || t === 'CLOSED') {
      const s = this.subs.get(a);
      if (s) {
        s.eosed.add(relay.url);
        this.checkEose(s);
      }
    } else if (t === 'OK') {
      const p = this.pending.get(a);
      if (!p) return;
      if (b) p.yes++;
      else p.no++;
      if (p.yes > 0) p.done(true);
      else if (p.no >= this.relays.length) p.done(false, c);
    }
  }

  checkEose(s) {
    if (!s.onEose || s.eoseFired) return;
    if (this.relays.every((r) => s.eosed.has(r.url) || !r.open)) {
      s.eoseFired = true;
      s.onEose();
    }
  }

  // Resolves {ok, message} at the first relay that accepts, or after `ms`.
  publish(ev, ms = 8000) {
    return new Promise((resolve) => {
      let fired = false;
      const p = {
        yes: 0,
        no: 0,
        done: (ok, message) => {
          if (fired) return;
          fired = true;
          clearTimeout(timer);
          this.pending.delete(ev.id);
          resolve({ ok, message: message || (ok ? '' : 'no relay accepted the event') });
        },
      };
      const timer = setTimeout(() => p.done(false, 'no relay answered in time'), ms);
      this.pending.set(ev.id, p);
      for (const r of this.relays) r.send(['EVENT', ev]);
    });
  }

  // Ephemeral publish: fire and forget.
  emit(ev) {
    for (const r of this.relays) r.send(['EVENT', ev]);
  }

  sub(filters, onEvent, onEose, max = Infinity) {
    const id = 'c' + this.next++;
    const s = { filters, onEvent, onEose, seen: new Set(), eosed: new Set(), eoseFired: false, got: 0, max };
    this.subs.set(id, s);
    for (const r of this.relays) if (r.open) r.raw(['REQ', id, ...filters]);
    if (onEose) setTimeout(() => this.checkEose(s), 0); // nothing open: fire at once
    return id;
  }

  unsub(id) {
    if (!this.subs.delete(id)) return;
    for (const r of this.relays) r.raw(['CLOSE', id]);
  }

  close() {
    this.closed = true;
    for (const p of this.pending.values()) p.done(false, 'shut down');
    for (const r of this.relays) r.close();
    this.subs.clear();
  }
}
