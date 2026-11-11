// Live scenario on the real public relays: 5 instances in one page.
import * as C from '../src/cosmos.js';

const log = (...a) => console.log('[scenario]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const checks = [];
const check = (name, ok, extra = '') => { checks.push({ name, ok: !!ok }); log(ok ? 'ok:' : 'FAIL:', name, extra); };

function drain(c, into) {
  for (let e; (e = c.poll()); ) into.push(e);
  return into;
}
async function until(f, ms = 20000) {
  const t = Date.now() + ms;
  while (Date.now() < t) { if (f()) return true; await sleep(100); }
  return false;
}

async function main() {
  const ns = 'cosmos-web-test-' + Math.random().toString(36).slice(2, 8);
  const [a, b, c, d, e] = await Promise.all([0, 1, 2, 3, 4].map(() => C.Cosmos.init({ game_id: ns })));
  const ev = new Map([a, b, c, d, e].map((x) => [x, []]));
  // like the game's hello: greet every peer the moment it is announced
  const pump = setInterval(() => {
    for (const [x, list] of ev) {
      const n = list.length;
      drain(x, list);
      for (const q of list.slice(n)) if (q.kind === C.EV_PEER_JOINED) try { x.send(q.peer, 7, new Uint8Array([7]), 1); } catch {}
    }
  }, 20);
  const joined = (x) => ev.get(x).filter((q) => q.kind === C.EV_PEER_JOINED).map((q) => q.peer);

  let t0 = Date.now();
  const code = await a.host();
  check('host publishes a code', /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(code), `${code} in ${Date.now() - t0} ms`);

  t0 = Date.now();
  await b.join(code.toLowerCase().replace('-', ' '));
  check('B joins (normalised code)', b.hostPeer() > 0, `${Date.now() - t0} ms`);
  t0 = Date.now();
  // broadcast the instant join() resolves: members may not have heard `joined` from the host yet
  const sayHi = (x) => () => x.send(0, 8, new Uint8Array([8]), 1);
  const both = await Promise.allSettled([c.join(code).then(sayHi(c)), d.join(code).then(sayHi(d))]);
  check('C and D join at the same time', both.every((r) => r.status === 'fulfilled'), `${Date.now() - t0} ms ${both.map((r) => r.reason?.message || '').join(' ')}`);
  const full = await e.join(code).then(() => 'joined', (x) => x.code);
  check('E is refused: run full', full === C.E_FULL, String(full));

  await until(() => [a, b, c, d].every((x) => joined(x).length >= 3));
  check('everyone sees 3 peers', [a, b, c, d].every((x) => joined(x).length === 3), [a, b, c, d].map((x) => joined(x).length).join(','));

  await until(() => [a, b, c, d].every((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 7).length >= 3), 5000);
  check('greetings sent on PEER_JOINED all arrive', [a, b, c, d].every((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 7).length === 3),
    [a, b, c, d].map((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 7).length).join(','));

  await until(() => [a, b].every((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 8).length >= 2), 5000);
  check('a new joiner broadcast reaches every member', [a, b].every((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 8).length === 2),
    [a, b].map((x) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === 8).length).join(','));

  // messages
  const hb = b.hostPeer();
  b.send(hb, 3, new Uint8Array([1, 2, 3]), 1);
  a.send(0, 4, new Uint8Array([9]), 1);
  for (let i = 0; i < 20; i++) c.send(0, 5, new Uint8Array([i]), 0);
  await sleep(1500);
  const msgs = (x, ch) => ev.get(x).filter((q) => q.kind === C.EV_MESSAGE && q.channel === ch);
  check('reliable to host', msgs(a, 3).some((m) => m.reliable === 1 && m.data.join() === '1,2,3'));
  check('host broadcast reaches all', [b, c, d].every((x) => msgs(x, 4).length === 1));
  check('unreliable broadcast arrives', [a, b, d].every((x) => msgs(x, 5).length >= 15), [a, b, d].map((x) => msgs(x, 5).length).join(','));

  // records
  const sub = c.recordSubscribe('ghost', 'd1');
  await sleep(1500);
  t0 = Date.now();
  await a.recordPut('note', 'd1', new TextEncoder().encode('hello'), 120);
  check('record put', true, `${Date.now() - t0} ms`);
  await d.recordPut('ghost', 'd1', new Uint8Array([7, 7]), 15);
  const f = await C.Cosmos.init({ game_id: ns });
  f.recordQuery('note', 'd1', 42);
  const fe = [];
  await until(() => drain(f, fe).some((q) => q.kind === C.EV_RECORD_RESULT), 15000);
  const r = fe.find((q) => q.kind === C.EV_RECORD_RESULT);
  check('fresh instance queries the note back', r && r.count === 1 && new TextDecoder().decode(r.data) === 'hello' && r.publisher.length === 32, JSON.stringify(r && { count: r.count, error: r.error }));
  await until(() => ev.get(c).some((q) => q.kind === C.EV_RECORD_UPDATE && q.req_id === sub), 15000);
  check('subscription sees the live ghost', ev.get(c).some((q) => q.kind === C.EV_RECORD_UPDATE && q.data.join() === '7,7'));
  f.recordQuery('nothing', 'here', 43);
  await until(() => drain(f, fe).some((q) => q.req_id === 43), 15000);
  const empty = fe.find((q) => q.req_id === 43);
  check('empty query gives count 0', empty && empty.count === 0);
  f.shutdown();

  // leaving
  d.shutdown();
  await until(() => [a, b, c].every((x) => ev.get(x).some((q) => q.kind === C.EV_PEER_LEFT)), 15000);
  check('D leaves: the rest see PEER_LEFT', [a, b, c].every((x) => ev.get(x).filter((q) => q.kind === C.EV_PEER_LEFT).length === 1));
  a.shutdown();
  await until(() => [b, c].every((x) => ev.get(x).some((q) => q.kind === C.EV_SESSION_ENDED)), 15000);
  check('host leaves: session ended', [b, c].every((x) => ev.get(x).some((q) => q.kind === C.EV_SESSION_ENDED)));
  let sendErr = 0;
  try { b.send(0, 1, new Uint8Array(1), 1); } catch (x) { sendErr = x.code; }
  check('send after end is E_ENDED', sendErr === C.E_ENDED, String(sendErr));

  clearInterval(pump);
  for (const x of [b, c, e]) x.shutdown();
}

main()
  .catch((x) => check('scenario threw', false, x.stack || x))
  .finally(() => {
    window.__result = { pass: checks.length > 0 && checks.every((c) => c.ok), checks };
    log(window.__result.pass ? 'PASS' : 'FAIL');
  });
