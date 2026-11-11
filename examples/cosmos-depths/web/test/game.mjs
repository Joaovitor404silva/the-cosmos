// Live browser test of the built game (dist/cosmos-depths-web): a bot host
// and a bot joiner in two isolated browser contexts, over the public relays.
// Usage: [SITE_URL=https://...] node test/game.mjs OUTDIR   -> host.png, join.png
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import puppeteer from 'puppeteer-core';

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1'));
const site = path.resolve(here, '../../../../dist/cosmos-depths-web');
const out = path.resolve(process.argv[2] || '.');
const exe = [process.env.BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe']
  .filter(Boolean).find((b) => fs.existsSync(b));
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };

const server = http.createServer((req, res) => {
  let u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (u === '/') u = '/index.html';
  const f = path.join(site, u);
  if (!f.startsWith(site) || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream' }); // no COOP/COEP: coi-serviceworker must do it
  fs.createReadStream(f).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = process.env.SITE_URL || `http://127.0.0.1:${server.address().port}/`; // SITE_URL: test the deployed site

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-game-'));
const browser = await puppeteer.launch({ executablePath: exe, headless: true, userDataDir: profile, args: ['--no-first-run', '--enable-unsafe-swiftshader'] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let code = 1;
try {
  async function open(name, query) {
    const ctx = await browser.createBrowserContext();
    const p = await ctx.newPage();
    await p.setViewport({ width: 1180, height: 900 });
    const lines = [];
    p.on('console', (m) => { lines.push(m.text()); console.log(`[${name}] ${m.text()}`); });
    p.on('pageerror', (e) => console.log(`[${name}] pageerror: ${e.message}`));
    await p.goto(base + query);
    return { p, lines };
  }
  const host = await open('host', '?host&bot');
  let joinCode = null;
  for (let i = 0; i < 300 && !joinCode; i++) {
    joinCode = host.lines.map((l) => /join code (\S+)/.exec(l)?.[1]).find(Boolean);
    await sleep(100);
  }
  if (!joinCode) throw new Error('host printed no join code');
  const join = await open('join', `?join=${joinCode}&bot`);
  await sleep(15000);
  await host.p.screenshot({ path: path.join(out, 'host.png') });
  await join.p.screenshot({ path: path.join(out, 'join.png') });
  const isolated = await join.p.evaluate('crossOriginIsolated');
  console.log('code', joinCode, 'isolated', isolated);
  code = isolated ? 0 : 1;
} catch (e) {
  console.log('FAIL', e.message);
} finally {
  await browser.close();
  server.close();
  fs.rmSync(profile, { recursive: true, force: true });
}
process.exit(code);
