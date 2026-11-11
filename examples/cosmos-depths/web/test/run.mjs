// Serves build/ on localhost and runs a page in headless Edge/Chrome/Brave.
// Usage: node test/run.mjs [page.html] (default: the live scenario)
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import puppeteer from 'puppeteer-core';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1')), '..');
const page = process.argv[2] || 'scenario';
const BROWSERS = [
  process.env.BROWSER,
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe',
].filter(Boolean);
const exe = BROWSERS.find((b) => fs.existsSync(b));
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.data': 'application/octet-stream' };

const html = `<!doctype html><meta charset=utf-8><title>scenario</title><script src="/build/scenario.js"></script>`;
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (u === '/scenario') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(html); }
  const f = path.join(root, u);
  if (!f.startsWith(root) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, {
    'content-type': TYPES[path.extname(f)] || 'application/octet-stream',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp',
  });
  fs.createReadStream(f).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/${page}`;

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-web-'));
const browser = await puppeteer.launch({ executablePath: exe, headless: true, userDataDir: profile, args: ['--no-first-run', '--autoplay-policy=no-user-gesture-required'] });
let code = 1;
try {
  const p = await browser.newPage();
  p.on('console', (m) => console.log(m.text()));
  p.on('pageerror', (e) => console.log('pageerror:', e.message));
  await p.goto(url);
  await p.waitForFunction('window.__result', { timeout: 240000, polling: 250 });
  const r = await p.evaluate('window.__result');
  console.log(r.pass ? 'PASS' : 'FAIL', `${r.checks.filter((c) => c.ok).length}/${r.checks.length}`);
  code = r.pass ? 0 : 1;
} finally {
  await browser.close();
  server.close();
  fs.rmSync(profile, { recursive: true, force: true });
}
process.exit(code);
