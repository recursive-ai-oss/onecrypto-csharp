// Serves a published browser-wasm app on a loopback port, opens it in a headless browser and waits for the page to post its results.
//
//   node serve-and-drive.mjs <wwwroot dir> <browser executable> <result file> [areas]
//
// The browser is the pinned Chrome for Testing headless shell (tools/fetch-chrome-headless.sh). Output goes to <result file> as the lines
// the app printed; the process exits 0 when the app's exit code is 0. No third-party packages are used.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';
import { tmpdir } from 'node:os';

const [root, browser, resultFile, areas] = process.argv.slice(2);
if (!root || !browser || !resultFile) {
  console.error('usage: serve-and-drive.mjs <wwwroot> <browser> <result file> [areas]');
  process.exit(2);
}
const timeoutMs = Number(process.env.BROWSER_SUITE_TIMEOUT_MS ?? 15 * 60 * 1000);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm', '.dat': 'application/octet-stream', '.pdb': 'application/octet-stream' };

let finish;
const done = new Promise((resolve) => { finish = resolve; });

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method === 'POST' && url.pathname === '/result') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(204).end();
    finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    return;
  }
  const path = normalize(url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname));
  if (path.includes('..')) { res.writeHead(400).end(); return; }
  try {
    const body = await readFile(join(root, path));
    res.writeHead(200, { 'content-type': types[extname(path)] ?? 'application/octet-stream', 'cache-control': 'no-store' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

const profile = await mkdtemp(join(process.env.TMPDIR ?? tmpdir(), 'browser-suite-'));
const page = `http://127.0.0.1:${port}/index.html${areas ? `?areas=${encodeURIComponent(areas)}` : ''}`;
const child = spawn(browser, [
  '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--disable-extensions',
  `--user-data-dir=${profile}`, page,
], { stdio: ['ignore', 'ignore', 'pipe'] });
let browserErr = '';
child.stderr.on('data', (d) => { browserErr += d; });
child.on('exit', (code) => finish({ exitCode: 98, failure: `the browser exited early (${code}): ${browserErr.slice(-2000)}`, lines: [] }));

const timer = setTimeout(() => finish({ exitCode: 97, failure: `no result after ${timeoutMs} ms`, lines: [] }), timeoutMs);
const result = await done;
clearTimeout(timer);
child.removeAllListeners('exit');
child.kill('SIGKILL');
server.close();
await rm(profile, { recursive: true, force: true });

await writeFile(resultFile, result.lines.join('\n') + '\n');
await writeFile(`${resultFile}.meta.json`, JSON.stringify({ userAgent: result.userAgent, exitCode: result.exitCode, failure: result.failure ?? null }, null, 2));
if (result.failure) console.error(result.failure);
console.log(`browser: ${result.userAgent ?? 'none'}\nexit code ${result.exitCode}, ${result.lines.length} lines`);
process.exit(result.exitCode === 0 ? 0 : 1);
