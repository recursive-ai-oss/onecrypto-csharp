// Runs the suite in the page and posts every output line to the local server that served it (see serve-and-drive.mjs).
import { dotnet } from './_framework/dotnet.js';

const lines = [];
async function post(extra) {
  await fetch('/result', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userAgent: navigator.userAgent, ...extra, lines }),
  });
}

window.addEventListener('error', (e) => lines.push(`PAGE-ERROR\t${e.message}`));
try {
  const query = new URLSearchParams(location.search);
  const args = query.has('areas') ? [query.get('areas')] : [];
  const { runMain } = await dotnet
    .withModuleConfig({ out: (l) => lines.push(l), err: (l) => lines.push(`STDERR\t${l}`) })
    .withApplicationArguments(...args)
    .create();
  const exitCode = await runMain();
  await post({ exitCode });
} catch (e) {
  await post({ exitCode: 99, failure: String(e && e.stack ? e.stack : e) });
}
