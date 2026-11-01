// A small Stateless OpenPGP command line over OpenPGP.js 6, written against its documented public API, so that the OpenPGP.js
// release can take part in the sop interop matrix. It supports only what the matrix needs: generate-key, extract-cert, sign,
// verify, inline-sign, inline-verify, encrypt and decrypt, buffered in memory. Anything else exits 69 (unsupported).
//   node sop.mjs <subcommand> [options] [--] [files...]     (run from the openpgp install directory, or set OPENPGP_JS_DIR)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const dir = process.env.OPENPGP_JS_DIR ?? process.cwd();
const openpgp = await import(pathToFileURL(`${dir}/node_modules/openpgp/dist/node/openpgp.min.mjs`).href);

const [sub, ...rest] = process.argv.slice(2);
const opts = {}; const pos = [];
for (const a of rest) {
  if (a.startsWith('--') && a.length > 2) {
    const i = a.indexOf('=');
    const k = i < 0 ? a : a.slice(0, i); const v = i < 0 ? true : a.slice(i + 1);
    if (['--with-password', '--sign-with', '--verify-with', '--with-key-password'].includes(k)) (opts[k] ??= []).push(v); else opts[k] = v;
  } else pos.push(a);
}
const fail = (code, msg) => { process.stderr.write(`sop.mjs: ${msg}\n`); process.exit(code); };
const stdin = () => new Uint8Array(readFileSync(0));
const out = (b) => process.stdout.write(typeof b === 'string' ? b : Buffer.from(b));
const readFileArg = (p) => new Uint8Array(readFileSync(p));
const isArmor = (b) => b.length > 0 && (b[0] & 0x80) === 0;
const text = (b) => new TextDecoder().decode(b);
const armorOn = !opts['--no-armor'];
const secretKeys = async (files, passwords = []) => {
  const keys = [];
  for (const f of files) {
    const b = readFileArg(f);
    let k = isArmor(b) ? await openpgp.readPrivateKey({ armoredKey: text(b) }) : await openpgp.readPrivateKey({ binaryKey: b });
    if (!k.isDecrypted()) {
      let done = false;
      for (const p of passwords) { try { k = await openpgp.decryptKey({ privateKey: k, passphrase: text(readFileArg(p)).trimEnd() }); done = true; break; } catch {} }
      if (!done) fail(67, 'key is protected');
    }
    keys.push(k);
  }
  return keys;
};
const publicKeys = async (files) => {
  const keys = [];
  for (const f of files) {
    const b = readFileArg(f);
    keys.push(...(isArmor(b) ? await openpgp.readKeys({ armoredKeys: text(b) }) : await openpgp.readKeys({ binaryKeys: b })));
  }
  return keys;
};
const passwords = (list) => (list ?? []).map((p) => text(readFileArg(p)).trimEnd());
const verificationLines = async (sigs, mode) => {
  const lines = [];
  for (const s of sigs) {
    try {
      await s.verified;
      const sig = await s.signature;
      const created = sig.packets[0].created.toISOString().replace(/\.\d+Z$/, 'Z');
      const fp = s.keyID.toHex().toUpperCase();
      lines.push(`${created} ${fp} ${fp} mode:${mode}`);
    } catch { /* an invalid signature is not listed */ }
  }
  return lines;
};

process.on('uncaughtException', (e) => fail(1, String(e && e.message ? e.message : e)));
process.on('unhandledRejection', (e) => fail(1, String(e && e.message ? e.message : e)));

switch (sub) {
  case 'generate-key': {
    const profile = opts['--profile'];
    if (profile && profile !== 'default') fail(89, 'unknown profile');
    const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: pos.map((u) => ({ name: u })), format: 'binary' });
    const key = await openpgp.readPrivateKey({ binaryKey: privateKey });
    out(armorOn ? key.armor() : key.write());
    break;
  }
  case 'extract-cert': {
    const b = stdin();
    const k = isArmor(b) ? await openpgp.readPrivateKey({ armoredKey: text(b) }) : await openpgp.readPrivateKey({ binaryKey: b });
    const pub = k.toPublic();
    out(armorOn ? pub.armor() : pub.write());
    break;
  }
  case 'list-profiles':
    if (pos[0] === 'generate-key') out('default: OpenPGP.js default (v6 keys)\n'); else if (pos[0] === 'encrypt') out('default: OpenPGP.js default\n'); else fail(89, 'no profiles');
    break;
  case 'sign': {
    const keys = await secretKeys(pos, opts['--with-key-password']);
    const message = await openpgp.createMessage({ binary: stdin() });
    const sig = await openpgp.sign({ message, signingKeys: keys, detached: true, format: armorOn ? 'armored' : 'binary' });
    out(sig);
    break;
  }
  case 'verify': {
    const [sigFile, ...certs] = pos;
    const sb = readFileArg(sigFile);
    const signature = isArmor(sb) ? await openpgp.readSignature({ armoredSignature: text(sb) }) : await openpgp.readSignature({ binarySignature: sb });
    const message = await openpgp.createMessage({ binary: stdin() });
    const res = await openpgp.verify({ message, signature, verificationKeys: await publicKeys(certs), format: 'binary' });
    const lines = await verificationLines(res.signatures, 'binary');
    if (!lines.length) fail(3, 'no valid signature');
    out(lines.join('\n') + '\n');
    break;
  }
  case 'inline-sign': {
    const keys = await secretKeys(pos, opts['--with-key-password']);
    const as = opts['--as'] ?? 'binary';
    const data = stdin();
    if (as === 'clearsigned') {
      const message = await openpgp.createCleartextMessage({ text: text(data) });
      out(await openpgp.sign({ message, signingKeys: keys, format: 'armored' }));
    } else {
      const message = await openpgp.createMessage({ binary: data });
      out(await openpgp.sign({ message, signingKeys: keys, format: armorOn ? 'armored' : 'binary' }));
    }
    break;
  }
  case 'inline-verify': {
    const b = stdin();
    const certs = await publicKeys(pos);
    let res;
    if (isArmor(b) && text(b).trimStart().startsWith('-----BEGIN PGP SIGNED MESSAGE-----')) {
      res = await openpgp.verify({ message: await openpgp.readCleartextMessage({ cleartextMessage: text(b) }), verificationKeys: certs });
    } else {
      const message = isArmor(b) ? await openpgp.readMessage({ armoredMessage: text(b) }) : await openpgp.readMessage({ binaryMessage: b });
      res = await openpgp.verify({ message, verificationKeys: certs, format: 'binary' });
    }
    const lines = await verificationLines(res.signatures, 'binary');
    if (!lines.length) fail(3, 'no valid signature');
    out(res.data);
    break;
  }
  case 'encrypt': {
    if (opts['--profile'] && opts['--profile'] !== 'default') fail(89, 'unknown profile');
    if (opts['--session-key-out']) fail(37, 'session keys are not supported by this driver');
    const certs = await publicKeys(pos);
    const signingKeys = await secretKeys(opts['--sign-with'] ?? [], opts['--with-key-password']);
    const message = await openpgp.createMessage({ binary: stdin() });
    const pw = passwords(opts['--with-password']);
    out(await openpgp.encrypt({ message, ...(certs.length ? { encryptionKeys: certs } : {}), ...(pw.length ? { passwords: pw } : {}), signingKeys, format: armorOn ? 'armored' : 'binary' }));
    break;
  }
  case 'decrypt': {
    if (opts['--session-key-out'] || opts['--with-session-key']) fail(37, 'session keys are not supported by this driver');
    const b = stdin();
    const message = isArmor(b) ? await openpgp.readMessage({ armoredMessage: text(b) }) : await openpgp.readMessage({ binaryMessage: b });
    const keys = await secretKeys(pos, opts['--with-key-password']);
    const verifyWith = await publicKeys(opts['--verify-with'] ?? []);
    let res;
    try {
      const pw = passwords(opts['--with-password']);
      res = await openpgp.decrypt({ message, ...(keys.length ? { decryptionKeys: keys } : {}), ...(pw.length ? { passwords: pw } : {}), verificationKeys: verifyWith, format: 'binary' });
    } catch (e) { fail(29, `cannot decrypt: ${e.message}`); }
    const vout = opts['--verifications-out'];
    if (vout) {
      if (existsSync(vout)) fail(59, 'output exists');
      writeFileSync(vout, (await verificationLines(res.signatures, 'binary')).join('\n') + '\n');
    }
    out(res.data);
    break;
  }
  case 'version':
    out(`sop.mjs over openpgp ${openpgp.config ? '6' : ''}\n`);
    break;
  default:
    fail(69, `unsupported subcommand ${sub}`);
}
