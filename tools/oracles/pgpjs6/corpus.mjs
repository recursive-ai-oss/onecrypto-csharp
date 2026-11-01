// Writes an OpenPGP corpus with OpenPGP.js 6 through its documented public API (generateKey, encrypt, sign).
// Throwaway keys only.   node corpus.mjs <output-dir> <label>
import * as openpgp from 'openpgp';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

const [out, label = 'openpgpjs'] = process.argv.slice(2);
const dest = `${out}/${label}`;
rmSync(dest, { recursive: true, force: true });
for (const d of ['keys', 'certs', 'sigs', 'messages']) mkdirSync(`${dest}/${d}`, { recursive: true });
const put = (kind, name, data) => writeFileSync(`${dest}/${kind}/${name}`, data);
const text = 'throwaway message for the corpus\n';
const pass = 'throwaway-passphrase';
const variants = [
  ['v6-curve25519', { type: 'curve25519', config: { v6Keys: true } }],
  ['v6-curve448', { type: 'curve448', config: { v6Keys: true } }],
  ['v6-rsa3072', { type: 'rsa', rsaBits: 3072, config: { v6Keys: true } }],
  ['v4-curve25519', { type: 'ecc', curve: 'curve25519Legacy', config: { v6Keys: false } }],
  ['v4-p256', { type: 'ecc', curve: 'nistP256', config: { v6Keys: false } }],
  ['v4-p384', { type: 'ecc', curve: 'nistP384', config: { v6Keys: false } }],
  ['v4-brainpool256', { type: 'ecc', curve: 'brainpoolP256r1', config: { v6Keys: false } }],
  ['v4-rsa2048', { type: 'rsa', rsaBits: 2048, config: { v6Keys: false } }],
];
let failures = 0;
for (const [name, opts] of variants) {
  try {
    const userIDs = [{ name: `Corpus ${name}`, email: `${name}@corpus.invalid` }];
    for (const format of ['binary', 'armored']) {
      const ext = format === 'binary' ? 'pgp' : 'asc';
      const { privateKey, publicKey } = await openpgp.generateKey({ ...opts, userIDs, format });
      put('keys', `${name}.${ext}`, privateKey);
      put('certs', `${name}.${ext}`, publicKey);
    }
    const priv = await openpgp.readPrivateKey({ armoredKey: (await openpgp.generateKey({ ...opts, userIDs, format: 'armored' })).privateKey });
    const pub = priv.toPublic();
    // password-protected secret key
    const locked = await openpgp.encryptKey({ privateKey: priv, passphrase: pass });
    put('keys', `${name}-locked.asc`, locked.armor());
    for (const [suffix, config] of [['seipd1', { aeadProtect: false }], ['seipd2', { aeadProtect: true }]]) {
      for (const format of ['binary', 'armored']) {
        const ext = format === 'binary' ? 'pgp' : 'asc';
        const enc = await openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: pub, format, config });
        put('messages', `${name}-enc-${suffix}.${ext}`, enc);
        const encs = await openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: pub, signingKeys: priv, format, config });
        put('messages', `${name}-encsign-${suffix}.${ext}`, encs);
      }
    }
    put('messages', `${name}-pw.pgp`, await openpgp.encrypt({ message: await openpgp.createMessage({ text }), passwords: [pass], format: 'binary', config: { aeadProtect: true } }));
    put('messages', `${name}-pw-seipd1.pgp`, await openpgp.encrypt({ message: await openpgp.createMessage({ text }), passwords: [pass], format: 'binary', config: { aeadProtect: false } }));
    put('sigs', `${name}-detached.pgp`, await openpgp.sign({ message: await openpgp.createMessage({ text }), signingKeys: priv, detached: true, format: 'binary' }));
    put('sigs', `${name}-detached.asc`, await openpgp.sign({ message: await openpgp.createMessage({ text }), signingKeys: priv, detached: true, format: 'armored' }));
    put('messages', `${name}-inline.pgp`, await openpgp.sign({ message: await openpgp.createMessage({ text }), signingKeys: priv, format: 'binary' }));
    put('messages', `${name}-clear.asc`, await openpgp.sign({ message: await openpgp.createCleartextMessage({ text }), signingKeys: priv }));
    // fingerprints as OpenPGP.js reports them, one line per key packet, primary first
    const lines = [priv, ...priv.subkeys].map((k) => `fpr:${k.getFingerprint().toUpperCase()}`);
    put('keys', `${name}.fpr`, lines.join('\n') + '\n');
    put('certs', `${name}.fpr`, lines.join('\n') + '\n');
  } catch (e) {
    failures++;
    console.error(`[${label}] ${name} failed: ${String(e.message).slice(0, 160)}`);
  }
}
console.error(`[${label}] openpgp ${openpgp.config ? 'ok' : ''}, ${variants.length - failures}/${variants.length} variants`);
