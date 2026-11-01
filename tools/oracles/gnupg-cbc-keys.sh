#!/usr/bin/env bash
# Makes key files protected the way GnuPG 2.0 did (openpgp-s2k3-sha1-aes-cbc, a naked canonical S-expression), by running the gpg-protect-tool
# of the Debian 8 gnupg-agent package on unprotected keys taken from a GnuPG 2.4 home. Later GnuPG versions write
# openpgp-s2k3-ocb-aes, so this is the only way to get a real CBC file. The tool is only run, never read.
#
#   tools/oracles/gnupg-cbc-keys.sh <unprotected-private-keys-v1.d> <output-dir>
#
# Each output <name>.key is protected with the passphrase "onecrypto-test"; <name>.clear.key is the unprotected original.
set -euo pipefail
SRC=${1:?usage: gnupg-cbc-keys.sh <private-keys-v1.d of a GnuPG 2.4 home> <output-dir>}
OUT=${2:?}
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
D=$ORACLES/gnupg-agent-2.0.26
mkdir -p "$D"
fetch_pinned https://archive.debian.org/debian/pool/main/g/gnupg2/gnupg-agent_2.0.26-6+deb8u2_amd64.deb e015a603e521440d300cd2ac71fd57bf58e9397ce5daa91334c1c591710f125b "$D/gnupg-agent.deb"
fetch_pinned https://archive.debian.org/debian/pool/main/liba/libassuan/libassuan0_2.1.2-2_amd64.deb 700236b1cab390839ab49d6dea0e5391e479141e1f0fcafeb1f7472907d9c232 "$D/libassuan0.deb"
[ -x "$D/root/usr/lib/gnupg2/gpg-protect-tool" ] || { dpkg -x "$D/gnupg-agent.deb" "$D/root"; dpkg -x "$D/libassuan0.deb" "$D/root"; }
TOOL=(env LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}" "$D/root/usr/lib/gnupg2/gpg-protect-tool")
mkdir -p "$OUT"
python3 - "$SRC" "$OUT" "${TOOL[@]}" <<'PY'
import os, re, subprocess, sys
src, out, tool = sys.argv[1], sys.argv[2], sys.argv[3:]

def advanced_to_canonical(s):
    pos = 0
    def skip():
        nonlocal pos
        while s[pos].isspace(): pos += 1
    def atom():
        nonlocal pos
        c = s[pos]
        if c == '#':
            e = s.index('#', pos + 1); h = re.sub(r'\s', '', s[pos + 1:e]); pos = e + 1; return bytes.fromhex(h)
        if c == '"':
            e = pos + 1; o = ''
            while s[e] != '"':
                if s[e] == '\\': e += 1
                o += s[e]; e += 1
            pos = e + 1; return o.encode()
        e = pos
        while not s[e].isspace() and s[e] not in '()': e += 1
        r = s[pos:e]; pos = e; return r.encode()
    def lst():
        nonlocal pos
        pos += 1; o = b'('
        while True:
            skip()
            if s[pos] == ')': pos += 1; return o + b')'
            if s[pos] == '(': o += lst()
            else:
                a = atom(); o += str(len(a)).encode() + b':' + a
    skip(); return lst()

wanted = {'rsa': r'private-key \(rsa', 'nistp256': r'curve "NIST P-256"', 'nistp384': r'curve "NIST P-384"', 'nistp521': r'curve "NIST P-521"', 'brainpoolp256r1': r'curve brainpoolP256r1'}
done = set()
for name in sorted(os.listdir(src)):
    text = open(os.path.join(src, name), 'rb').read().decode('latin1')
    if 'protected-private-key' in text or 'Key: (private-key' not in text and not text.startswith('(private-key'): continue
    i = text.index('Key: ') + 5 if text.startswith('Created') or text.startswith('Key:') else 0
    key = re.sub(r'\n ', '', text[i:]).strip()
    for label, pat in wanted.items():
        if label in done: continue
        if re.search(pat, text.replace('\n ', '')):
            r = subprocess.run(tool + ['-p', '-P', 'onecrypto-test'], input=advanced_to_canonical(key), capture_output=True)
            if r.returncode != 0 or not r.stdout.startswith(b'(21:protected-private-key'):
                print('skip', label, r.stderr.decode()[:80], file=sys.stderr); continue
            open(os.path.join(out, label + '.key'), 'wb').write(r.stdout)
            open(os.path.join(out, label + '.clear.key'), 'wb').write(text.encode('latin1'))
            done.add(label)
print('wrote', sorted(done))
PY
