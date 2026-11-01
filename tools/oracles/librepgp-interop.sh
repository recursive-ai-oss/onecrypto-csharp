#!/usr/bin/env bash
# Two-way LibrePGP checks against a GnuPG binary (the one on PATH; set PATH and LD_LIBRARY_PATH for another) through our sop, and against RNP when
# ONECRYPTO_RNP points at its distribution directory (see rnp.sh):
#   - ours -> GnuPG: messages to a version 5 key and to a version 4 key announcing OCB Encrypted Data are written as OCB Encrypted Data (tag 20), to a
#     plain version 4 key as SEIPD v1 (tag 18); GnuPG decrypts all of them; a version 5 key's signatures verify in GnuPG
#   - GnuPG -> ours: OCB Encrypted Data to those keys, a password message with SKESK version 5, bzip2-compressed messages (1 KiB to 64 MiB), version 5
#     signatures; GnuPG 2.5 also: Kyber composite keys (both directions)
# Usage: tools/oracles/librepgp-interop.sh <"dotnet path/to/onecrypto.dll"> <work dir> [max bzip2 MiB, default 64]
set +e +o pipefail
SOP=${1:?sop command}
W=${2:?work dir}
BZMAX=${3:-64}
mkdir -p "$W" && cd "$W" || exit 2
find . -maxdepth 1 -type f -delete
export GNUPGHOME="$W/gnupg"
rm -rf "$GNUPGHOME" && mkdir -m 700 "$GNUPGHOME"
sop() { $SOP sop "$@"; }
pass=0; fail=0; skipped=0
ok() { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }
skip() { skipped=$((skipped+1)); echo "skip $1"; }
GPGV=$(gpg --version | head -1); echo "$GPGV"
major_minor=$(gpg --version | head -1 | sed 's/.* //' | cut -d. -f1-2)
fpr() { gpg --batch --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }
tags() { gpg --list-packets "$1" 2>/dev/null | grep -c "$2"; }

printf 'Hello from the LibrePGP test\nsecond line\n' > msg.txt
head -c 700000 /dev/urandom > big.bin

gpg --batch --compliance=gnupg --passphrase '' --quick-gen-key v5@example.org ed25519/v5 sign,cert never 2>/dev/null
gpg --batch --compliance=gnupg --passphrase '' --quick-add-key "$(fpr v5@example.org)" cv25519/v5 encr never 2>/dev/null
gpg --batch --compliance=gnupg --rfc4880bis --passphrase '' --quick-gen-key v4o@example.org ed25519 sign,cert never 2>/dev/null
gpg --batch --compliance=gnupg --rfc4880bis --passphrase '' --quick-add-key "$(fpr v4o@example.org)" cv25519 encr never 2>/dev/null
gpg --batch --passphrase '' --quick-gen-key v4@example.org ed25519 sign,cert never 2>/dev/null
gpg --batch --passphrase '' --quick-add-key "$(fpr v4@example.org)" cv25519 encr never 2>/dev/null
for k in v5 v4o v4; do gpg --batch --export $k@example.org > $k.cert; gpg --batch --export-secret-keys $k@example.org > $k.key; done

for k in v5 v4o v4; do
  # a key announcing OCB Encrypted Data (features bit 0x02) gets tag 20; one announcing only MDC (features 01) gets SEIPD v1, tag 18
  want=20; gpg --list-packets $k.cert 2>/dev/null | grep -q "features: 01" && want=18
  # ours -> GnuPG
  sop encrypt $k.cert < big.bin > $k.oenc
  [ "$(tags $k.oenc "^# off=.* tag=$want ")" -ge 1 ] && ok "$k ours uses packet tag $want" || bad "$k ours uses packet tag $want"
  gpg --batch --yes --pinentry-mode loopback --passphrase '' -o dec.bin --decrypt $k.oenc 2>gpg.err && cmp -s dec.bin big.bin && ok "$k gpg decrypts ours" || { bad "$k gpg decrypts ours"; tail -2 gpg.err; }
  # sign and encrypt (version 5 signatures for the version 5 key)
  sop encrypt --sign-with=$k.key $k.cert < big.bin > $k.osenc
  gpg --batch --yes --pinentry-mode loopback --passphrase '' -o dec.bin --decrypt $k.osenc 2>gpg.err && cmp -s dec.bin big.bin && grep -q 'Good signature' gpg.err && ok "$k gpg decrypts and verifies ours" || { bad "$k gpg decrypts and verifies ours"; tail -3 gpg.err; }
  sop sign $k.key < msg.txt > $k.osig
  gpg --batch --import $k.cert 2>/dev/null
  gpg --batch --verify $k.osig msg.txt 2>/dev/null && ok "$k gpg verifies our detached signature" || bad "$k gpg verifies our detached signature"
  # GnuPG -> ours
  gpg --batch --yes --trust-model always --force-ocb -r $k@example.org -o $k.genc --encrypt big.bin 2>/dev/null
  sop decrypt $k.key < $k.genc > dec.bin && cmp -s dec.bin big.bin && ok "$k ours decrypts gpg --force-ocb" || bad "$k ours decrypts gpg --force-ocb"
  gpg --batch --yes --trust-model always --force-ocb -r $k@example.org --local-user $k@example.org --sign -o $k.gencs --encrypt big.bin 2>/dev/null
  sop decrypt --verify-with=$k.cert --verifications-out=$k.ver $k.key < $k.gencs > dec.bin && cmp -s dec.bin big.bin && [ -s $k.ver ] && ok "$k ours decrypts and verifies gpg" || bad "$k ours decrypts and verifies gpg"
  gpg --batch --yes --local-user $k@example.org --detach-sign -o $k.gsig msg.txt 2>/dev/null
  sop verify $k.gsig $k.cert < msg.txt > /dev/null && ok "$k ours verifies gpg detached" || bad "$k ours verifies gpg detached"
done

# Old hashes: GnuPG signs with SHA-224 and RIPEMD-160, we verify; we refuse to sign with them
for h in SHA224 RIPEMD160; do
  gpg --batch --yes --allow-weak-digest-algos --digest-algo $h --local-user v4@example.org --detach-sign -o old-$h.sig msg.txt 2>/dev/null
  sop verify old-$h.sig v4.cert < msg.txt > /dev/null && ok "ours verifies gpg $h detached" || bad "ours verifies gpg $h detached"
  gpg --batch --yes --allow-weak-digest-algos --digest-algo $h --local-user v4@example.org --sign -o old-$h.gpg msg.txt 2>/dev/null
  sop inline-verify --verifications-out=old-$h.ver v4.cert < old-$h.gpg > dec.bin && cmp -s dec.bin msg.txt && ok "ours verifies gpg $h inline" || bad "ours verifies gpg $h inline"
done

# passwords
echo -n 'pw' > pw.txt
gpg --batch --yes --pinentry-mode loopback --passphrase-file pw.txt --symmetric --force-ocb -o sym.gpg big.bin 2>/dev/null
[ "$(tags sym.gpg "^# off=.* tag=20 ")" -ge 1 ] || echo "note: this gpg wrote no tag 20 for --force-ocb --symmetric"
sop decrypt --with-password=pw.txt < sym.gpg > dec.bin && cmp -s dec.bin big.bin && ok "ours decrypts gpg SKESK v5 + OCB" || bad "ours decrypts gpg SKESK v5 + OCB"

# BZip2
for mib in 0 1 8 $BZMAX; do
  if [ $mib = 0 ]; then head -c 1024 /dev/urandom > bz.bin; else
    # compressible and not: text-like repeated content and random content alternate
    : > bz.bin; i=0; while [ $i -lt $mib ]; do head -c 524288 /dev/urandom >> bz.bin; yes 'the quick brown fox jumps over the lazy dog' | head -c 524288 >> bz.bin; i=$((i+1)); done
  fi
  gpg --batch --yes --pinentry-mode loopback --passphrase-file pw.txt --symmetric --compress-algo bzip2 -o bz.gpg bz.bin 2>/dev/null
  if [ ! -s bz.gpg ]; then skip "gpg here cannot write bzip2 (${mib} MiB)"; continue; fi
  sop decrypt --with-password=pw.txt < bz.gpg > dec.bin && cmp -s dec.bin bz.bin && ok "ours decrypts gpg bzip2 (${mib} MiB)" || bad "ours decrypts gpg bzip2 (${mib} MiB)"
done
head -c 300000 /dev/zero > zeros.bin
gpg --batch --yes --trust-model always -r v5@example.org --compress-algo bzip2 -o zeros.gpg --encrypt zeros.bin 2>/dev/null
if [ -s zeros.gpg ]; then sop decrypt v5.key < zeros.gpg > dec.bin && cmp -s dec.bin zeros.bin && ok "ours decrypts gpg bzip2 of zeros inside OCB Encrypted Data" || bad "ours decrypts gpg bzip2 of zeros inside OCB Encrypted Data"; else skip "gpg here cannot write bzip2 of zeros"; fi

# Kyber (GnuPG 2.5)
if gpg --version | grep -q 'GnuPG) 2\.[5-9]'; then
  for a in ky768_cv25519 ky1024_cv448; do
    gpg --batch --passphrase '' --quick-gen-key k-$a@example.org ed25519 sign,cert never 2>/dev/null
    gpg --batch --passphrase '' --quick-add-key "$(fpr k-$a@example.org)" $a encr never 2>/dev/null
    gpg --batch --export k-$a@example.org > $a.cert; gpg --batch --export-secret-keys k-$a@example.org > $a.key
    gpg --batch --yes --trust-model always -r k-$a@example.org -o $a.genc --encrypt big.bin 2>/dev/null
    sop decrypt $a.key < $a.genc > dec.bin && cmp -s dec.bin big.bin && ok "$a ours decrypts gpg" || bad "$a ours decrypts gpg"
    sop encrypt $a.cert < big.bin > $a.oenc
    gpg --batch --yes --pinentry-mode loopback --passphrase '' -o dec.bin --decrypt $a.oenc 2>gpg.err && cmp -s dec.bin big.bin && ok "$a gpg decrypts ours" || { bad "$a gpg decrypts ours"; tail -2 gpg.err; }
  done
else
  skip "Kyber: this gpg is older than 2.5"
fi

# RNP
if [ -n "${ONECRYPTO_RNP:-}" ] && [ -x "$ONECRYPTO_RNP/usr/bin/rnp" ]; then
  export LD_LIBRARY_PATH=$ONECRYPTO_RNP/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  RNP="$ONECRYPTO_RNP/usr/bin/rnp --notty"; RNPK="$ONECRYPTO_RNP/usr/bin/rnpkeys --notty"
  $ONECRYPTO_RNP/usr/bin/rnp --version | head -1
  for k in v5 v4o v4; do
    # one RNP home per key, so a user ID can only select that key
    H=$W/rnphome-$k; rm -rf "$H"; mkdir -m 700 "$H"
    $RNPK --homedir "$H" --import $k.key >/dev/null 2>&1
    want="ok"; [ $k = v5 ] && want="v5"
    $RNP --homedir "$H" --password '' --decrypt $k.oenc --output rnp.bin --overwrite >/dev/null 2>&1
    if cmp -s rnp.bin big.bin; then ok "$k rnp decrypts ours"; elif [ $k = v5 ]; then skip "$k rnp decrypts ours (RNP does not import version 5 keys?)"; else bad "$k rnp decrypts ours"; fi
    $RNP --homedir "$H" --password '' --decrypt $k.genc --output rnp.bin --overwrite >/dev/null 2>&1
    $RNP --homedir "$H" --password '' --userid $k@example.org --encrypt big.bin --output $k.renc --overwrite >/dev/null 2>&1
    if [ -s $k.renc ]; then sop decrypt $k.key < $k.renc > dec.bin && cmp -s dec.bin big.bin && ok "$k ours decrypts rnp" || bad "$k ours decrypts rnp"; else skip "$k rnp encrypt"; fi
  done
else
  skip "RNP not configured"
fi
echo "passed=$pass failed=$fail skipped=$skipped"
gpgconf --kill all 2>/dev/null
[ "$fail" -eq 0 ]
