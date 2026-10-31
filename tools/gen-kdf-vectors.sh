#!/usr/bin/env bash
# Writes testdata/kdf/openssl-vectors.txt: Argon2 and scrypt outputs from `openssl kdf`, used as an independent check of
# parameter sets the RFCs do not cover (odd memory sizes, many lanes, long tags, the multi-threaded path). The openssl
# version is recorded in the file's first line. Inputs are fixed so the file is reproducible.
#
#   Argon2 line:  argon2d|argon2i|argon2id  password-hex salt-hex m t p secret-hex ad-hex tag-hex
#   scrypt line:  scrypt password-hex salt-hex N r p dklen tag-hex
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OPENSSL=${OPENSSL:-openssl}
out=testdata/kdf/openssl-vectors.txt
hex() { printf %s "$1" | xxd -p | tr -d '\n'; }
{
  echo "# $($OPENSSL version)"
  # type password salt m t p taglen secret ad
  while read -r type pw salt m t p taglen secret ad; do
    [ -z "$type" ] && continue
    opts=(-kdfopt "hexpass:$(hex "$pw")" -kdfopt "hexsalt:$(hex "$salt")" -kdfopt "iter:$t" -kdfopt "memcost:$m" -kdfopt "lanes:$p" -kdfopt threads:1)
    [ "$secret" != - ] && opts+=(-kdfopt "hexsecret:$(hex "$secret")")
    [ "$ad" != - ] && opts+=(-kdfopt "hexad:$(hex "$ad")")
    tag=$($OPENSSL kdf -keylen "$taglen" "${opts[@]}" -binary "${type^^}" | xxd -p | tr -d '\n')
    echo "$type $(hex "$pw") $(hex "$salt") $m $t $p $([ "$secret" = - ] && echo - || hex "$secret") $([ "$ad" = - ] && echo - || hex "$ad") $tag"
  done <<'CASES'
argon2id password saltsalt 8 1 1 32 - -
argon2id password saltsalt 100 2 3 32 - -
argon2d  password saltsalt 64 3 8 16 - -
argon2i  password saltsalt 64 3 8 16 sekret adata
argon2id x 0123456789abcdef 8 1 1 4 - -
argon2id pw 0123456789abcdef 256 2 2 65 - -
argon2i  pw 0123456789abcdef 512 1 4 100 - -
argon2d  pw 0123456789abcdef 1024 4 2 200 pepper header
argon2id pw 0123456789abcdef 4100 2 2 33 - -
argon2id long-password-0123456789-long-password-0123456789 0123456789abcdef0123456789abcdef 8192 2 4 32 s a
argon2i  pw 0123456789abcdef 8192 2 4 64 - -
argon2d  pw 0123456789abcdef 8192 3 4 64 - -
argon2id pw 0123456789abcdef 16384 1 8 1024 - -
argon2id pw 0123456789abcdef 65536 3 4 32 - -
CASES
  while read -r pw salt n r p dk; do
    [ -z "$pw" ] && continue
    [ "$pw" = EMPTY ] && pw=""; [ "$salt" = EMPTY ] && salt=""
    tag=$($OPENSSL kdf -keylen "$dk" -kdfopt "hexpass:$(hex "$pw")" -kdfopt "hexsalt:$(hex "$salt")" -kdfopt "n:$n" -kdfopt "r:$r" -kdfopt "p:$p" -kdfopt maxmem_bytes:1073741824 -binary SCRYPT | xxd -p | tr -d '\n')
    echo "scrypt $(hex "$pw") $(hex "$salt") $n $r $p $dk $tag"
  done <<'CASES'
EMPTY EMPTY 2 1 1 32
EMPTY salt 1024 1 2 16
password NaCl 4096 3 2 100
pw salt 32 16 1 1
pw salt 32768 1 1 64
pw salt 128 8 5 200
CASES
} > "$out"
wc -l "$out"
