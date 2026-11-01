#!/usr/bin/env bash
# Streams 1 GiB through our sop (password encrypt/decrypt with SEIPD v2, inline sign/verify) and prints each step's peak resident set,
# to show that memory stays flat whatever the size.
# Usage: tools/oracles/stream-1g.sh <path to onecrypto.dll> <work dir (large, not RAM-backed)> [size in MiB, default 1024]
set -eu
DLL=${1:?onecrypto.dll}; W=${2:?work dir}; MIB=${3:-1024}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$W"; cd "$W"
head -c $((MIB * 1048576)) /dev/urandom > in.bin
printf 'stream test' > pw
sop() { /usr/bin/time -f "  peak %M KiB, %e s" dotnet "$DLL" sop "$@"; }
echo "encrypt (password, SEIPD v2)"; sop encrypt --with-password=pw < in.bin > enc.pgp
echo "decrypt"; sop decrypt --with-password=pw < enc.pgp | cmp - in.bin && echo "  round trip identical"
echo "inline-sign"; sop inline-sign "$root/testdata/openpgp/keys/test-ed25519.sec.asc" --no-armor < in.bin > signed.pgp
echo "inline-verify"; sop inline-verify "$root/testdata/openpgp/keys/test-ed25519.pub.asc" < signed.pgp | cmp - in.bin && echo "  round trip identical"
rm -f in.bin enc.pgp signed.pgp pw
