#!/usr/bin/env bash
# Two-way matrix between our sop and another sop implementation (sqop, gosop, the OpenPGP.js driver, rnp's sop ...).
# The other side generates the keys, so every cell checks interoperability of keys it wrote with messages we write and read.
# Usage: tools/oracles/sop-matrix.sh "<our sop command>" "<other sop command>" <work dir>
# A cell is ok, FAIL, or unsup when the other tool answers with an exit code that means "I do not do that"
# (13 unsupported algorithm, 37 unsupported option, 69 unsupported subcommand, 89 unsupported profile).
set -u
OURS=${1:?our sop}; OTHER=${2:?other sop}; W=${3:?work dir}
mkdir -p "$W" && cd "$W" || exit 2
o() { $OURS "$@"; }
x() { $OTHER "$@"; }
pass=0; fail=0; unsup=0
cell() { # name, command... ; the last command's status decides
  local name=$1; shift
  if "$@" >/dev/null 2>"$W/err.txt"; then pass=$((pass+1)); echo "ok    $name"
  else
    local rc=$?
    if grep -q 'not supported by this driver' "$W/err.txt"; then rc=37; fi
    case $rc in 13|37|69|89) unsup=$((unsup+1)); echo "unsup $name (exit $rc)";; *) fail=$((fail+1)); echo "FAIL  $name (exit $rc): $(head -c 200 "$W/err.txt" | tr '\n' ' ')";; esac
  fi
}
printf 'Hello, interop\nline two with trailing space \n\nend' > msg.txt
head -c 200000 /dev/urandom > big.bin
echo -n 'matrix password' > pw.txt

profiles=$(x list-profiles generate-key 2>/dev/null | cut -d: -f1)
[ -z "$profiles" ] && profiles=default
for prof in $profiles; do
  p=""; [ "$prof" != default ] && p="--profile=$prof"
  k=key-$prof; rm -f $k.key $k.cert
  x generate-key $p "Matrix <matrix@example.org>" > $k.key 2>gen.err || { echo "unsup generate-key $prof"; continue; }
  x extract-cert < $k.key > $k.cert
  echo "--- key profile: $prof"
  # detached
  for as in binary text; do
    cell "[$prof] other sign($as) -> ours verify" bash -c "$OTHER sign --as=$as $k.key < msg.txt > s1.sig && $OURS verify s1.sig $k.cert < msg.txt"
    cell "[$prof] ours sign($as) -> other verify" bash -c "$OURS sign --as=$as $k.key < msg.txt > s2.sig && $OTHER verify s2.sig $k.cert < msg.txt"
  done
  # inline
  for as in binary text clearsigned; do
    cell "[$prof] other inline-sign($as) -> ours inline-verify" bash -c "$OTHER inline-sign --as=$as $k.key < msg.txt > i1.asc && $OURS inline-verify $k.cert < i1.asc > /dev/null"
    cell "[$prof] ours inline-sign($as) -> other inline-verify" bash -c "$OURS inline-sign --as=$as $k.key < msg.txt > i2.asc && $OTHER inline-verify $k.cert < i2.asc > /dev/null"
  done
  # public-key encryption, with and without a signature, each of our encrypt profiles
  for eprof in rfc9580 rfc4880; do
    cell "[$prof] ours encrypt($eprof) -> other decrypt" bash -c "$OURS encrypt --profile=$eprof $k.cert < big.bin > e1.asc && $OTHER decrypt $k.key < e1.asc | cmp - big.bin"
    cell "[$prof] ours encrypt($eprof)+sign -> other decrypt+verify" bash -c "$OURS encrypt --profile=$eprof --sign-with=$k.key $k.cert < big.bin > e2.asc && $OTHER decrypt --verifications-out=v.out --verify-with=$k.cert $k.key < e2.asc | cmp - big.bin && test -s v.out; rc=\$?; rm -f v.out; exit \$rc"
  done
  cell "[$prof] other encrypt -> ours decrypt" bash -c "$OTHER encrypt $k.cert < big.bin > e3.asc && $OURS decrypt $k.key < e3.asc | cmp - big.bin"
  cell "[$prof] other encrypt+sign -> ours decrypt+verify" bash -c "$OTHER encrypt --sign-with=$k.key $k.cert < big.bin > e4.asc && $OURS decrypt --verifications-out=v2.out --verify-with=$k.cert $k.key < e4.asc | cmp - big.bin && test -s v2.out; rc=\$?; rm -f v2.out; exit \$rc"
  for eprof in $($OTHER list-profiles encrypt 2>/dev/null | cut -d: -f1); do
    cell "[$prof] other encrypt($eprof) -> ours decrypt" bash -c "$OTHER encrypt --profile=$eprof $k.cert < big.bin > e5.asc && $OURS decrypt $k.key < e5.asc | cmp - big.bin"
  done
  # session key hand-off
  cell "[$prof] ours decrypt --session-key-out -> other decrypt --with-session-key" bash -c "rm -f sk.txt; $OTHER encrypt $k.cert < big.bin > e6.asc && $OURS decrypt --session-key-out=sk.txt $k.key < e6.asc > /dev/null && $OTHER decrypt --with-session-key=sk.txt < e6.asc | cmp - big.bin"
done

# passwords
for eprof in rfc9580 rfc4880; do
  cell "ours encrypt --with-password($eprof) -> other decrypt" bash -c "$OURS encrypt --profile=$eprof --with-password=pw.txt < big.bin > p1.asc && $OTHER decrypt --with-password=pw.txt < p1.asc | cmp - big.bin"
done
for eprof in $($OTHER list-profiles encrypt 2>/dev/null | cut -d: -f1); do
  cell "other encrypt --with-password($eprof) -> ours decrypt" bash -c "$OTHER encrypt --profile=$eprof --with-password=pw.txt < big.bin > p2.asc && $OURS decrypt --with-password=pw.txt < p2.asc | cmp - big.bin"
done
cell "other encrypt --with-password -> ours decrypt" bash -c "$OTHER encrypt --with-password=pw.txt < big.bin > p3.asc && $OURS decrypt --with-password=pw.txt < p3.asc | cmp - big.bin"
echo "pass=$pass fail=$fail unsup=$unsup"
[ "$fail" -eq 0 ]
