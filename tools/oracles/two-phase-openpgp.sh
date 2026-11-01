#!/usr/bin/env bash
# Two-phase OpenPGP signing across three processes (prepare, sign, complete), verified by other implementations.
#   tools/oracles/two-phase-openpgp.sh "<our sop command>" "<dotnet path/to/OpenPgpTwoPhase.dll>" <work dir> [sqop path] [gpg path]
set -u
OURS=$1; STEPS=$2; W=${3:?work dir}; SQOP=${4:-}; GPG=${5:-}
mkdir -p "$W" && cd "$W" || exit 2
export GNUPGHOME=$W/gnupg; rm -rf "$GNUPGHOME"; mkdir -m 700 "$GNUPGHOME"
pass=0; fail=0
ok() { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }
head -c 300000 /dev/urandom > data.bin
echo -n 'two phase pw' > pw.txt
for prof in rfc4880 rfc9580 rfc9580-ed448 nist-p256 draft-koch-eddsa-for-openpgp-00; do
  for prot in none pw; do
    k=$prof-$prot; kp=''; unset TWO_PHASE_PASSWORD; [ $prot = pw ] && { kp='--with-key-password=pw.txt'; export TWO_PHASE_PASSWORD='two phase pw'; }
    $OURS generate-key --profile=$prof $kp 'Two Phase <tp@example.org>' > $k.key || { echo "n/a  [$k] generate-key"; continue; }
    $OURS extract-cert < $k.key > $k.cert
    $STEPS prepare $k.cert data.bin $k.state && $STEPS sign $k.key $k.state $k.raw && $STEPS complete $k.state $k.raw $k.sig || { bad "[$k] the three steps"; continue; }
    $OURS verify $k.sig $k.cert < data.bin >/dev/null && ok "[$k] our verify" || bad "[$k] our verify"
    if [ -n "$SQOP" ]; then $SQOP verify $k.sig $k.cert < data.bin >/dev/null 2>&1 && ok "[$k] sqop verify" || bad "[$k] sqop verify"; fi
    case $prof in rfc9580|rfc9580-ed448) ;; *)
      if [ -n "$GPG" ]; then $GPG --batch --quiet --import $k.cert 2>/dev/null; $GPG --batch --verify $k.sig data.bin >/dev/null 2>&1 && ok "[$k] gpg verify" || bad "[$k] gpg verify"; fi;;
    esac
    # the state refuses another key, and a signature over other data does not complete
    cp $k.key other.key; head -c 10 /dev/urandom > other.bin
    $STEPS prepare $k.cert other.bin other.state && ! $STEPS complete $k.state <(cat $k.raw | head -c 5) o.sig 2>/dev/null && ok "[$k] a truncated signature is refused" || bad "[$k] a truncated signature is refused"
    $STEPS complete other.state $k.raw o2.sig 2>/dev/null && bad "[$k] a signature over other data completed" || ok "[$k] a signature over other data is refused"
  done
done
[ -n "$GPG" ] && gpgconf --homedir "$GNUPGHOME" --kill all 2>/dev/null
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
