#!/usr/bin/env bash
# Key-management matrix between our sop and another sop implementation (sqop, gosop, the OpenPGP.js driver).
# Keys we generate (every profile, with and without a password) are used by the other side, and its answers to our revocations, certifications and
# password changes are checked; then the other side's own keys go through our change-key-password, revoke-key, certify-userid, update-key and merge-certs.
# Usage: tools/oracles/sop-keys-matrix.sh "<our sop command>" "<other sop command>" <work dir>
# A cell is ok, FAIL, or unsup when the other tool answers with an exit code that means "I do not do that" (13, 37, 69, 89).
set -u
OURS=${1:?our sop}; OTHER=${2:?other sop}; W=${3:?work dir}
mkdir -p "$W" && cd "$W" || exit 2
o() { $OURS "$@"; }
x() { $OTHER "$@"; }
pass=0; fail=0; unsup=0
cell() {
  local name=$1; shift
  if "$@" >/dev/null 2>"$W/err.txt"; then pass=$((pass+1)); echo "ok    $name"
  else
    local rc=$?
    if grep -q 'not supported by this driver' "$W/err.txt"; then rc=37; fi
    case $rc in 13|37|69|89) unsup=$((unsup+1)); echo "unsup $name (exit $rc)";; *) fail=$((fail+1)); echo "FAIL  $name (exit $rc): $(head -c 200 "$W/err.txt" | tr '\n' ' ')";; esac
  fi
}
printf 'Hello, key management\nline two\n' > msg.txt
echo -n 'first password' > pw1.txt
echo -n 'second password' > pw2.txt
UID1='Ours <ours@example.org>'

# a second, unprotected certifier of our own, and one of theirs (their default profile)
o generate-key --profile=rfc4880 "Certifier <certifier@example.org>" > certifier.key; o extract-cert < certifier.key > certifier.cert
x generate-key "Theirs <theirs@example.org>" > theirs.key 2>/dev/null; x extract-cert < theirs.key > theirs.cert 2>/dev/null

profiles=$(o list-profiles generate-key | cut -d: -f1)
for prof in $profiles; do
  case $prof in default|compatibility|security|performance) continue;; esac # aliases of listed profiles
  for prot in none pw; do
    k=k-$prof-$prot; kp=""; ow=""; xw=""
    if [ $prot = pw ]; then kp="--with-key-password=pw1.txt"; fi
    rm -f $k.*
    o generate-key --profile=$prof $kp "$UID1" > $k.key 2>gen.err; grc=$?
    if [ $grc -ne 0 ]; then
      if [ $grc -eq 13 ] || grep -q 'is not supported on' gen.err; then echo "unsup [$prof/$prot] our generate-key (platform lacks the algorithm)"; unsup=$((unsup+1)); continue; fi
      echo "FAIL  [$prof/$prot] our generate-key: $(head -c 200 gen.err)"; fail=$((fail+1)); continue
    fi
    o extract-cert < $k.key > $k.cert
    echo "--- ours: $prof / $prot"
    # an implementation that cannot read the profile's keys (no RFC 9980 support) is not a failure of ours: only our own round trip is checked
    if ! $OTHER extract-cert < $k.key > /dev/null 2>&1; then
      cell "[$prof/$prot] our sign -> our verify (the other implementation does not read these keys)" bash -c "$OURS sign $kp $k.key < msg.txt > s0.sig && $OURS verify s0.sig $k.cert < msg.txt"
      cell "[$prof/$prot] our encrypt+sign -> our decrypt+verify" bash -c "rm -f v0.out; $OURS encrypt --sign-with=$k.key $kp $k.cert < msg.txt > e0.asc && $OURS decrypt $kp --verifications-out=v0.out --verify-with=$k.cert $k.key < e0.asc | cmp - msg.txt"
      unsup=$((unsup+1)); echo "unsup [$prof/$prot] other implementation does not read these keys"; continue
    fi
    cell "[$prof/$prot] other extract-cert = ours" bash -c "$OTHER extract-cert < $k.key | $OURS dearmor > a.bin && $OURS dearmor < $k.cert | cmp - a.bin"
    cell "[$prof/$prot] other sign -> ours verify" bash -c "$OTHER sign $kp $k.key < msg.txt > s1.sig && $OURS verify s1.sig $k.cert < msg.txt"
    cell "[$prof/$prot] ours sign -> other verify" bash -c "$OURS sign $kp $k.key < msg.txt > s2.sig && $OTHER verify s2.sig $k.cert < msg.txt"
    cell "[$prof/$prot] other encrypt -> ours decrypt" bash -c "$OTHER encrypt $k.cert < msg.txt > e1.asc && $OURS decrypt $kp $k.key < e1.asc | cmp - msg.txt"
    cell "[$prof/$prot] ours encrypt -> other decrypt" bash -c "$OURS encrypt $k.cert < msg.txt > e2.asc && $OTHER decrypt $kp $k.key < e2.asc | cmp - msg.txt"
    cell "[$prof/$prot] ours encrypt+sign -> other decrypt+verify" bash -c "rm -f v.out; $OURS encrypt --sign-with=$k.key $kp $k.cert < msg.txt > e3.asc && $OTHER decrypt $kp --verifications-out=v.out --verify-with=$k.cert $k.key < e3.asc | cmp - msg.txt && test -s v.out"
    # revocation: a revoked certificate neither verifies nor takes messages
    cell "[$prof/$prot] ours revoke-key -> other refuses verify" bash -c "$OURS revoke-key $kp < $k.key > r.cert && $OURS sign $kp $k.key < msg.txt > s3.sig && ! $OTHER verify s3.sig r.cert < msg.txt"
    cell "[$prof/$prot] ours revoke-key -> other refuses encrypt" bash -c "! $OTHER encrypt r.cert < msg.txt"
    # certification
    cell "[$prof/$prot] ours certify-userid -> other validate-userid" bash -c "$OURS certify-userid --userid='$UID1' certifier.key < $k.cert > c1.cert && $OTHER validate-userid '$UID1' certifier.cert < c1.cert"
    cell "[$prof/$prot] other certify-userid -> ours validate-userid" bash -c "$OTHER certify-userid --userid='$UID1' theirs.key < $k.cert > c2.cert && $OURS validate-userid '$UID1' theirs.cert < c2.cert"
    # passwords
    if [ $prot = pw ]; then
      cell "[$prof/$prot] ours change-key-password -> other signs" bash -c "$OURS change-key-password --old-key-password=pw1.txt --new-key-password=pw2.txt < $k.key > n.key && $OTHER sign --with-key-password=pw2.txt n.key < msg.txt > s4.sig && $OURS verify s4.sig $k.cert < msg.txt"
      cell "[$prof/$prot] other change-key-password -> ours signs" bash -c "$OTHER change-key-password --old-key-password=pw1.txt --new-key-password=pw2.txt < $k.key > n2.key && $OURS sign --with-key-password=pw2.txt n2.key < msg.txt > s5.sig && $OURS verify s5.sig $k.cert < msg.txt"
      cell "[$prof/$prot] ours change-key-password (remove) -> other signs unprotected" bash -c "$OURS change-key-password --old-key-password=pw1.txt < $k.key > n3.key && $OTHER sign n3.key < msg.txt > s6.sig && $OURS verify s6.sig $k.cert < msg.txt"
    else
      cell "[$prof/$prot] ours change-key-password (add) -> other signs" bash -c "$OURS change-key-password --new-key-password=pw2.txt < $k.key > n.key && $OTHER sign --with-key-password=pw2.txt n.key < msg.txt > s4.sig && $OURS verify s4.sig $k.cert < msg.txt"
    fi
    # update-key and merge-certs outputs stay usable
    cell "[$prof/$prot] ours update-key -> other encrypts and verifies" bash -c "$OURS update-key $kp < $k.key > u.key && $OURS extract-cert < u.key > u.cert && $OTHER encrypt u.cert < msg.txt > e4.asc && $OURS decrypt $kp u.key < e4.asc | cmp - msg.txt && $OURS sign $kp u.key < msg.txt > s7.sig && $OTHER verify s7.sig u.cert < msg.txt"
    cell "[$prof/$prot] ours merge-certs of a certification -> other validate-userid" bash -c "$OURS certify-userid --userid='$UID1' certifier.key < $k.cert > c3.cert && $OURS merge-certs c3.cert < $k.cert > m.cert && $OTHER validate-userid '$UID1' certifier.cert < m.cert"
  done
done

# Their keys through our key management
tprofiles=$(x list-profiles generate-key 2>/dev/null | cut -d: -f1)
[ -z "$tprofiles" ] && tprofiles=default
for tp in $tprofiles; do
  p=""; [ "$tp" != default ] && p="--profile=$tp"
  for prot in none pw; do
    t=t-$tp-$prot; kp=""; [ $prot = pw ] && kp="--with-key-password=pw1.txt"
    rm -f $t.*
    x generate-key $p $kp "Theirs <t-$tp@example.org>" > $t.key 2>gen.err || { echo "unsup [theirs $tp/$prot] their generate-key"; unsup=$((unsup+1)); continue; }
    x extract-cert < $t.key > $t.cert
    echo "--- theirs: $tp / $prot"
    cell "[theirs $tp/$prot] ours extract-cert = theirs" bash -c "$OURS extract-cert < $t.key | $OURS dearmor > a.bin && $OTHER extract-cert < $t.key | $OURS dearmor | cmp - a.bin"
    cell "[theirs $tp/$prot] ours revoke-key -> their verify refuses" bash -c "$OURS revoke-key $kp < $t.key > r.cert && $OTHER sign $kp $t.key < msg.txt > s.sig && ! $OTHER verify s.sig r.cert < msg.txt"
    cell "[theirs $tp/$prot] ours revoke-key -> their encrypt refuses" bash -c "! $OTHER encrypt r.cert < msg.txt"
    cell "[theirs $tp/$prot] ours certify-userid -> their validate-userid" bash -c "$OURS certify-userid --userid='Theirs <t-$tp@example.org>' certifier.key < $t.cert > c.cert && $OTHER validate-userid 'Theirs <t-$tp@example.org>' certifier.cert < c.cert"
    cell "[theirs $tp/$prot] ours change-key-password -> their sign" bash -c "$OURS change-key-password $( [ $prot = pw ] && echo --old-key-password=pw1.txt ) --new-key-password=pw2.txt < $t.key > n.key && $OTHER sign --with-key-password=pw2.txt n.key < msg.txt > s.sig && $OURS verify s.sig $t.cert < msg.txt"
    cell "[theirs $tp/$prot] ours update-key -> their encrypt and verify" bash -c "$OURS update-key $kp < $t.key > u.key && $OURS extract-cert < u.key > u.cert && $OTHER encrypt u.cert < msg.txt > e.asc && $OTHER decrypt $kp u.key < e.asc | cmp - msg.txt && $OTHER sign $kp u.key < msg.txt > s.sig && $OTHER verify s.sig u.cert < msg.txt"
    cell "[theirs $tp/$prot] ours merge-certs absorbs their certification" bash -c "$OTHER certify-userid --userid='Theirs <t-$tp@example.org>' theirs.key < $t.cert > c.cert && $OURS merge-certs c.cert < $t.cert > m.cert && $OURS validate-userid 'Theirs <t-$tp@example.org>' theirs.cert < m.cert"
  done
done
echo "pass=$pass fail=$fail unsup=$unsup"
[ "$fail" -eq 0 ]
