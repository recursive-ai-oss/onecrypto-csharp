#!/usr/bin/env bash
# Generates the three-certificate chain (P-256, valid from 2026-01-01 for a century) that tests/Common/ValidationSmoke.cs embeds, and prints it
# as base64 lines. The keys are throwaway and are discarded. Needs openssl 3.x.
set -euo pipefail
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
cd "$d"
for n in root ca leaf; do openssl ecparam -name prime256v1 -genkey -noout -out $n.key; done
start=20260101000000Z
openssl req -new -key root.key -subj '/CN=Smoke Root' -out root.csr
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > root.ext
openssl x509 -req -in root.csr -signkey root.key -days 36500 -set_serial 1 -extfile root.ext -out root.pem -not_before $start 2>/dev/null || openssl x509 -req -in root.csr -signkey root.key -days 36500 -set_serial 1 -extfile root.ext -out root.pem
openssl req -new -key ca.key -subj '/CN=Smoke CA' -out ca.csr
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > ca.ext
openssl x509 -req -in ca.csr -CA root.pem -CAkey root.key -days 36000 -set_serial 2 -extfile ca.ext -out ca.pem
openssl req -new -key leaf.key -subj '/CN=smoke.example.test' -out leaf.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:smoke.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -days 35000 -set_serial 3 -extfile leaf.ext -out leaf.pem
for n in root ca leaf; do echo "$n:"; openssl x509 -in $n.pem -outform DER | base64 -w0; echo; openssl x509 -in $n.pem -noout -dates | tr '\n' ' '; echo; done
