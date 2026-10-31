#!/usr/bin/env python3
"""Prints a short summary of the certificates of chosen differential cases.

Usage: explain.py cases.jsonl id-prefix-or-id... > summary.txt
For each case: the verdict inputs, then per certificate its subject, issuer, validity,
subjectAltName, basicConstraints, keyUsage, extKeyUsage and nameConstraints as `openssl x509`
prints them. Used to check differential classes by hand against the RFC text.
"""
import json
import subprocess
import sys

ids = set(sys.argv[2:])
EXT = ["subjectAltName", "basicConstraints", "keyUsage", "extendedKeyUsage", "nameConstraints"]


def info(pem):
    r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-ext", ",".join(EXT)],
                       input=pem, capture_output=True, text=True)
    return " | ".join(" ".join(r.stdout.split()).replace("X509v3 ", "").split(" | ")) if r.returncode == 0 else r.stderr.strip()


for l in open(sys.argv[1]):
    c = json.loads(l)
    if c["id"] not in ids:
        continue
    print("==", c["id"], "expected", c["expected"], "time", c["time"], "profile", c["profile"], "eku", c["eku"], "name", c["name"])
    print("  leaf:", info(c["leaf"]))
    for u in c["untrusted"]:
        print("  untrusted:", info(u))
    for t in c["trusted"]:
        print("  trusted:", info(t))
