#!/usr/bin/env python3
"""Extracts the OCB sample results (RFC 7253 Appendix A) from the RFC text into a line-oriented vector file.

Usage: extract-rfc7253-vectors.py rfc7253.txt > testdata/vectors/rfc7253-ocb.txt
Each line is `name key taglen nonce aad plaintext ciphertext` (hex; `-` is the empty string), or
`iter name taglen output` for the iterated test.
"""
import re, sys

text = open(sys.argv[1], encoding="ascii").read()
# Drop page furniture so wrapped values join up.
lines = [l for l in text.splitlines() if not re.match(r"^(Krovetz|RFC 7253)", l)]
start = next(i for i, l in enumerate(lines) if l.startswith("Appendix A.") and i > 100)
body = lines[start:]


def hexjoin(parts):
    return "".join(parts) or "-"


records = []
cur = None
key = None
for l in body:
    m = re.match(r"^\s+(K|N|A|P|C)\s*:\s*([0-9A-F]*)\s*$", l)
    if m:
        tag, val = m.groups()
        if tag == "K":
            key = val
            cur = None
        elif tag == "N":
            cur = {"K": key, "N": val, "A": [], "P": [], "C": []}
            records.append(cur)
            field = None
        if tag != "K" and tag != "N":
            field = tag
            cur[tag].append(val)
        continue
    m = re.match(r"^\s+([0-9A-F]+)\s*$", l)
    if m and cur is not None and field:
        cur[field].append(m.group(1))
    elif re.match(r"^\s+\S", l) and not re.match(r"^\s+[0-9A-F]+\s*$", l):
        field = None

n = 0
for r in records:
    c = hexjoin(r["C"])
    k = r["K"]
    taglen = 96 if r is records[-1] else 128
    print(f"rfc7253-{n} {k} {taglen} {r['N']} {hexjoin(r['A'])} {hexjoin(r['P'])} {c}")
    n += 1

for m in re.finditer(r"AEAD_AES_(\d+)_OCB_TAGLEN(\d+) Output\s*:\s*([0-9A-F]+)", text):
    print(f"iter {m.group(1)} {m.group(2)} {m.group(3)}")
