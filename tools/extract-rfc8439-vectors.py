#!/usr/bin/env python3
"""Extracts the ChaCha20-Poly1305 test vectors of RFC 8439 (sections 2.8.2, appendix A.1, A.3 and A.5) into a line-oriented file.

Usage: extract-rfc8439-vectors.py rfc8439.txt > testdata/vectors/rfc8439.txt
Lines (all hex; `-` is the empty string):
  block <key> <counter> <nonce> <keystream>
  poly1305 <key> <message> <tag>
  aead <key> <nonce> <aad> <plaintext> <ciphertext> <tag>
  decrypt <key> <nonce> <aad> <ciphertext> <tag>
"""
import re, sys

text = open(sys.argv[1], encoding="ascii").read()
lines = [l for l in text.splitlines() if not re.match(r"^(Nir & Langley|RFC 8439)", l)]


def find(pattern, start=0):
    for i in range(start, len(lines)):
        if re.search(pattern, lines[i]):
            return i
    raise SystemExit("not found: " + pattern)


def dump(label, start, stop=None):
    """The hex dump that follows the first line at or after start whose text is label."""
    i = find(r"^\s*" + re.escape(label) + r"\s*$", start)
    out = []
    i += 1
    while i < len(lines) and (stop is None or i < stop):
        m = re.match(r"^\s+(\d{3})  (.*)$", lines[i])
        if m:
            out += m.group(2)[:47].split()
        elif out and lines[i].strip():
            break
        elif out and not lines[i].strip():
            # blank line inside page furniture or the end of the dump
            j = i
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and re.match(r"^\s+\d{3}  ", lines[j]):
                i = j
                continue
            break
        i += 1
    return "".join(out) or "-"


def colon_row(label, start):
    """A tag printed as one row of colon-separated bytes after the label."""
    i = find(r"^\s*" + re.escape(label) + r"\s*$", start)
    return lines[i + 1].strip().replace(":", "")


records = []

# A.1 block function vectors
a1 = find(r"^A\.1\.  The ChaCha20 Block Functions", 200)
a2 = find(r"^A\.2\.  ChaCha20 Encryption", a1)
starts = [i for i in range(a1, a2) if re.match(r"^\s+Test Vector #\d+:", lines[i])] + [a2]
for s, e in zip(starts, starts[1:]):
    key = dump("Key:", s, e)
    nonce = dump("Nonce:", s, e)
    counter = int(re.search(r"Block Counter = (\d+)", "\n".join(lines[s:e])).group(1))
    ks = dump("Keystream:", s, e)
    records.append(("block", key, "%08x" % counter, nonce, ks))

# A.3 Poly1305 vectors #1 to #4 (hex dumps)
b1 = find(r"^A\.3\.  Poly1305 Message Authentication Code", 200)
b2 = find(r"^A\.4\.  Poly1305 Key Generation", b1)
starts = [i for i in range(b1, b2) if re.match(r"^\s+Test Vector #\d+:\s*$", lines[i])] + [b2]
for s, e in zip(starts, starts[1:]):
    records.append(("poly1305", dump("One-time Poly1305 Key:", s, e), dump("Text to MAC:", s, e), dump("Tag:", s, e)))

# A.3 vectors #5 to #11: R, S, data, tag as plain hex rows
starts = [i for i in range(b1, b2) if re.match(r"^\s+Test Vector #(5|6|7|8|9|10|11):", lines[i])] + [b2]
for s, e in zip(starts, starts[1:]):
    def rows(label):
        i = find(r"^\s+" + label + r"\s*$", s)
        out = []
        i += 1
        while i < e and re.match(r"^\s+([0-9A-Fa-f]{2} ?)+\s*$", lines[i]):
            out += lines[i].split()
            i += 1
        return "".join(out).lower() or "-"
    records.append(("poly1305", rows("R:") + rows("S:"), rows("data:"), rows("tag:")))

# 2.8.2 AEAD
c1 = find(r"^2\.8\.2\.  Example and Test Vector for AEAD", 200)
c2 = find(r"^3\.  ", c1)
iv = dump("IV:", c1, c2)
fixed = dump("32-bit fixed-common part:", c1, c2)
records.append(("aead", dump("Key:", c1, c2), fixed + iv, dump("AAD:", c1, c2), dump("Plaintext:", c1, c2), dump("Ciphertext:", c1, c2), colon_row("Tag:", c1)))

# A.5 decryption
d1 = find(r"^A\.5\.  ChaCha20-Poly1305 AEAD Decryption", 200)
records.append(("decrypt", dump("The ChaCha20 Key", d1), dump("The nonce:", d1), dump("The AAD:", d1), dump("Ciphertext:", d1), dump("Received Tag:", d1)))

for r in records:
    print(" ".join(r))
