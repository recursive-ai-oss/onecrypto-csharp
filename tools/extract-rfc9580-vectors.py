#!/usr/bin/env python3
"""Extracts the ASCII-armored sample objects of RFC 9580 Appendix A into testdata/openpgp/rfc9580/.

usage: extract-rfc9580-vectors.py <rfc9580.txt> <output directory>

The RFC text is indented and broken by page headers and footers; the armor lines between the BEGIN and END lines are
kept and everything else is dropped. Each file is named after the appendix section that holds it.
"""
import os
import re
import sys

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
lines = open(src, encoding="utf-8").read().replace("\f", "\n").split("\n")
section = None
block = None
counts = {}
in_appendix = False
for line in lines:
    m = re.match(r"^(A\.\d+(?:\.\d+)?)\.\s", line)
    if m:
        section = m.group(1)
        in_appendix = True
    if not in_appendix:
        continue
    s = line.strip()
    if s.startswith("-----BEGIN PGP") and "SIGNED MESSAGE" not in s:
        block = [s]
        continue
    if block is not None:
        if re.search(r"Wouters|^RFC 9580\s|\[Page \d+\]", line):
            continue
        if s.startswith("-----END PGP"):
            block.append(s)
            n = counts.get(section, 0) + 1
            counts[section] = n
            name = section.replace(".", "_") + ("" if n == 1 else "_%d" % n) + ".asc"
            with open(os.path.join(out, name), "w", newline="\n") as f:
                f.write("\n".join(block) + "\n")
            block = None
        else:
            block.append(s)
print("wrote", sum(counts.values()), "files")
