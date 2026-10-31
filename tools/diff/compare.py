#!/usr/bin/env python3
"""Compares the verdicts of ours, openssl and go over one cases file.

Usage: compare.py cases.jsonl ours.tsv openssl.tsv go.tsv [out-disagreements.tsv]
Prints the agreement matrix per case set and writes every case where the three do not all agree.
"""
import collections
import json
import sys

cases = [json.loads(l) for l in open(sys.argv[1])]


def load(p):
    d = {}
    for l in open(p):
        f = l.rstrip("\n").split("\t")
        d[f[0]] = (f[1], f[2] if len(f) > 2 else "")
    return d


ours, ossl, go = load(sys.argv[2]), load(sys.argv[3]), load(sys.argv[4])
m = collections.Counter()
rows = []
for c in cases:
    i = c["id"]
    v = (ours.get(i, ("?",))[0], ossl.get(i, ("?",))[0], go.get(i, ("?",))[0])
    m[(c["set"], v)] += 1
    if len(set(v)) > 1:
        rows.append((i, c["expected"], *v, ours[i][1][:80], ossl[i][1][-80:], go[i][1][:80]))
for (s, v), n in sorted(m.items()):
    print(f"{s:10} ours={v[0]:6} openssl={v[1]:6} go={v[2]:6} {n}")
print(len(cases), "cases,", len(rows), "with a difference")
if len(sys.argv) > 5:
    with open(sys.argv[5], "w") as o:
        for r in rows:
            o.write("\t".join(r) + "\n")

if len(sys.argv) > 5:
    cat = collections.defaultdict(collections.Counter)
    ex = {}
    for r in rows:
        parts = r[0].split("::")
        key = "::".join(parts[:2]) if parts[0] in ("rfc5280", "webpki", "pathlen", "crl", "cve", "online", "pathological", "rfc9881", "invalid") else "::".join(parts[:3] if parts[0] != "bettertls" else parts[:2])
        cat[key][(r[2], r[3], r[4], r[1])] += 1
        ex.setdefault((key, r[2], r[3], r[4]), r)
    print()
    for key in sorted(cat):
        for (a, b, c, e), n in sorted(cat[key].items()):
            print(f"{key:45} ours={a} openssl={b} go={c} expected={e} x{n}")
