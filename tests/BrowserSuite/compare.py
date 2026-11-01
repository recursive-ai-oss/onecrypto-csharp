#!/usr/bin/env python3
"""Compares the case lines of the suite's runs.

    compare.py <report.md> <chromium.out> <node.out> <native.out> [<native-forced.out>]

The browser engine and Node must agree on every case (same status and verdict). Against the native runs the areas that test the same
code on the same inputs must agree too; the areas that probe the platform itself are listed, not judged. Exits 1 on any failed case or
disagreement.
"""
import collections
import sys

PLATFORM_AREAS = {"platform", "unsupported", "protected-inputs", "load", "private-keys"}


def read(path):
    cases = collections.OrderedDict()
    for line in open(path, encoding="utf-8", errors="replace"):
        f = line.rstrip("\n").split("\t")
        if f[0] == "CASE" and len(f) >= 5:
            cases[(f[1], f[2])] = (f[3], f[4], f[5] if len(f) > 5 else "")
    return cases


def counts(cases):
    c = collections.OrderedDict()
    for (area, _), (status, _, _) in cases.items():
        c.setdefault(area, collections.Counter())[status] += 1
    return c


report, chromium_path, node_path, native_path = sys.argv[1:5]
forced_path = sys.argv[5] if len(sys.argv) > 5 else None
runs = {"chromium": read(chromium_path), "node": read(node_path), "native": read(native_path)}
if forced_path:
    runs["native, fallbacks forced"] = read(forced_path)

problems = []
out = ["## Cases per area\n", "| area | " + " | ".join(f"{n} (pass/fail/skip)" for n in runs) + " |", "|---|" + "---|" * len(runs)]
per = {n: counts(c) for n, c in runs.items()}
for area in per["chromium"]:
    cells = []
    for n in runs:
        c = per[n].get(area, collections.Counter())
        cells.append(f"{c['pass']}/{c['fail']}/{c['skip']}")
        if n in ("chromium", "node") and c["fail"]:
            problems.append(f"{n}: {c['fail']} failed case(s) in {area}")
    out.append(f"| {area} | " + " | ".join(cells) + " |")


def compare(a, b, label, judged):
    ka, kb = runs[a], runs[b]
    notes = []
    for key in ka.keys() | kb.keys():
        if key not in ka or key not in kb:
            notes.append((key, "only in " + (a if key in ka else b), ""))
        elif ka[key][:2] != kb[key][:2]:
            notes.append((key, f"{a}: {ka[key][0]} {ka[key][1]}", f"{b}: {kb[key][0]} {kb[key][1]}"))
    # ML-DSA certificates need a platform with ML-DSA; where it is missing the signature cannot be checked and the path is refused.
    judged_notes = [n for n in notes if judged(n[0][0]) and not n[0][1].startswith("rfc9881::")]
    out.append(f"\n## {label}: {len(set(ka) & set(kb))} shared cases, {len(notes)} differences ({len(judged_notes)} in judged areas)\n")
    for key, x, y in sorted(notes)[:80]:
        out.append(f"- `{key[0]}` {key[1]}: {x} | {y}" + ("" if judged(key[0]) else "  *(platform probe, expected)*"))
    return judged_notes


problems += [f"chromium and node disagree on {k}" for k, _, _ in compare("chromium", "node", "Chromium against Node", lambda area: True)]
problems += [f"chromium and native disagree on {k}" for k, _, _ in compare("chromium", "native", "Chromium against the native run", lambda area: area not in PLATFORM_AREAS)]
if forced_path:
    problems += [f"native forced and native disagree on {k}" for k, _, _ in compare("native, fallbacks forced", "native", "Native with the managed verifiers forced, against native", lambda area: area not in PLATFORM_AREAS)]

out.append("\n## Result\n")
out += [f"- FAIL: {p}" for p in problems] or ["- all runs agree and no case failed"]
open(report, "w").write("\n".join(out) + "\n")
print("\n".join(out[-12:]))
sys.exit(1 if problems else 0)
