#!/usr/bin/env python3
"""Summarises a results.json of the OpenPGP interoperability test suite: per driver, how many test cases scored Success, Failure,
Neutral or Unsupported, and the same by section for our driver.
   interop-summary.py results.json [driver-id-of-ours]"""
import collections
import json
import sys

data = json.load(open(sys.argv[1]))
ours = sys.argv[2] if len(sys.argv) > 2 else "onecrypto"
ids = [i["id"] for i in data["implementations"]]
total = collections.Counter()      # (consumer, score)
by_section = collections.defaultdict(collections.Counter)  # (section, consumer) -> score
tests = 0
for section in data["results"]:
    for test in section["results"]:
        tests += 1
        for cell in test["results"]:
            for r in cell["results"]:
                if r is None:
                    continue
                consumer = r["producer"]
                score = r["score"].split()[0] if r.get("score") else "None"
                total[(consumer, score)] += 1
                by_section[(section["section"], consumer)][score] += 1

scores = sorted({s for (_, s) in total})
print(f"{tests} tests in {len(data['results'])} sections; one score per driver per case\n")
print("| Driver | " + " | ".join(scores) + " |")
print("|---|" + "---|" * len(scores))
for i in ids:
    print(f"| {i} | " + " | ".join(str(total[(i, s)]) for s in scores) + " |")
print()
print(f"Per section for {ours} (score counts):\n")
for (section, consumer), c in sorted(by_section.items()):
    if consumer == ours:
        print(f"- {section}: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
