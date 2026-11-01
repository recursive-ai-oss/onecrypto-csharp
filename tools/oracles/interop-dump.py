"""Writes the artifacts of one interoperability cell to a directory so that a driver can be run by hand.

  python3 interop-dump.py results.json "test title" "producer name" outdir

Files: producer-artifact-N (what the producing side made), additional-artifact-N (the test's own inputs), and command.txt
(our driver's command, with the expectations).
"""
import base64
import json
import os
import sys

d = json.load(open(sys.argv[1]))
title, prod, out = sys.argv[2], sys.argv[3], sys.argv[4]
os.makedirs(out, exist_ok=True)
for sec in d['results']:
    for t in sec['results']:
        if t['title'] != title:
            continue
        for i, a in enumerate(t['artifacts']):
            open(os.path.join(out, f'test-artifact-{i}'), 'wb').write(base64.b64decode(a[1]) if not a[1].startswith('data/') else a[1].encode())
        for cell in t['results']:
            pa = cell['artifacts']
            if pa.get('producer') != prod:
                continue
            for j, a in enumerate(pa.get('artifacts', [])):
                if a.get('data'):
                    open(os.path.join(out, f'producer-artifact-{j}'), 'wb').write(base64.b64decode(a['data']))
            for r in cell['results']:
                if r and r['producer'] == 'onecrypto':
                    for a in r['artifacts']:
                        print(a.get('command'))
                    print({k: str(v)[:300] for k, v in r.items() if k != 'artifacts'})
            print('expectations:', cell.get('producer_expectation'), cell.get('consumer_expectation'))
            sys.exit()
