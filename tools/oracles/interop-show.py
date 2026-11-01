"""Shows the cells of one interoperability test: what each driver scored and the error text, for triage.

  python3 interop-show.py results.json "title substring" [max cells]
"""
import json
import sys

d = json.load(open(sys.argv[1]))
want = sys.argv[2]
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 6
shown = 0
for sec in d['results']:
    for t in sec['results']:
        if want not in t['title']:
            continue
        print('##', t['title'])
        for cell in t['results']:
            rs = [r for r in cell['results'] if r]
            ours = [r for r in rs if r.get('producer') == 'onecrypto' or r.get('consumer') == 'onecrypto']
            if not any((r.get('score') or '').startswith('Failure') for r in ours):
                continue
            print(' cell', {k: str(v)[:80] for k, v in cell['artifacts'].items()})
            for r in rs:
                print('   ', {k: str(v)[:260] for k, v in r.items() if k not in ('data', 'artifacts')})
            shown += 1
            if shown >= limit:
                sys.exit()
