"""Lists the cells where Sequoia's driver scored Success and ours scored Failure, grouped by test, for triage.

  python3 interop-vs-sqop.py results.json [title substring]
"""
import json
import sys
from collections import defaultdict

d = json.load(open(sys.argv[1]))
want = sys.argv[2] if len(sys.argv) > 2 else ''
groups = defaultdict(list)
for sec in d['results']:
    for t in sec['results']:
        if want not in t['title']:
            continue
        for cell in t['results']:
            score = {r['producer']: r for r in cell['results'] if r}
            sq = next((r for k, r in score.items() if k.startswith('sqop')), None)
            ours = score.get('onecrypto')
            if sq and ours and sq.get('score') == 'Success' and ours.get('score') == 'Failure':
                groups[t['title']].append((str(cell['artifacts'].get('producer') if isinstance(cell['artifacts'], dict) else cell['artifacts'])[:40], ours.get('error', '')[:50].strip()))
for title, cells in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    print(f'{len(cells):3} {title[:70]} | {cells[0]} | {cells[-1]}')
print('total', sum(len(c) for c in groups.values()))
