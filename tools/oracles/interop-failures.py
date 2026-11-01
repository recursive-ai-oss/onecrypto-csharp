import json, collections, sys
d = json.load(open(sys.argv[1]))
ours = 'onecrypto'
bad = collections.defaultdict(list)      # title -> [(artifact producer, ours score, sqop, gosop)]
agree = collections.Counter()
total_fail = 0
for sec in d['results']:
    for t in sec['results']:
        for cell in t['results']:
            prod = cell['artifacts']['producer']
            sc = {}
            for r in cell['results']:
                if r is None: continue
                sc[r['producer']] = (r.get('score') or 'None').split()[0]
            o = sc.get(ours)
            if o in ('Failure', 'IO', 'Unknown'):
                total_fail += 1
                others = [sc.get(k) for k in sc if k != ours]
                key = (sec['section'], t['title'])
                if 'Success' in others:
                    bad[key].append((prod, o, tuple(sorted((k, v) for k, v in sc.items() if k != ours))))
                else:
                    agree[key] += 1
print('ours failing cells:', total_fail, ' where some other driver succeeds:', sum(len(v) for v in bad.values()), ' where none does:', sum(agree.values()))
by_prod = collections.Counter()
for k, v in bad.items():
    for p, o, others in v:
        by_prod[p] += 1
print('by artifact producer:', dict(by_prod))
for (sec, title), v in sorted(bad.items(), key=lambda kv: -len(kv[1]))[:45]:
    print(f'{len(v):3d} {sec[:18]:18s} {title[:80]}  e.g. producer={v[0][0]} ours={v[0][1]} others={v[0][2]}')
