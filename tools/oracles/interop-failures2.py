import json, collections, sys
d = json.load(open(sys.argv[1]))
drivers = {i['id'] for i in d['implementations']}
rows = collections.defaultdict(lambda: collections.Counter())
sample = {}
for sec in d['results']:
    for t in sec['results']:
        for cell in t['results']:
            prod = cell['artifacts']['producer']
            if prod in drivers:
                continue  # round trips: need generate-key, which is not provided
            sc = {}
            for r in cell['results']:
                if r is None: continue
                sc[r['producer']] = r
            o = sc.get('onecrypto')
            if not o: continue
            os_ = (o.get('score') or 'None').split()[0]
            if os_ == 'Success' or os_ == 'Neutral': continue
            others = [(k, (v.get('score') or 'None').split()[0]) for k, v in sc.items() if k != 'onecrypto']
            if not any(s == 'Success' for _, s in others): continue
            key = (sec['section'], t['title'])
            rows[key][os_] += 1
            sample.setdefault(key, (prod, o.get('score'), (o.get('error') or '')[:160], others))
print('non-roundtrip cells where ours fails and another driver succeeds:', sum(sum(c.values()) for c in rows.values()))
for key, c in sorted(rows.items(), key=lambda kv: -sum(kv[1].values())):
    p, sc, err, oth = sample[key]
    print(f'{sum(c.values()):3d} {key[0][:14]:14s} {key[1][:60]:60s} | {p[:30]!r} {sc} {err!r}')
