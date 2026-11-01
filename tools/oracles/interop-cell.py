import json, sys
d = json.load(open(sys.argv[1]))
want = sys.argv[2]
n = 0
for sec in d['results']:
    for t in sec['results']:
        if want not in t['title']: continue
        for cell in t['results']:
            for r in cell['results']:
                if r and r['producer'] == 'onecrypto' and (r.get('score') or '').startswith('Failure'):
                    print(t['title'], '|', cell['artifacts']['producer'])
                    print({k: (str(v)[:300]) for k, v in r.items() if k != 'data'})
                    n += 1
                    if n >= 2: sys.exit()
