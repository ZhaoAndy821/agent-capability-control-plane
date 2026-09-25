#!/usr/bin/env python3
import json, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
cat=json.loads((ROOT/'registry/catalog.json').read_text(encoding='utf-8-sig'))
lock=json.loads((ROOT/'lock/sources.lock.json').read_text(encoding='utf-8-sig')).get('sources',{})
errors=[]; rows=[]
for e in cat['entries']:
    url=e.get('source_url')
    if not url or e.get('adoption') not in {'adopted','conditional','candidate','alternate','optional'}: continue
    cp=subprocess.run(['git','ls-remote',url,'HEAD'],capture_output=True,text=True)
    if cp.returncode!=0 or not cp.stdout.strip():
        errors.append(f"{e['id']}: {cp.stderr.strip() or 'no HEAD returned'}"); continue
    head=cp.stdout.split()[0]
    pinned=lock.get(e['id'],{}).get('commit')
    rows.append((e['id'],url,head,pinned,'match' if pinned==head else ('changed' if pinned else 'unpinned')))
print('| ID | HEAD | Pinned | Status |')
print('|---|---|---|---|')
for i,u,h,p,s in rows: print(f'| {i} | `{h[:12]}` | `{(p or "")[:12]}` | {s} |')
if errors:
    print('\nErrors:',file=sys.stderr)
    for x in errors: print(' - '+x,file=sys.stderr)
    sys.exit(2)
