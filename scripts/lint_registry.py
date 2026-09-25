#!/usr/bin/env python3
import json, pathlib, re, hashlib, sys
from accp import readj, validate_catalog_eligibility, validate_lock_fields
import artifact_binding as binding
R=pathlib.Path(__file__).resolve().parents[1]
err=[]
def j(p): return readj(R/p,strict=True)
cat=j('registry/catalog.json'); idx={}
for e in cat['entries']:
    try: validate_catalog_eligibility(e)
    except RuntimeError as ex:
        err.append(str(ex)); continue
    i=e['id']
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,95}',i): err.append(f'invalid id {i}')
    if i in idx: err.append(f'duplicate id {i}')
    idx[i]=e
    path=(e.get('deploy') or {}).get('path')
    if path and (path.startswith(('/', '\\')) or '..' in path.replace('\\','/').split('/')): err.append(f'unsafe deploy.path {i}: {path}')
ops=j('modes/operational-modes.json')['modes']; evm=j('modes/evaluation-modes.json')['modes']; lock=j('lock/sources.lock.json')['sources']
for m,s in ops.items():
    for i in s.get('providers',[]):
        if i not in idx: err.append(f'operational {m}: unknown {i}')
        if i not in lock: err.append(f'operational {m}: unlocked {i}')
for m,ids in evm.items():
    for i in ids:
        if i not in idx: err.append(f'evaluation {m}: unknown {i}')
# conflict file is generated mirror; enforce bidirectional equality
truth={}
for e in cat['entries']:
    if e.get('conflict_group'): truth.setdefault(e['conflict_group'],[]).append(e['id'])
mirror=j('registry/conflict-groups.json')['groups']
for g,ids in truth.items():
    if sorted(ids)!=sorted(mirror.get(g,{}).get('members',[])): err.append(f'conflict mirror mismatch {g}')
for g in mirror:
    if g not in truth: err.append(f'extraneous conflict group {g}')
for i,l in lock.items():
    try: validate_lock_fields(i,l)
    except RuntimeError as ex:
        err.append(str(ex)); continue
    if i not in idx: err.append(f'lock unknown {i}'); continue
    try:
        binding.validate_lock_record(l)
        if 'binding' not in l:
            print(f'LEGACY NON-ADMISSIBLE: {i}; explicit catalog path, fresh review/pin/materialize required')
            continue
        binding.load_review_binding(R,i,idx[i],l)
    except (RuntimeError,OSError,ValueError) as ex:
        err.append(f'{i}: {ex}')

if err:
    print('FAIL'); [print(' -',x) for x in err]; sys.exit(1)
print(f'OK: {len(idx)} catalog entries, {len(ops)} operational modes, {len(evm)} evaluation modes, {len(lock)} locked providers')
