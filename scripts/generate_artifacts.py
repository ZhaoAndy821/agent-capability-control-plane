#!/usr/bin/env python3
import json, pathlib, html
ROOT=pathlib.Path(__file__).resolve().parents[1]
cat=json.loads((ROOT/'registry/catalog.json').read_text(encoding='utf-8-sig'))
ops=json.loads((ROOT/'modes/operational-modes.json').read_text(encoding='utf-8-sig'))
ev=json.loads((ROOT/'modes/evaluation-modes.json').read_text(encoding='utf-8-sig'))
conf=json.loads((ROOT/'registry/conflict-groups.json').read_text(encoding='utf-8-sig'))
lock=json.loads((ROOT/'lock/sources.lock.json').read_text(encoding='utf-8-sig'))
version={'name':'Agent Capability Control Plane','version':'2.1.0-rc1','generated_from':['registry/catalog.json','modes/operational-modes.json','modes/evaluation-modes.json','registry/conflict-groups.json','lock/sources.lock.json'],'catalog_entries':len(cat['entries']),'operational_modes':len(ops['modes']),'evaluation_modes':len(ev['modes']),'conflict_groups':len(conf['groups']),'locked_operational_providers':len(lock['sources']),'real_windows_smoke_test':'pending'}
(ROOT/'VERSION.json').write_text(json.dumps(version,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
lines=['# Generated Registry Summary','',f"- Catalog entries: **{len(cat['entries'])}**",f"- Operational modes: **{len(ops['modes'])}**",f"- Evaluation modes: **{len(ev['modes'])}**",f"- Locked providers: **{len(lock['sources'])}**",'', '## Operational modes','']
for k,v in ops['modes'].items(): lines.append(f"- `{k}` → {', '.join(v.get('providers',[]))}")
(ROOT/'docs/REGISTRY-SUMMARY.md').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
rows=[]
for e in sorted(cat['entries'],key=lambda x:x['id']):
    blob=' '.join([e['id'],e['name'],e['kind'],e['adoption'],e['trust'],e['risk'],' '.join(e.get('domains',[])),' '.join(e.get('capabilities',[]))]).lower()
    src=f'<a href="{html.escape(e["source_url"],quote=True)}">source</a>' if e.get('source_url') else ''
    rows.append('<tr data-text="{}"><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(blob,quote=True),html.escape(e['id']),html.escape(e['name']),html.escape(e['kind']),html.escape(e['adoption']),html.escape(e['trust']),html.escape(e['risk']),src))
page='''<!doctype html><meta charset="utf-8"><title>ACCP Registry</title><style>body{font-family:system-ui;margin:24px}input{padding:10px;width:70%}table{border-collapse:collapse;width:100%;margin-top:16px}td,th{border:1px solid #ddd;padding:6px}.hide{display:none}</style><h1>Agent Capability Registry</h1><input id="q" placeholder="Search"><table><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Adoption</th><th>Trust</th><th>Risk</th><th>Source</th></tr></thead><tbody>'''+''.join(rows)+'''</tbody></table><script>q.oninput=()=>{let s=q.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>r.classList.toggle('hide',s&&!r.dataset.text.includes(s)))}</script>'''
(ROOT/'docs/INDEX.html').write_text(page,encoding='utf-8',newline='\n')
