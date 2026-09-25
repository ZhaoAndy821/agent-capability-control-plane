#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, pathlib, shutil, subprocess, sys, tempfile, hashlib, uuid, time, re, stat, math
from contextlib import nullcontext
from functools import wraps
from datetime import datetime, timezone
from runtime_ownership import RuntimeOwnership
from active_transaction import JournalAuthority
import artifact_binding as binding
import activation_context as activation

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME_RAW = os.environ.get('ACCP_RUNTIME_ROOT', str(pathlib.Path.home()/'.agent-capability-control-plane'))
RUNTIME = pathlib.Path(RUNTIME_RAW)  # Preserve spelling until ownership validation.
CATALOG = ROOT/'registry/catalog.json'
CONFLICTS = ROOT/'registry/conflict-groups.json'
OP_MODES = ROOT/'modes/operational-modes.json'
EVAL_MODES = ROOT/'modes/evaluation-modes.json'
LOCK = ROOT/'lock/sources.lock.json'
EVIDENCE = ROOT/'audit/evidence'
SOURCES = RUNTIME/'sources'
VAULT = RUNTIME/'vault'/'skills'
GLOBAL_INSTALL = RUNTIME/'install-manifest.json'
GLOBAL_STATE = RUNTIME/'active-state.json'

ID_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,95}$')
SHA_RE = re.compile(r'^[0-9a-f]{40}$')
ELIGIBILITY_DOMAINS = {
    'adoption': frozenset(('adopted','alternate','candidate','conditional','deferred',
                           'experimental','optional','quarantine','reference','rejected')),
    'trust': frozenset(('reviewed','partial','unreviewed','quarantine')),
    'risk': frozenset(('low','medium','high')),
    'invocation': frozenset(('dormant','explicit','implicit')),
}
SUPPORTED_EXECUTABLES = frozenset(('python','git','bash','ffmpeg','yt-dlp'))

def runtime_owner(project=None):
    return RuntimeOwnership(RUNTIME_RAW, ROOT, project)

def runtime_operation(create=False):
    def decorate(fn):
        @wraps(fn)
        def owned(args):
            with runtime_owner().session(create=create, dry_run=getattr(args,'dry_run',False)):
                return fn(args)
        return owned
    return decorate

def now(): return datetime.now(timezone.utc).isoformat()
def readj(p, *, strict=False):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise RuntimeError(f'duplicate JSON key: {key}')
            result[key]=value
        return result
    def invalid_constant(value):
        raise RuntimeError(f'nonfinite JSON value: {value}')
    def finite_float(value):
        number=float(value)
        if not math.isfinite(number): invalid_constant(value)
        return number
    options={'object_pairs_hook':unique,'parse_constant':invalid_constant,'parse_float':finite_float} if strict else {}
    value=json.loads(pathlib.Path(p).read_text(encoding='utf-8-sig'),**options)
    if strict and type(value) is not dict: raise RuntimeError(f'JSON object required: {p}')
    return value
def writej(p, obj):
    p=pathlib.Path(p); p.parent.mkdir(parents=True, exist_ok=True)
    tmp=p.with_name(p.name+'.tmp-'+uuid.uuid4().hex)
    tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    os.replace(tmp,p)
def sha256_file(p):
    h=hashlib.sha256();
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def tree_hash(root, exclude_names=frozenset({'.accp-vault-manifest.json'})):
    root=pathlib.Path(root); h=hashlib.sha256()
    for p in sorted(x for x in root.rglob('*') if x.is_file() and '.git' not in x.parts and x.name not in exclude_names):
        rel=p.relative_to(root).as_posix().encode(); h.update(rel+b'\0'); h.update(bytes.fromhex(sha256_file(p)))
    return h.hexdigest()
def run(cmd,cwd=None,check=True):
    cp=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True)
    if check and cp.returncode: raise RuntimeError(f"command failed ({cp.returncode}): {' '.join(cmd)}\n{cp.stderr.strip()}")
    return cp
def normalize_url(u):
    u=(u or '').strip().rstrip('/')
    if u.endswith('.git'): u=u[:-4]
    return u.lower()
def catalog_index(*, strict=False, record=None):
    c=record if record is not None else (binding.read_bound_record(CATALOG,canonical=False).value if strict else readj(CATALOG)); out={}
    if strict:
        resolver_object(c,'catalog',2)
        resolver_require(type(c.get('entries')) is list,'catalog.entries must be a list')
    for e in c['entries']:
        if strict:
            validate_catalog_eligibility(e)
        i=e['id']
        if not ID_RE.fullmatch(i): raise RuntimeError(f'invalid catalog id: {i}')
        if i in out: raise RuntimeError(f'duplicate catalog id: {i}')
        out[i]=e
    return out

def safe_deploy_path(repo, rel):
    repo=pathlib.Path(repo).resolve(); rel=rel or '.'
    pp=pathlib.PurePosixPath(rel.replace('\\','/'))
    if pp.is_absolute() or '..' in pp.parts: raise RuntimeError(f'unsafe deploy.path: {rel}')
    target=(repo/pathlib.Path(*pp.parts)).resolve()
    try: target.relative_to(repo)
    except ValueError: raise RuntimeError(f'deploy.path escapes repo: {rel}')
    return target

def source_dir(e):
    return SOURCES/binding.digest('accp-origin-v1',binding.canonical_origin(e['source_url']))


def evidence_path(i): return EVIDENCE/f'{i}.json'
def lock_index(*, strict=False, record=None):
    data=record if record is not None else (binding.read_bound_record(LOCK,canonical=False).value if strict else readj(LOCK))
    if strict:
        resolver_object(data,'lock',2)
        resolver_object(data.get('sources'),'lock.sources')
        for i,record in data['sources'].items(): validate_lock_fields(i,record)
    return data.get('sources',{})

def assert_git_clean(repo):
    s=run(['git','status','--porcelain=v1','--untracked-files=all'],repo).stdout.strip()
    if s: raise RuntimeError(f'contaminated worktree: {repo}\n{s[:1000]}')

def ensure_source_at_lock(i,e,l):
    ready_runtime_binding()
    repo,_=binding.acquire_cache(SOURCES,binding.canonical_origin(e['source_url']),l['commit'])
    return repo


def evidence_ok(i,l, *, strict=False, entry=None):
    entry=catalog_index(strict=True)[i] if entry is None else entry
    return binding.load_review_binding(ROOT,i,entry,l,forbidden_roots=(RUNTIME,)).value


def ready_runtime_binding(project=None):
    owner=runtime_owner(project); receipt=owner.validate()
    if receipt is None or receipt['state']!='ready': raise RuntimeError('ready owned runtime required')
    if (os.path.normcase(str(SOURCES))!=str(owner.root/'sources') or
        os.path.normcase(str(VAULT))!=str(owner.root/'vault'/'skills')):
        raise RuntimeError('runtime component location mismatch')
    record={key:receipt[key] for key in ('runtime_id','runtime_path','control_plane_path','principal','root_identity')}
    record['vault_identity']=receipt['components']['vault']['identity']
    return binding.validate_runtime_binding(record)


def validate_catalog_eligibility(e):
    """Pure representation checks. Known inactive entries remain valid catalog data."""
    resolver_object(e,'catalog entry')
    validate_managed_ids([e.get('id')]); i=e['id']
    for field,domain in ELIGIBILITY_DOMAINS.items():
        value=e.get(field)
        resolver_require(type(value) is str and value in domain,f'{i}: invalid {field}')
    resolver_strings(e.get('capabilities'),f'{i}.capabilities')
    group=e.get('conflict_group')
    resolver_require('conflict_group' in e and (group is None or (type(group) is str and bool(group.strip()))),
                     f'{i}: invalid/missing conflict_group')
    deploy=resolver_object(e.get('deploy'),f'{i}.deploy')
    resolver_require(type(deploy.get('deployable')) is bool,f'{i}: deployable must be boolean')
    validate_runtime_fields(e)

def validate_runtime_fields(e):
    resolver_object(e,'catalog entry')
    runtime=resolver_object(e.get('runtime'),'runtime')
    for field in ('requires','credentials'): resolver_strings(runtime.get(field),f'runtime.{field}')
    return runtime

def validate_approval_fields(approval):
    resolver_object(approval,'approval')
    resolver_require(not set(approval)-{'partial_or_conditional','high_risk','approved_at'},'unknown approval fields')
    for field in ('partial_or_conditional','high_risk'):
        if field in approval:
            resolver_require(type(approval[field]) is bool,f'approval.{field} must be boolean')
    if 'approved_at' in approval:
        resolver_require(type(approval['approved_at']) is str and bool(approval['approved_at'].strip()),
                         'invalid approval.approved_at')
    return approval

def validate_lock_fields(i,lock):
    validate_managed_ids([i]); resolver_object(lock,f'lock {i}')
    for field in ('repo','commit','deploy_path','evidence','evidence_sha256'):
        resolver_require(type(lock.get(field)) is str and bool(lock[field].strip()),f'{i}: invalid lock {field}')
    resolver_require(bool(SHA_RE.fullmatch(lock['commit'])),f'{i}: invalid locked commit')
    resolver_require(bool(re.fullmatch(r'[0-9a-f]{64}',lock['evidence_sha256'])),f'{i}: invalid evidence hash')
    validate_approval_fields(lock.get('approval'))
    binding.validate_lock_record(lock)

def approval_ok(e,l,allow_partial=False):
    """Pure operational policy; evidence and executable checks belong to the shared core."""
    validate_catalog_eligibility(e); resolver_object(l,'lock')
    approval=validate_approval_fields(l.get('approval'))
    resolver_require(type(allow_partial) is bool,'allow_partial must be boolean')
    if e['deploy']['deployable'] is not True: raise RuntimeError(f"{e['id']}: not deployable")
    if e['adoption'] not in ('adopted','conditional'): raise RuntimeError(f"{e['id']}: adoption={e['adoption']} is not operationally eligible")
    if e['trust'] not in ('reviewed','partial'): raise RuntimeError(f"{e['id']}: trust={e['trust']} provider refused")
    if e['trust']=='partial' or e['adoption']=='conditional':
        if not (allow_partial is True and approval.get('partial_or_conditional') is True):
            raise RuntimeError(f"{e['id']}: partial/conditional provider needs explicit approval")
    if e['risk']=='high' and approval.get('high_risk') is not True:
        raise RuntimeError(f"{e['id']}: high-risk provider refused")
    if e['invocation']=='dormant': raise RuntimeError(f"{e['id']}: dormant provider refused")
    if e['invocation']=='implicit' and e['risk']!='low':
        raise RuntimeError(f"{e['id']}: implicit invocation requires low risk")

def check_dependencies(e):
    runtime=validate_runtime_fields(e)
    missing=[]
    for dep in sorted(set(name.lower() for name in runtime['requires'])):
        if dep not in SUPPORTED_EXECUTABLES: raise RuntimeError(f'unsupported dependency requirement: {dep}')
        if shutil.which(dep) is None: missing.append(dep)
    return missing, sorted(set(runtime['credentials']))

def require_operational_eligibility(i,e,l,allow_partial=False):
    """Shared admission checks; no source fetch, runtime creation or credential access."""
    validate_catalog_eligibility(e); validate_lock_fields(i,l)
    resolver_require(e['id']==i,'catalog/provider identity mismatch')
    approval_ok(e,l,allow_partial)
    ev=evidence_ok(i,l,strict=True,entry=e)
    missing,_=check_dependencies(e)
    if missing: raise RuntimeError(f'{i}: missing dependencies {missing}')
    return ev

def cmd_doctor(args):
    print('report_kind: configuration_only; Active Set lifecycle: not assessed')
    checks=[]
    for p in [CATALOG,CONFLICTS,OP_MODES,EVAL_MODES,LOCK]:
        try: readj(p); checks.append((str(p.relative_to(ROOT)),'ok'))
        except Exception as ex: checks.append((str(p.relative_to(ROOT)),f'FAIL {ex}'))
    checks += [('git','ok' if shutil.which('git') else 'FAIL missing'),('python',sys.version.split()[0])]
    if args.project:
        pr=pathlib.Path(args.project).resolve(); checks.append(('project',str(pr)))
        checks.append(('project-policy','ok' if (pr/'.codex-skillset.json').exists() else 'missing (allowed)'))
    for k,v in checks: print(f'{k}: {v}')
    return 1 if any(str(v).startswith('FAIL') for _,v in checks) else 0

def binding_stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')


def review_entry(i):
    e=catalog_index(strict=True)[i]
    binding.canonical_relative_path(e['deploy'].get('path'),allow_dot=True)
    binding.canonical_origin(e.get('source_url'))
    binding.catalog_digest(e)
    if e['invocation'] not in ('explicit','implicit'): raise RuntimeError('review requires an operational invocation projection')
    return e


def cmd_fetch(args):
    e=review_entry(args.id); origin=binding.canonical_origin(e['source_url'])
    if origin['kind']=='file': binding._local_transport(origin)
    with runtime_owner().session(create=True):
        ready_runtime_binding()
        if review_entry(args.id)!=e: raise RuntimeError('fetch catalog changed')
        repo,commit=binding.acquire_cache(SOURCES,origin)
        if review_entry(args.id)!=e: raise RuntimeError('fetch catalog changed')
        print(json.dumps({'source_id':args.id,'repo':origin['url'],'fetched_commit':commit,'cache':str(repo)}))


def cmd_review(args):
    resolver_require(type(args.approve) is bool,'review approval must be boolean')
    e=review_entry(args.id); origin=binding.canonical_origin(e['source_url'])
    binding.hex_digest(args.commit,40)
    with runtime_owner().session():
        ready_runtime_binding()
        if review_entry(args.id)!=e: raise RuntimeError('review catalog changed')
        repo,_=binding.acquire_cache(SOURCES,origin,args.commit)
        exported=binding.export_locked_tree(repo,args.commit,e['deploy']['path'],origin)
        artifact=binding.projected_inventory(exported.inventory,e['invocation'])
        candidate={'binding_version':1,'source_id':args.id,'catalog_sha256':binding.catalog_digest(e),
                   'origin':origin,'commit':args.commit,'source_tree_oid':exported.source_tree_oid,
                   'deploy_path':e['deploy']['path'],'source_tree_sha256':binding.digest('accp-source-tree-v1',exported.inventory),
                   'artifact_tree_sha256':binding.digest('accp-artifact-tree-v1',artifact),
                   'invocation':e['invocation'],'projection':binding.PROJECTION}
        ev={'schema_version':2,'candidate':candidate,'candidate_sha256':binding.digest('accp-candidate-v1',candidate),
            'source_inventory':exported.inventory,'artifact_inventory':artifact,'status':'approved' if args.approve else 'pending',
            'reviewer':'human-explicit' if args.approve else 'pending','reviewed_at':binding_stamp(),
            'notes':args.notes if args.notes is not None else '', 'executable_surface':list(exported.executable_paths)}
        data=binding.encode_evidence(ev)
        if review_entry(args.id)!=e: raise RuntimeError('review catalog changed before publication')
        ready_runtime_binding()
        binding.plain_path(EVIDENCE,True)
        binding.publish_bytes(evidence_path(args.id),data,replace=True)
        print(json.dumps({'evidence':str(evidence_path(args.id)),'projection':binding.PROJECTION,
                          'policy_replacement':binding.policy_bytes(e['invocation']).decode(),'record':ev},indent=2))


def cmd_pin(args):
    resolver_require(type(args.approve_partial) is bool and type(args.approve_high_risk) is bool,'pin approval flags must be boolean')
    e=review_entry(args.id); ep=binding.evidence_path(ROOT,args.id,forbidden_roots=(RUNTIME,))
    snapshot=binding.read_bound_record(ep); ev=binding.validate_evidence(snapshot.value)
    if ev['status']!='approved': raise RuntimeError('review evidence must be explicitly approved')
    b=ev['candidate']
    if (b['source_id']!=args.id or b['catalog_sha256']!=binding.catalog_digest(e) or
        b['origin']!=binding.canonical_origin(e['source_url']) or b['deploy_path']!=e['deploy']['path'] or
        b['invocation']!=e['invocation']): raise RuntimeError('review candidate != current catalog')
    old=binding.read_bound_record(LOCK,canonical=False)
    data=resolver_object(old.value,'lock',2); src=resolver_object(data.get('sources'),'lock.sources')
    for i,l in src.items(): validate_lock_fields(i,l); binding.validate_lock_record(l)
    record={'repo':b['origin']['url'],'commit':b['commit'],'deploy_path':b['deploy_path'],
            'evidence':f'audit/evidence/{args.id}.json','evidence_sha256':snapshot.sha256,
            'approval':{'partial_or_conditional':args.approve_partial,'high_risk':args.approve_high_risk,'approved_at':binding_stamp()},
            'binding':{'schema_version':1,'candidate_sha256':ev['candidate_sha256']}}
    binding.validate_lock_record(record,operational=True)
    if review_entry(args.id)!=e or binding.read_bound_record(ep)!=snapshot or binding.read_bound_record(LOCK,canonical=False)!=old:
        raise RuntimeError('pin inputs changed before publication')
    src[args.id]=record; data['generated_at']=binding_stamp()
    binding.publish_bytes(LOCK,binding.canonical_json(data)+b'\n',replace=True)
    print(f'pinned {args.id} -> {b["commit"]}')


def materialize_admission(ids,allow_partial):
    resolver_require(type(ids) is list,'materialize IDs must be a list')
    resolver_require(type(allow_partial) is bool,'allow_partial must be boolean')
    idx=catalog_index(strict=True); locks=lock_index(strict=True)
    ids=ids or sorted(locks)
    validate_managed_ids(ids); admitted={}
    for i in ids:
        if i not in locks: raise RuntimeError(f'{i}: not locked')
        resolver_require(i in idx,f'{i}: not in catalog')
        e=idx[i]; l=locks[i]; ev=require_operational_eligibility(i,e,l,allow_partial)
        if ev['candidate']['origin']['kind']=='file': binding._local_transport(ev['candidate']['origin'])
        admitted[i]=(e,l,ev)
    return admitted

def recheck_materialize(admitted,allow_partial):
    current=materialize_admission(list(admitted),allow_partial)
    resolver_require(current==admitted,'materialize admission records changed; retry explicitly')

def cmd_materialize(args):
    admitted=materialize_admission(args.id,args.allow_partial)
    if not admitted: return
    with runtime_owner().session(create=True):
        recheck_materialize(admitted,args.allow_partial)
        materialize_admitted(admitted,args.allow_partial)

def materialize_admitted(admitted,allow_partial):
    for i,(e,l,ev) in admitted.items():
        recheck_materialize(admitted,allow_partial)
        rb=ready_runtime_binding()
        dest=VAULT/i
        binding.plain_path(VAULT.parent,True)
        if os.path.lexists(VAULT): binding.plain_path(VAULT,True)
        if os.path.lexists(dest):
            binding.validate_vault_binding(dest,ev,l['evidence_sha256'],rb)
            # Same reviewed artifact is already present; do not delete/rewrite it.
            recheck_materialize(admitted,allow_partial)
            print(f'vaulted {i} (already current)'); continue
        repo=ensure_source_at_lock(i,e,l)
        recheck_materialize(admitted,allow_partial)
        exported=binding.export_locked_tree(repo,l['commit'],l['deploy_path'],ev['candidate']['origin'])
        if exported.source_tree_oid!=ev['candidate']['source_tree_oid'] or exported.inventory!=ev['source_inventory']:
            raise RuntimeError(f'{i}: reviewed raw source changed')
        inventory=binding.projected_inventory(exported.inventory,e['invocation'])
        if inventory!=ev['artifact_inventory']: raise RuntimeError(f'{i}: reviewed projection changed')
        if not os.path.lexists(VAULT): VAULT.mkdir()
        binding.plain_path(VAULT,True)
        stage=VAULT/f'.stage-{i}-{uuid.uuid4().hex}'; stage.mkdir()
        stage_id=binding.directory_identity(stage)
        payload=dict(exported.payload); payload['agents/openai.yaml']=binding.policy_bytes(e['invocation'])
        for r in inventory:
            target=stage/pathlib.Path(*r['path'].split('/'))
            if r['type']=='directory': target.mkdir()
            else:
                binding.publish_bytes(target,payload[r['path']],binding.MAX_FILE)
                if os.name!='nt': target.chmod(0o755 if r['path'] in exported.executable_paths and r['path']!='agents/openai.yaml' else 0o644)
        manifest={'schema_version':2,'source_id':i,'candidate_sha256':ev['candidate_sha256'],
                  'evidence_sha256':l['evidence_sha256'],'artifact_tree_sha256':ev['candidate']['artifact_tree_sha256'],
                  'invocation':e['invocation'],'projection':binding.PROJECTION,'runtime_binding':rb,'materialized_at':binding_stamp()}
        binding.validate_vault_manifest(manifest)
        binding.publish_bytes(stage/binding.MANIFEST,binding.canonical_json(manifest)+b'\n',binding.MAX_MANIFEST)
        manifest_snapshot=binding.read_bound_record(stage/binding.MANIFEST,binding.MAX_MANIFEST)
        if manifest_snapshot.value!=manifest: raise RuntimeError('staged manifest mismatch')
        if binding.inventory_tree(stage,vault=True)!=ev['artifact_inventory']: raise RuntimeError('staged artifact mismatch')
        recheck_materialize(admitted,allow_partial)
        if ready_runtime_binding()!=rb: raise RuntimeError('runtime binding changed before publication')
        binding.plain_path(VAULT,True)
        if binding.inventory_tree(stage,vault=True)!=ev['artifact_inventory']: raise RuntimeError('artifact drift before publication')
        if (binding.directory_identity(stage)!=stage_id or
            binding.read_bound_record(stage/binding.MANIFEST,binding.MAX_MANIFEST)!=manifest_snapshot):
            raise RuntimeError('stage identity/manifest drift before publication')
        if os.path.lexists(dest): raise RuntimeError('Vault publication collision')
        os.rename(stage,dest)
        binding.validate_vault_binding(dest,ev,l['evidence_sha256'],ready_runtime_binding())
        print(f'vaulted {i}')


def project_policy(project, *, strict=False):
    p=pathlib.Path(project).resolve()/'.codex-skillset.json'
    if strict:
        # lexists() hides access/I/O errors as absence, which would drop policy.
        try: p.lstat()
        except FileNotFoundError: return None
        return readj(p,strict=True)
    return readj(p) if p.exists() else None

def resolver_require(condition, message):
    if not condition: raise RuntimeError(message)

def resolver_object(value, label, version=None):
    resolver_require(type(value) is dict,f'{label} must be an object')
    if version is not None:
        resolver_require(type(value.get('schema_version')) is int and value['schema_version']==version,
                         f'unsupported {label} schema_version')
    return value

def resolver_strings(value, label, provider_ids=False):
    resolver_require(type(value) is list and all(type(v) is str and bool(v.strip()) for v in value),
                     f'{label} must be a list of nonempty strings')
    if provider_ids: validate_managed_ids(list(dict.fromkeys(value)))
    return frozenset(value)

def normalize_resolver_inputs(mode, project, allow_partial=False, *, documents=None):
    """Read once; validate representations before evaluating operational eligibility."""
    resolver_require(type(mode) is str and bool(mode.strip()),'invalid operational mode')
    resolver_require(type(allow_partial) is bool,'allow_partial must be boolean')
    idx=catalog_index(strict=True,record=documents['catalog'] if documents else None)
    locks=lock_index(strict=True,record=documents['lock'] if documents else None)
    ops=resolver_object(documents['modes'] if documents else readj(OP_MODES,strict=True),'operational modes',1)
    modes=resolver_object(ops.get('modes'),'operational modes.modes')
    for name,spec in modes.items():
        resolver_require(type(name) is str and bool(name.strip()),'invalid mode name')
        resolver_object(spec,f'mode {name}')
        refs=resolver_strings(spec.get('providers'),f'mode {name}.providers',True)
        resolver_require(refs<=idx.keys(),f'mode {name}: unknown provider IDs {sorted(refs-idx.keys())}')
    resolver_require(mode in modes,f'{mode}: not an operational mode; evaluation modes cannot activate')
    for i,lock in locks.items():
        resolver_require(i in idx,f'lock references unknown provider: {i}')
    conflict=resolver_object(documents['conflicts'] if documents else readj(CONFLICTS,strict=True),'conflicts',2)
    groups=resolver_object(conflict.get('groups'),'conflicts.groups'); limits={}
    for name,spec in groups.items():
        resolver_require(type(name) is str and bool(name.strip()),'invalid conflict group name')
        resolver_object(spec,f'conflict {name}')
        maximum=spec.get('max_active',1)
        resolver_require(type(maximum) is int and maximum>=0,f'conflict {name}: invalid max_active')
        limits[name]=maximum
    pol=documents['policy'] if documents else project_policy(project,strict=True)
    if pol is None: pol={'schema_version':1}
    resolver_object(pol,'project policy',1)
    allowed_fields={'schema_version','allowed_operational_modes','default_operational_mode',
                    'include','exclude','capabilities','project_type'}
    resolver_require(not set(pol)-allowed_fields,
                     'unknown project policy fields (use allowed_operational_modes/default_operational_mode): '
                     +str(sorted(set(pol)-allowed_fields)))
    if 'allowed_operational_modes' in pol:
        allowed=resolver_strings(pol['allowed_operational_modes'],'allowed_operational_modes')
        resolver_require(mode in allowed,f'{mode}: forbidden by project policy allowed_operational_modes')
    if 'default_operational_mode' in pol:
        resolver_require(type(pol['default_operational_mode']) is str and bool(pol['default_operational_mode'].strip()),
                         'invalid default_operational_mode')
    if 'project_type' in pol: resolver_strings(pol['project_type'],'project_type')
    include=resolver_strings(pol.get('include',[]),'include',True)
    exclude=resolver_strings(pol.get('exclude',[]),'exclude',True)
    resolver_require(include<=idx.keys(),f'include: unknown provider IDs {sorted(include-idx.keys())}')
    capabilities=resolver_object(pol.get('capabilities',{}),'policy capabilities')
    resolver_require(not set(capabilities)-{'require','prefer','forbid'},'unknown policy capability fields')
    needs={name:resolver_strings(capabilities.get(name,[]),f'capabilities.{name}')
           for name in ('require','prefer','forbid')}
    resolver_require(not needs['require']&needs['forbid'],'required capabilities intersect forbid')
    seeds=(set(modes[mode]['providers'])|include)-exclude
    return dict(idx=idx,locks=locks,exclude=exclude,limits=limits,seeds=frozenset(seeds),
                allow_partial=allow_partial,**needs)

def provider_eligibility(i, context):
    """One predicate for seeds, expansion and final gate. None means eligible.

    Expected external/approval denials exclude automatic candidates; unexpected
    errors propagate. Evidence binding is unchanged; operational policy is shared.
    """
    idx=context['idx']
    if i not in idx: return 'unknown provider'
    if i in context['exclude']: return 'excluded by project policy'
    e=idx[i]
    if set(e['capabilities'])&context['forbid']: return 'violates capabilities.forbid'
    if i not in context['locks']: return 'operational provider is not locked'
    lock=context['locks'][i]
    try:
        require_operational_eligibility(i,e,lock,context['allow_partial'])
    except (RuntimeError,OSError,ValueError) as exc:
        return f'operational eligibility denied: {exc}'
    return None

def selection_conflicts(selected, context):
    groups={}
    for i in sorted(set(selected)):
        group=context['idx'][i]['conflict_group']
        if group is not None: groups.setdefault(group,[]).append(i)
    for group,members in sorted(groups.items()):
        if len(members)>context['limits'].get(group,1): return f'conflict {group}: {members}'
    return None

def resolver_coverage(selected, context):
    return set().union(*(context['idx'][i]['capabilities'] for i in selected))

def validate_resolved_plan(selected, context):
    """No caller can return a plan based solely on incremental candidate checks."""
    resolver_require(type(selected) in (list,tuple,set,frozenset),'invalid selected IDs')
    selected=list(selected)
    validate_managed_ids(selected)  # duplicate references are a final-gate error
    resolver_require(context['seeds']<=set(selected),'final selection omits explicit seed providers')
    warnings=[]
    for i in sorted(selected):
        reason=provider_eligibility(i,context)
        resolver_require(reason is None,f'{i}: {reason}')
        creds=sorted(set(context['idx'][i]['runtime']['credentials']))
        if creds: warnings.append(f'{i}: credential requirements (not verified): {creds}')
    covered=resolver_coverage(selected,context)
    resolver_require(not set(selected)&context['exclude'],'final selection includes excluded IDs')
    resolver_require(not covered&context['forbid'],'final selection violates capabilities.forbid')
    resolver_require(context['require']<=covered,
                     f'unsatisfied required capabilities: {sorted(context["require"]-covered)}')
    conflict=selection_conflicts(selected,context)
    resolver_require(conflict is None,conflict)
    return covered,warnings

def resolve_with_context(mode,project,allow_partial=False, *, documents=None):
    context=normalize_resolver_inputs(mode,project,allow_partial,documents=documents)
    selected=set(context['seeds']); warnings=[]
    for i in sorted(selected):
        reason=provider_eligibility(i,context)
        resolver_require(reason is None,f'{i}: {reason}')
    conflict=selection_conflicts(selected,context)
    resolver_require(conflict is None,conflict)
    for kind in ('require','prefer'):
        for capability in sorted(context[kind]):
            if capability in resolver_coverage(selected,context): continue
            if capability in context['forbid']:
                warnings.append(f'preferred capability {capability!r} skipped: forbidden'); continue
            candidates=[]; denied=[]
            for i,e in sorted(context['idx'].items()):
                if capability not in e['capabilities']: continue
                reason=provider_eligibility(i,context)
                if reason is None: reason=selection_conflicts(selected|{i},context)
                if reason is None: candidates.append(i)
                else: denied.append(f'{i}: {reason}')
            if len(candidates)==1:
                selected.add(candidates[0])
            else:
                detail=f'capability {capability!r} has {len(candidates)} eligible providers: {candidates}; denied: {denied}'
                if kind=='require': raise RuntimeError('required '+detail)
                warnings.append('preferred '+detail+'; skipped')
    selected=sorted(selected)
    covered,final_warnings=validate_resolved_plan(selected,context)
    return {'schema_version':1,'generated_at':now(),'mode':mode,'project':str(pathlib.Path(project).resolve()),
            'providers':selected,'capabilities_covered':sorted(covered),'warnings':sorted(set(warnings+final_warnings))},context

def resolve_plan(mode,project,allow_partial=False):
    return resolve_with_context(mode,project,allow_partial)[0]

def activation_admission(args,plan, *, documents=None):
    """A supplied plan is a request, never authority. Reuse the actual resolver."""
    resolver_object(plan,'activation plan',1)
    resolver_require(plan.get('mode')==args.mode,'activation plan mode mismatch')
    resolver_require(plan.get('project')==str(pathlib.Path(args.project).resolve()),'activation plan project mismatch')
    resolver_require(type(plan.get('providers')) is list,'activation plan providers must be a list')
    validate_managed_ids(plan['providers'])
    fresh,context=resolve_with_context(args.mode,args.project,args.allow_partial,documents=documents)
    resolver_require(sorted(plan['providers'])==fresh['providers'],'activation selection changed; resolve again')
    validate_resolved_plan(plan['providers'],context)
    return fresh,context

def validate_vault(i,l):
    ev=evidence_ok(i,l,strict=True)
    d=VAULT/i
    return d,binding.validate_vault_binding(d,ev,l['evidence_sha256'],ready_runtime_binding())


def acquire_lock(authority):
    path=authority.legacy_lock
    # Legacy activation cannot participate in an M2a transaction. Refuse it once
    # the new lifecycle boundary exists, including the post-open race window.
    def lifecycle_guard():
        authority.require_legacy_activation_safe()
        if any(os.path.lexists(path.parent/name) for name in ('.accp-lifecycle.lock','.accp-transaction.json')):
            raise RuntimeError('Active Set uses transactional lifecycle; activation requires later integration')
    lifecycle_guard()
    path.parent.mkdir(parents=True,exist_ok=True)
    try: fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY)
    except FileExistsError: raise RuntimeError(f'activation lock already held: {path}')
    try:
        lifecycle_guard()
        os.write(fd,f'{os.getpid()} {now()}\n'.encode())
    except Exception:
        os.close(fd); path.unlink(); raise
    os.close(fd); return path

def active_paths(project,scope):
    assert_plain_path(pathlib.Path(project).absolute())
    pr=pathlib.Path(project).resolve()
    if scope=='project': base=pr/'.agents'
    else: base=pathlib.Path(os.environ.get('ACCP_USER_SCOPE_ROOT',pathlib.Path.home()/'.agents')).absolute()
    assert_plain_path(base)
    return base,base/'skills',base/'install-manifest.json',base/'active-state.json',base/'.accp-activate.lock'

def assert_plain_path(path):
    """Reject redirection before resolve(), including dangling links and junctions.

    The operator must exclude concurrent untrusted filesystem writers. These
    checks are not a handle-based defence against hostile ancestor replacement.
    """
    path=pathlib.Path(path).absolute()
    for p in (*reversed(path.parents),path):
        try: info=p.lstat()
        except FileNotFoundError: continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError(f'linked/reparse path refused: {p}')
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError(f'non-regular path refused: {p}')

def assert_plain_tree(path):
    assert_plain_path(path)
    if path.is_dir():
        for child in path.iterdir(): assert_plain_tree(child)

def validate_managed_ids(ids):
    if not isinstance(ids,list): raise RuntimeError('managed_ids must be a list')
    seen=set()
    for i in ids:
        if (not isinstance(i,str) or not ID_RE.fullmatch(i) or i.endswith('.')
                or re.fullmatch(r'(con|prn|aux|nul|com[1-9]|lpt[1-9])',i.split('.')[0])):
            raise RuntimeError(f'invalid managed id: {i!r}')
        if i in seen: raise RuntimeError(f'duplicate managed id: {i}')
        seen.add(i)
    return ids

def managed_child(parent,i):
    validate_managed_ids([i])
    assert_plain_path(parent)
    child=parent/i
    assert_plain_path(child)
    if child.resolve().parent!=parent.resolve():
        raise RuntimeError(f'managed path is not an immediate child: {i}')
    if child.exists() and not child.is_dir():
        raise RuntimeError(f'managed skill is not a directory: {i}')
    return child

def read_install_manifest(base,skills,im,state,project,scope):
    """A manifest grants authority only over named immediate children of skills.

    Binding fields prevent accidental cross-install use; they are not signatures
    and cannot authenticate ownership against a writer of the project itself.
    """
    for p in (base,skills,im,state): assert_plain_path(p)
    if skills.exists() and not skills.is_dir(): raise RuntimeError('skills must be a directory')
    if not im.exists(): manifest={'managed_ids':[]}
    else:
        def unique_object(pairs):
            obj={}
            for k,v in pairs:
                if k in obj: raise RuntimeError(f'duplicate manifest field: {k}')
                obj[k]=v
            return obj
        manifest=json.loads(im.read_text(encoding='utf-8-sig'),object_pairs_hook=unique_object)
        if not isinstance(manifest,dict): raise RuntimeError('install manifest must be an object')
        if type(manifest.get('schema_version')) is not int or manifest['schema_version']!=1:
            raise RuntimeError('unsupported install manifest schema')
        if manifest.get('scope')!=scope: raise RuntimeError('install manifest scope mismatch')
        for field,expected in [('control_plane_path',ROOT),('project',pathlib.Path(project).resolve())]:
            value=manifest.get(field)
            if not isinstance(value,str) or not pathlib.Path(value).is_absolute() or pathlib.Path(value)!=expected:
                raise RuntimeError(f'install manifest {field} mismatch')
    ids=validate_managed_ids(manifest.get('managed_ids'))
    for i in ids: managed_child(skills,i)
    # The whole directory is copied and the backup recursively removed, so even
    # unmanaged descendants must not redirect traversal outside this boundary.
    assert_plain_tree(skills)
    return manifest

def remove_managed_children(stage,ids):
    targets=[managed_child(stage,i) for i in validate_managed_ids(ids)]
    for p in targets: assert_plain_tree(p)
    for p in targets:
        if p.exists(): shutil.rmtree(p)

def cmd_resolve(args):
    print(json.dumps({'report_kind':'resolution_only','lifecycle_assessed':False,
                     'plan':resolve_plan(args.mode,args.project,args.allow_partial)},indent=2))
_activation_attempts={}

def reader_owner(args):
    user_base=os.environ.get('ACCP_USER_SCOPE_ROOT',str(pathlib.Path.home()/'.agents')) if args.scope=='user' else None
    return JournalAuthority(ROOT,args.project,args.scope,user_base)

def reader_preflight(args):
    return read_install_manifest(*active_paths(args.project,args.scope)[:4],args.project,args.scope)

def emit_reader(result):
    print(json.dumps(result,indent=2))
    return JournalAuthority.reader_exit(result)

def runtime_read_check(owner):
    # Read-only consumers never create/acquire the F02 mutex (or invert lock order).
    def no_writer():
        try: owner.lock_path.lstat()
        except FileNotFoundError: return
        raise RuntimeError('runtime writer present; retry preview')
    no_writer()
    receipt=owner.validate()
    resolver_require(receipt is not None and receipt['state']=='ready','owned ready runtime required')
    no_writer()
    return receipt

def preview_activation(args,plan=None,paths=None):
    owner=reader_owner(args)
    def admission(held):
        api=sys.modules[__name__]; nonce=str(uuid.uuid4())
        proposed=resolve_plan(args.mode,args.project,args.allow_partial) if plan is None else plan
        fresh,context,proof,actual=activation.capture(api,args,proposed,nonce)
        resolver_require(paths is None or tuple(paths)==tuple(actual),'activation path mismatch')
        old=reader_preflight(args)
        held.activation_snapshot(sorted(old['managed_ids']),sorted(fresh['providers']))
        anchors=activation.anchors(actual[0])
        runtime=runtime_owner(args.project) if fresh['providers'] else None
        receipt=runtime_read_check(runtime) if runtime else None
        runtime_binding,prepared,observed=activation.observe_vault(api,fresh,context)
        resolver_require(activation.capture(api,args,proposed,nonce)[2]==proof,'activation preview context drift')
        resolver_require(activation.observe_vault(api,fresh,context)==(runtime_binding,prepared,observed),
                         'activation preview Vault drift')
        if runtime:
            resolver_require(runtime_read_check(runtime)==receipt,'activation preview runtime drift')
        resolver_require(activation.capture(api,args,proposed,nonce)[2]==proof,'activation preview final context drift')
        activation.check_anchors(anchors)
        resolver_require(reader_owner(args).bindings()==held.bindings(),'activation preview authority drift')
        return {'plan':fresh,'target':str(actual[1])}
    return emit_reader(owner.reader_report(lambda:reader_preflight(args),
        lambda:assert_plain_tree(active_paths(args.project,args.scope)[1]),operation='activate',admission=admission))

def cmd_activate(args):
    if args.dry_run: return preview_activation(args)
    plan=resolve_plan(args.mode,args.project,args.allow_partial)
    plan,_=activation_admission(args,plan)
    base,skills,im_path,state_path,mutex=active_paths(args.project,args.scope)
    validate_managed_ids(plan['providers'])
    read_install_manifest(base,skills,im_path,state_path,args.project,args.scope)
    # Empty plans consume no Vault. Hold the runtime mutex through staging for
    # nonempty plans so cooperating uninstall cannot remove their source midway.
    attempt=activation.ActivationAttempt(sys.modules[__name__],args,plan)
    _activation_attempts[attempt]=attempt
    try:
        context=runtime_owner(args.project).session(dry_run=args.dry_run) if plan['providers'] else nullcontext()
        with context:
            attempt.runtime_held=True
            return activate_plan(args,plan,attempt.paths,attempt=attempt)
    finally:
        attempt.phase='expired'; attempt.runtime_held=False
        _activation_attempts.pop(attempt,None)

def activate_plan(args,plan,paths,*,attempt=None):
    if args.dry_run: return preview_activation(args,plan,paths)
    resolver_require(type(attempt) is activation.ActivationAttempt and
                     _activation_attempts.get(attempt) is attempt and attempt.phase=='created',
                     'current activation attempt required')
    attempt.phase='running'
    base,skills,im_path,state_path,mutex=paths
    result=attempt.authority.activate(attempt,args,plan,paths)
    print(json.dumps(result,indent=2))

def cmd_status(args):
    return emit_reader(reader_owner(args).reader_report(lambda:reader_preflight(args),
        lambda:assert_plain_tree(active_paths(args.project,args.scope)[1])))
def cmd_deactivate(args):
    base,skills,im,state,mutex=active_paths(args.project,args.scope)
    user_base=os.environ.get('ACCP_USER_SCOPE_ROOT',str(pathlib.Path.home()/'.agents')) if args.scope=='user' else None
    owner=JournalAuthority(ROOT,args.project,args.scope,user_base)
    stamp=now()
    new_im={'schema_version':1,'control_plane_path':str(ROOT),'scope':args.scope,'project':str(pathlib.Path(args.project).resolve()),'managed_ids':[],'deactivated_at':stamp}
    new_state={'schema_version':1,'control_plane_path':str(ROOT),'active_ids':[],'deactivated_at':stamp}
    result=owner.deactivate(lambda: read_install_manifest(base,skills,im,state,args.project,args.scope),
                            (json.dumps(new_im)+'\n').encode('utf-8'),
                            (json.dumps(new_state)+'\n').encode('utf-8'),dry_run=args.dry_run)
    print(json.dumps(result,indent=2))
    if args.dry_run: return JournalAuthority.reader_exit(result)


def cmd_recover(args):
    base,skills,im,state,mutex=active_paths(args.project,args.scope)
    user_base=os.environ.get('ACCP_USER_SCOPE_ROOT',str(pathlib.Path.home()/'.agents')) if args.scope=='user' else None
    owner=JournalAuthority(ROOT,args.project,args.scope,user_base)
    operation=owner.cleanup if getattr(args,'cleanup',False) else owner.recover
    result=operation(lambda: read_install_manifest(base,skills,im,state,args.project,args.scope),
                         lambda: assert_plain_tree(skills),dry_run=args.dry_run)
    print(json.dumps(result,indent=2))
    if args.dry_run: return JournalAuthority.reader_exit(result)

def cmd_audit(args):
    owner=runtime_owner(); receipt=runtime_read_check(owner)
    def observe():
        records=tuple(activation.file_observation(p) for p in (CATALOG,LOCK))
        idx=catalog_index(strict=True); locks=lock_index(strict=True); rows=[]; proofs=[]
        tree=activation.tree_observation(VAULT)
        for i,l in locks.items():
            e=idx.get(i); status='reviewed_binding'; vault='absent'
            try:
                proofs.append(evidence_ok(i,l))
                if os.path.lexists(VAULT/i): validate_vault(i,l); vault='binding_validated'
            except (RuntimeError,ValueError,OSError) as ex:
                status=f'INVALID: {ex}'
            rows.append({'id':i,'adoption':e.get('adoption') if e else None,
                         'trust':e.get('trust') if e else None,'risk':e.get('risk') if e else None,
                         'lock':status,'vault':vault})
        resolver_require(tuple(activation.file_observation(p) for p in (CATALOG,LOCK))==records,
                         'runtime audit catalog/lock drift')
        resolver_require(activation.tree_observation(VAULT)==tree,'runtime audit Vault drift')
        return records,tree,proofs,rows
    observed=observe()
    resolver_require(observe()==observed and runtime_read_check(owner)==receipt,'runtime audit drift')
    print(json.dumps({'report_kind':'runtime_audit','lifecycle_assessed':False,
                     'admission_authority':False,'reservation':False,'rows':observed[-1]},indent=2))
    return 2 if any(row['lock'].startswith('INVALID:') for row in observed[-1]) else 0

@runtime_operation(create=True)
def cmd_bootstrap(args):
    # Deliberately copy only when destination absent unless --replace-agents.
    home=pathlib.Path(os.environ.get('ACCP_USER_HOME',pathlib.Path.home())).resolve(); agents=home/'.codex'/'agents'
    if not args.dry_run: agents.mkdir(parents=True,exist_ok=True)
    installed=[]; skipped=[]
    for src in (ROOT/'.codex'/'agents').glob('*.toml'):
        dst=agents/src.name
        if dst.exists() and not args.replace_agents: skipped.append(str(dst)); continue
        if args.dry_run: installed.append(str(dst)); continue
        shutil.copy2(src,dst); installed.append(str(dst))
    m={'schema_version':1,'control_plane_path':str(ROOT),'personal_agents_installed':installed,'personal_agents_skipped':skipped,'bootstrap_at':now()}
    if not args.dry_run: writej(GLOBAL_INSTALL,m)
    print(json.dumps({'dry_run':args.dry_run,'report_kind':'bootstrap_proposal' if args.dry_run else 'bootstrap',
                     'lifecycle_assessed':False,'reservation':False,**m},indent=2))
def cmd_uninstall(args):
    plan=runtime_owner(getattr(args,'project',None)).uninstall(yes=args.yes,dry_run=args.dry_run)
    if args.dry_run: plan.update(report_kind='runtime_uninstall_proposal',lifecycle_assessed=False,reservation=False)
    print(json.dumps(plan,indent=2))

def parser():
    p=argparse.ArgumentParser(); sp=p.add_subparsers(dest='cmd',required=True)
    q=sp.add_parser('doctor'); q.add_argument('--project'); q.set_defaults(fn=cmd_doctor)
    q=sp.add_parser('fetch'); q.add_argument('id'); q.set_defaults(fn=cmd_fetch)
    q=sp.add_parser('review'); q.add_argument('id'); q.add_argument('--commit'); q.add_argument('--approve',action='store_true'); q.add_argument('--notes'); q.set_defaults(fn=cmd_review)
    q=sp.add_parser('pin'); q.add_argument('id'); q.add_argument('--approve-partial',action='store_true'); q.add_argument('--approve-high-risk',action='store_true'); q.set_defaults(fn=cmd_pin)
    q=sp.add_parser('materialize'); q.add_argument('id',nargs='*'); q.add_argument('--allow-partial',action='store_true'); q.set_defaults(fn=cmd_materialize)
    for name,fn in [('resolve',cmd_resolve),('activate',cmd_activate)]:
        q=sp.add_parser(name); q.add_argument('--mode',required=True); q.add_argument('--project',default='.'); q.add_argument('--allow-partial',action='store_true');
        if name=='activate': q.add_argument('--scope',choices=['project','user'],default='project'); q.add_argument('--dry-run',action='store_true')
        q.set_defaults(fn=fn)
    for name,fn in [('status',cmd_status),('deactivate',cmd_deactivate)]:
        q=sp.add_parser(name); q.add_argument('--project',default='.'); q.add_argument('--scope',choices=['project','user'],default='project');
        if name=='deactivate': q.add_argument('--dry-run',action='store_true')
        q.set_defaults(fn=fn)
    q=sp.add_parser('recover'); q.add_argument('--project',required=True); q.add_argument('--scope',choices=['project','user'],default='project'); q.add_argument('--dry-run',action='store_true'); q.add_argument('--cleanup',action='store_true'); q.set_defaults(fn=cmd_recover)
    q=sp.add_parser('audit'); q.set_defaults(fn=cmd_audit)
    q=sp.add_parser('bootstrap'); q.add_argument('--replace-agents',action='store_true'); q.add_argument('--dry-run',action='store_true'); q.set_defaults(fn=cmd_bootstrap)
    q=sp.add_parser('uninstall'); q.add_argument('--yes',action='store_true'); q.add_argument('--dry-run',action='store_true'); q.add_argument('--project'); q.set_defaults(fn=cmd_uninstall)
    return p

def main():
    args=parser().parse_args()
    try: return args.fn(args) or 0
    except Exception as ex:
        print(f'ERROR: {ex}',file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main())
