"""Bounded observations for call-local activation proofs, not persisted authority.

All paths come from the control plane. No proof loader, mutation or replay API.
Cooperating writers are required, as for the existing F01/F02 boundaries.
"""
import hashlib
import os
import pathlib
import stat
import uuid

import artifact_binding as binding


def canonical_path(path):
    return os.path.normcase(str(binding._absolute(path)))


def anchors(path):
    path = binding._absolute(path)
    result = {}
    for item in (*reversed(path.parents), path):
        try:
            result[str(item)] = binding.directory_identity(item)
        except FileNotFoundError:
            result[str(item)] = None
    return result


def check_anchors(expected, created=False):
    current = {}
    for name, identity in expected.items():
        path = pathlib.Path(name)
        try:
            value = binding.directory_identity(path)
        except FileNotFoundError:
            value = None
        binding.require(value == identity or (created and identity is None and value is not None),
                        'activation ancestor identity changed')
        current[name] = value
    return current


def file_observation(path, limit=binding.MAX_RECORD):
    try:
        data, identity = binding._read_file(path, limit)
    except FileNotFoundError:
        return None
    return {'identity': binding.observed_stamp(identity),
            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def tree_observation(root):
    """Include every live/unmanaged byte and identity, including Vault metadata.

    Do not use payload name exclusions for an Active Set. File reads retain the
    same plain-file, link, reparse, stream and bounded read checks as bindings.
    """
    root = binding._absolute(root)
    if not os.path.lexists(root):
        return None
    result, seen, total = [], [], 0

    def visit(path):
        nonlocal total
        _, info = binding.plain_path(path)
        binding._streams(path)
        binding.require(len(result) < binding.MAX_ENTRIES, 'activation tree count limit')
        row = {'path': path.relative_to(root).as_posix(), 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISDIR(info.st_mode):
            identity = binding.directory_identity(path)
            row.update(type='directory', identity=identity)
            result.append(row)
            for child in sorted(path.iterdir(), key=lambda item: item.name.encode('utf-8')):
                visit(child)
            binding.require(binding.directory_identity(path) == identity, 'activation directory replaced')
        else:
            observation = file_observation(path, binding.MAX_FILE)
            binding.require(observation is not None, 'activation file disappeared')
            total += observation['size']
            binding.require(total <= binding.MAX_PAYLOAD, 'activation tree byte limit')
            row.update(type='file', **observation)
            result.append(row)
        seen.append((path, binding._stamp(info)))

    visit(root)
    for path, identity in seen:
        binding.require(binding._stamp(binding.plain_path(path)[1]) == identity, 'activation tree changed during read')
    return result


def content_rows(observation, excluded=()):
    return [{key: value for key, value in row.items() if key != 'identity'}
            for row in observation or [] if row['path'] != '.' and row['path'].split('/')[0] not in excluded]


def transaction_digest(label, value):
    """Activation-only domains using C1; do not expand artifact authority domains."""
    binding.require(type(label) is str and label in ('accp-activation-child-v1',
        'accp-activation-unmanaged-v1', 'accp-activation-context-v1'), 'unknown transaction digest domain')
    return hashlib.sha256(label.encode('ascii') + b'\0' + binding.canonical_json(value)).hexdigest()


UNMANAGED_DIGEST_V1 = 1
UNMANAGED_DIGEST_V2 = 2

# The child-observation digest (the persisted `observation_sha256` of every
# old_children/new_children entry) is a SECOND, independent versioned domain.
# It crosses the same process/version boundary as the unmanaged digest and is
# recomputed on the forward, rollback, terminal and non-terminal paths, so it
# needs its own marker. Neither version is ever inferred from the other.
OBSERVATION_DIGEST_V1 = 1
OBSERVATION_DIGEST_V2 = 2


def legacy_file_identities(rows):
    """Re-encode file observations into the legacy integer identity encoding.

    Only files changed representation when the stamp encoding was versioned;
    directory identities were already canonical text.
    """
    return [dict(row, identity=binding.legacy_observed_stamp(row['identity']))
            if row['type'] == 'file' else row for row in rows or []]


def unmanaged_observation(rows, owned, version):
    """Keep identities as well as bytes; exclude only named immediate children.

    `version` selects the observation encoding of the digest:

      1  the legacy integer encoding, retained so a journal written before the
         version-2 stamp encoding can still be validated on this volume;
      2  the canonical decimal-string encoding (binding.observed_stamp).

    The caller must take the version from the journal record. This function has no
    fallback between the two: an unknown version is refused, and the caller must
    not retry a version-2 mismatch as version 1.
    """
    binding.require(type(version) is int and version in (UNMANAGED_DIGEST_V1, UNMANAGED_DIGEST_V2),
                    'unknown unmanaged digest version')
    selected = [row for row in rows or []
                if row['path'] != '.' and row['path'].split('/')[0] not in owned]
    if version == UNMANAGED_DIGEST_V1:
        selected = legacy_file_identities(selected)
    return transaction_digest('accp-activation-unmanaged-v1', selected)


def child_observation(rows, version):
    """Digest one child observation under an explicit encoding version.

    This is the value persisted as `observation_sha256` in every
    old_children/new_children entry, and it is recomputed from live data on the
    forward, rollback, terminal and non-terminal paths. `version` must come from
    the journal record; an unknown version is refused and there is deliberately
    no fallback -- a version-2 mismatch must never be retried as version 1, and a
    version-1 mismatch must never be retried as version 2.
    """
    binding.require(type(version) is int
                    and version in (OBSERVATION_DIGEST_V1, OBSERVATION_DIGEST_V2),
                    'unknown observation digest version')
    selected = legacy_file_identities(rows) if version == OBSERVATION_DIGEST_V1 else rows
    return transaction_digest('accp-activation-child-v1', selected)


def child_rows(path):
    """Observation rows of one transaction child; never grants mutation authority."""
    rows = tree_observation(path)
    binding.require(rows is not None and rows[0]['type'] == 'directory',
                    'transaction child directory missing')
    return rows


def transaction_observation(path, version=OBSERVATION_DIGEST_V2):
    """Read-only, rename-stable observation; never grants mutation authority."""
    return child_observation(child_rows(path), version)


def request(api, args):
    binding.require(type(args.scope) is str and args.scope in ('project','user'), 'invalid activation scope')
    binding.require(type(args.dry_run) is bool and type(args.allow_partial) is bool, 'activation flags must be boolean')
    binding.require(type(args.project) is str, 'activation project must be a string')
    spelling = pathlib.PureWindowsPath(args.project)
    binding.require('..' not in spelling.parts and not args.project.startswith(('\\\\','//')) and
                    not (spelling.drive and not spelling.is_absolute()), 'unsafe activation project spelling')
    project=pathlib.Path(args.project).absolute()
    binding.plain_path(project,True)
    if args.scope == 'user':
        # Validate the original override before active_paths makes it absolute.
        binding._absolute(os.environ.get('ACCP_USER_SCOPE_ROOT',str(pathlib.Path.home()/'.agents')))
    paths=api.active_paths(args.project,args.scope)
    return {'mode':args.mode,'project':canonical_path(project),'scope':args.scope,
            'allow_partial':args.allow_partial,'dry_run':args.dry_run,
            'paths':[canonical_path(path) for path in paths]},paths


def capture(api,args,plan,nonce):
    invocation,paths=request(api,args)
    project=pathlib.Path(invocation['project'])
    checkout_identity=binding.directory_identity(api.ROOT)
    project_identity=binding.directory_identity(project)
    sources={'catalog':api.ROOT/'registry/catalog.json','lock':api.ROOT/'lock/sources.lock.json',
             'modes':api.ROOT/'modes/operational-modes.json','conflicts':api.ROOT/'registry/conflict-groups.json',
             'policy':project/'.codex-skillset.json'}
    snapshots={}; documents={}
    for name,path in sources.items():
        try: snap=binding.read_bound_record(path,canonical=False)
        except FileNotFoundError:
            if name!='policy': raise
            snap=None
        snapshots[name]=snap; documents[name]=None if snap is None else snap.value
    fresh,context=api.activation_admission(args,plan,documents=documents)
    records={}
    for ident in fresh['providers']:
        lock=context['locks'][ident]
        evidence=binding.load_review_binding(api.ROOT,ident,context['idx'][ident],lock,
            forbidden_roots=(api.RUNTIME,project,api.ROOT/'.local/active-transactions'))
        records[ident]={'candidate':evidence.value['candidate_sha256'],'evidence':evidence.sha256,
                       'identity':binding.observed_stamp(evidence.identity),'lock':binding.digest('accp-lock-record-v1',lock)}
    for name,path in sources.items():
        if snapshots[name] is None: binding.require(not os.path.lexists(path),'activation policy appeared')
        else: binding.require(binding.read_bound_record(path,canonical=False)==snapshots[name], 'activation document drift during capture')
    proof={'version':1,'attempt':nonce,'request':invocation,
           'checkout':canonical_path(api.ROOT),'checkout_identity':checkout_identity,
           'project_identity':project_identity,'providers':fresh['providers'],'records':records,
           'documents':{name:None if snap is None else {'path':canonical_path(sources[name]),
               'identity':binding.observed_stamp(snap.identity),'digest':binding.digest('accp-context-v1',snap.value)}
               for name,snap in snapshots.items()}}
    binding.require(binding.directory_identity(api.ROOT)==checkout_identity and
                    binding.directory_identity(project)==project_identity, 'activation context directory replaced')
    return fresh,context,binding.canonical_json(proof),paths


def live_observation(paths):
    """Raw bounded observation, not a committed-generation or reader authority."""
    _,skills,manifest,state,_=paths
    return {'tree':tree_observation(skills),'manifest':file_observation(manifest),'state':file_observation(state)}


def observe_vault(api,plan,context):
    """Pure current binding observation; grants no attempt or mutation authority."""
    prepared={}; observed={}; runtime=None
    if plan['providers']:
        runtime=api.ready_runtime_binding()
        for ident in plan['providers']:
            prepared[ident]=api.validate_vault(ident,context['locks'][ident])[0]
            observed[ident]=tree_observation(prepared[ident])
    return runtime,prepared,observed


class ActivationAttempt:
    """Internal, call-local proof. CLI accepts no token or serialized proof.

    accp's private registry issues/retires these only within cmd_activate. This
    does not defend against arbitrary Python execution in the trusted process.
    """
    def __init__(self,api,args,plan):
        self.api=api; self.nonce=str(uuid.uuid4()); self.phase='created'; self.runtime_held=False
        self.plan,_,self.proof,self.paths=capture(api,args,plan,self.nonce)
        self.request,_=request(api,args)
        self.anchors=anchors(self.paths[0]); self.live=live_observation(self.paths)
        user_base=os.environ.get('ACCP_USER_SCOPE_ROOT',str(pathlib.Path.home()/'.agents')) if args.scope=='user' else None
        self.authority=api.JournalAuthority(api.ROOT,pathlib.Path(args.project).absolute(),args.scope,user_base)
        self.vault=None; self.lock=None; self.stage=None; self.stage_id=None
        self.authority.require_no_transaction()
        old=api.read_install_manifest(*self.paths[:4],args.project,args.scope)
        self.authority.activation_snapshot(sorted(old['managed_ids']),sorted(self.plan['providers']))
        if not os.path.lexists(self.paths[0]): binding.plain_path(self.paths[0].parent,True)

    def accept_enrollment(self):
        current=anchors(self.paths[0])
        for name, old in self.anchors.items():
            binding.require(current[name]==old or (name==str(self.paths[0]) and old is None
                and current[name]==binding.directory_identity(self.paths[0])), 'foreign enrollment drift')
        self.anchors=current

    def validate(self,args,plan,paths,stage=None):
        api=self.api
        binding.require(api._activation_attempts.get(self) is self and self.phase=='running' and self.runtime_held,
                        'missing, stale or consumed activation attempt')
        invocation,current_paths=request(api,args)
        binding.require(invocation==self.request and tuple(paths)==tuple(current_paths),'activation request/path mismatch')
        fresh,context,proof,_=capture(api,args,plan,self.nonce)
        binding.require(proof==self.proof,'activation context/binding changed; retry explicitly')
        check_anchors(self.anchors)
        owner=self.authority
        record=owner.forward_record(self)
        if record is None:
            owner.require_no_transaction()
        else:
            layout=owner._activation_current(record)
            binding.require(record['phase'] in ('PREPARING','PREPARED','APPLYING')
                and all(p=='LIVE' for p in layout['old_positions'].values())
                and all(p in ('STAGED','UNPREPARED') for p in layout['new_positions'].values()),
                'forward attempt cannot resume a partial switch')
        live=live_observation(paths)
        expected=dict(self.live)
        if record is not None and record['skills_created_identity'] is not None:
            binding.require(self.live['tree'] is None and live['tree'] is not None and len(live['tree'])==1
                and live['tree'][0]['identity']==record['skills_created_identity'], 'foreign created skills root')
            expected['tree']=live['tree']
        binding.require(live==expected,'activation live tree/metadata changed')
        runtime,prepared,observed=observe_vault(api,fresh,context)
        if fresh['providers']:
            if self.vault is None: self.vault=(runtime,observed)
            binding.require(self.vault==(runtime,observed),'activation Vault identity/state changed')
        if stage is not None:
            binding.require(record is not None and record['phase']=='APPLYING' and record['prepared']
                and stage==owner.workspace(self.nonce)/'new' and stage==self.stage,
                'foreign activation stage or phase')
            binding.require(binding.directory_identity(stage)==self.stage_id,'activation stage identity changed')
            binding.require({p.name for p in stage.iterdir()}==set(fresh['providers']), 'staged provider set differs')
            for ident in fresh['providers']:
                evidence=binding.load_review_binding(api.ROOT,ident,context['idx'][ident],context['locks'][ident],
                    forbidden_roots=(api.RUNTIME,pathlib.Path(invocation['project']),api.ROOT/'.local/active-transactions'))
                binding.validate_artifact_copy(api.managed_child(stage,ident),evidence.value,evidence.sha256,runtime)
            binding.require(tree_observation(stage)==self.staged,'activation staged tree changed')
            binding.require(capture(api,args,plan,self.nonce)[2]==self.proof,'activation context drift before switch')
            binding.require(live_observation(paths)==expected,'activation live drift before switch')
            if runtime is not None:
                binding.require(api.ready_runtime_binding()==runtime,'activation runtime drift before switch')
            check_anchors(self.anchors)
            owner._activation_current(record)
            binding.require(tree_observation(stage)==self.staged,'activation staged drift before switch')
            binding.require({ident:tree_observation(path) for ident,path in prepared.items()}==observed,
                            'activation Vault drift before switch')
        return fresh,context,prepared
