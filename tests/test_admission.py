"""F05 M2 deterministic admission/drift tests; disposable local records only."""
import copy
import io
import json
from contextlib import contextmanager, redirect_stdout
from types import SimpleNamespace
import unittest
from unittest import mock

import test_eligibility as fixture
import accp
import active_transaction as txn
import artifact_binding as ab
import uuid
import os


class Admission(unittest.TestCase):
    setUp = fixture.EligibilityFixture.setUp
    _write = staticmethod(fixture.EligibilityFixture._write)
    entry = fixture.EligibilityFixture.entry
    lock = fixture.EligibilityFixture.lock
    write_resolver_fixture = fixture.EligibilityFixture.write_resolver_fixture

    def setup_provider(self):
        self.write_resolver_fixture([self.entry()], seed=['fixture'])
        vault=self.root/'runtime'/'vault'/'skills'
        patcher=mock.patch.object(accp,'VAULT',vault); patcher.start(); self.addCleanup(patcher.stop)
        d=vault/'fixture'; d.mkdir(parents=True)
        payload={'SKILL.md': b'---\nname: fixture\ndescription: fixture\n---\n'}
        projected=ab.project_invocation(payload, 'explicit')
        for rel,data in projected.items():
            p=d/rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        lock=accp.lock_index(strict=True)['fixture']
        runtime=d.parents[2]
        (runtime/'vault').mkdir(parents=True, exist_ok=True)
        rb={'runtime_id':str(uuid.uuid4()), 'runtime_path':os.path.normcase(str(runtime)),
            'control_plane_path':os.path.normcase(str(self.root)), 'principal':'sid:S-1-5-21-1234',
            'root_identity':ab.directory_identity(runtime),
            'vault_identity':ab.directory_identity(runtime/'vault')}
        self.fixture_rb = rb
        rp = mock.patch.object(accp, 'ready_runtime_binding', return_value=rb)
        rp.start(); self.addCleanup(rp.stop)
        ev=ab.decode_evidence((self.evidence_dir/'fixture.json').read_bytes())
        manifest=dict(schema_version=2,source_id='fixture',
            candidate_sha256=ev['candidate_sha256'],evidence_sha256=lock['evidence_sha256'],
            artifact_tree_sha256=ev['candidate']['artifact_tree_sha256'],invocation='explicit',
            projection=ab.PROJECTION,runtime_binding=rb,materialized_at='2026-09-16T00:00:00Z')
        (d/'.accp-vault-manifest.json').write_bytes(ab.canonical_json(manifest)+b'\n')
        self.args=SimpleNamespace(mode='smoke',project=str(self.project),scope='project',
                                  allow_partial=False,dry_run=False)
        self.plan=accp.resolve_plan('smoke',self.project)

    def change_entry(self, **changes):
        cat=accp.readj(accp.CATALOG,strict=True)
        cat['entries'][0].update(changes); self._write(accp.CATALOG,cat)

    def tree(self,path):
        return {str(p.relative_to(path)):(p.stat().st_ino,p.read_bytes() if p.is_file() else None)
                for p in path.rglob('*')}

    @contextmanager
    def fake_runtime(self, events=None, on_enter=None):
        events=[] if events is None else events
        @contextmanager
        def session(**kwargs):
            events.append('runtime-enter')
            if on_enter: on_enter()
            try: yield
            finally: events.append('runtime-exit')
        with mock.patch.object(accp,'runtime_owner') as owner:
            owner.return_value.session.side_effect=session
            yield owner

    def test_actual_plan_shape_binding_and_selection_are_not_authority(self):
        self.setup_provider(); self.args.dry_run=True
        authority=txn.JournalAuthority(accp.ROOT,self.project)
        authority.base.mkdir(); authority.lock_path.write_bytes(b'')
        bad=[]
        for field,value in [('schema_version',True),('mode','foreign'),('project',str(self.root)),
                            ('providers',None),('providers',['fixture','fixture']),
                            ('providers', ['../escape']),('providers',[]),('providers',['extra']),
                            ('providers',['fixture','extra'])]:
            p=copy.deepcopy(self.plan); p[field]=value; bad.append(p)
        for field in ('schema_version','mode','project','providers'):
            p=copy.deepcopy(self.plan); del p[field]; bad.append(p)
        paths=accp.active_paths(self.project,'project')
        before=self.tree(self.project)
        for plan in bad:
            with self.subTest(plan=plan), mock.patch.object(accp,'runtime_owner') as owner:
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(2,accp.activate_plan(self.args,plan,paths))
                self.assertEqual('UNKNOWN',json.loads(output.getvalue())['lifecycle'])
                with mock.patch.object(accp,'resolve_plan',return_value=plan),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(2,accp.cmd_activate(self.args))
                self.assertEqual('UNKNOWN',json.loads(output.getvalue())['lifecycle'])
                owner.assert_not_called()
        self.assertEqual(before,self.tree(self.project))

    def test_stale_plan_cannot_override_current_policy_or_availability(self):
        self.setup_provider()
        original=accp.CATALOG.read_bytes()
        changes=[{'trust':'quarantine'},{'trust':'partial'},{'risk':'high'},
                 {'deploy':{'deployable':False}},{'invocation':'dormant'},
                 {'runtime':{'requires':['unknown-stack'],'credentials':[]}}]
        for change in changes:
            with self.subTest(change=change):
                accp.CATALOG.write_bytes(original); self.change_entry(**change)
                with self.assertRaises(RuntimeError): accp.activation_admission(self.args,self.plan)
        accp.CATALOG.write_bytes(original)
        self.change_entry(runtime={'requires':['git'],'credentials':[]})
        with mock.patch.object(accp.shutil,'which',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'missing dependencies|catalog digest mismatch'):
                accp.activation_admission(self.args,self.plan)
        accp.CATALOG.write_bytes(original)
        self._write(self.project/'.codex-skillset.json',{'schema_version':1,'exclude':['fixture']})
        with self.assertRaises(RuntimeError): accp.activation_admission(self.args,self.plan)

    def test_new_required_choice_ambiguity_refuses_old_plan(self):
        self.setup_provider()
        policy={'schema_version':1,'capabilities':{'require':['cap']}}
        self.write_resolver_fixture([self.entry()],policy=policy)
        plan=accp.resolve_plan('smoke',self.project)
        self.write_resolver_fixture([self.entry(),self.entry('other')],policy=policy)
        with self.assertRaisesRegex(RuntimeError,'2 eligible providers'):
            accp.activation_admission(self.args,plan)

    def test_final_gate_holds_runtime_then_lifecycle_lock_and_releases_on_refusal(self):
        self.setup_provider(); paths=accp.active_paths(self.project,'project')
        base,skills,im,state,mutex=paths
        personal=skills/'personal'; personal.mkdir(parents=True); (personal/'keep').write_bytes(b'unchanged')
        old=skills/'fixture'; old.mkdir(); (old/'SKILL.md').write_bytes(b'old active bytes')
        self._write(im,{'schema_version':1,'control_plane_path':str(accp.ROOT),
            'project':str(self.project),'scope':'project','managed_ids':['fixture']})
        self._write(state, {'schema_version':1, 'control_plane_path':str(accp.ROOT),
                           'active_ids':['fixture'], 'sentinel':'exact bytes'})
        before=accp.activation.live_observation(paths); events=[]
        acquire=txn.JournalAuthority.lifecycle_lock
        @contextmanager
        def drift(authority, **kwargs):
            self.assertEqual(events,['runtime-enter'])
            with acquire(authority, **kwargs):
                self.assertIsNotNone(authority._held); events.append('lifecycle-acquired')
                self.change_entry(trust='quarantine')
                yield authority
        with self.fake_runtime(events), mock.patch.object(txn.JournalAuthority,'lifecycle_lock',drift):
            with self.assertRaisesRegex(RuntimeError,'quarantine'): accp.cmd_activate(self.args)
        self.assertEqual(events,['runtime-enter','lifecycle-acquired','runtime-exit'])
        self.assertEqual(before,accp.activation.live_observation(paths)); self.assertFalse(mutex.exists())
        owner=txn.JournalAuthority(accp.ROOT,self.project)
        with owner.lifecycle_lock(): self.assertFalse(owner.journal.exists())

    def test_vault_revalidated_against_fresh_lock_after_acquire(self):
        self.setup_provider(); acquire=txn.JournalAuthority.lifecycle_lock
        @contextmanager
        def drift(authority, **kwargs):
            with acquire(authority, **kwargs):
                lock=self.lock(self.entry(),commit='b'*40)
                self._write(accp.LOCK,{'schema_version':2,'sources':{'fixture':lock}})
                yield authority
        with self.fake_runtime(), mock.patch.object(txn.JournalAuthority,'lifecycle_lock',drift):
            with self.assertRaisesRegex((RuntimeError,txn.JournalError),'activation context/binding changed'):
                accp.cmd_activate(self.args)
        base,skills,im,state,mutex=accp.active_paths(self.project,'project')
        self.assertFalse(mutex.exists()); self.assertFalse(skills.exists()); self.assertFalse(im.exists())
        self.assertFalse(list(base.glob('.skills-*')))

    def test_valid_dry_run_uses_derived_plan_and_no_mutation(self):
        self.setup_provider(); self.args.dry_run=True
        authority=txn.JournalAuthority(accp.ROOT,self.project)
        authority.base.mkdir(); authority.lock_path.write_bytes(b'')
        runtime=SimpleNamespace(lock_path=self.root/'runtime-mutex',validate=lambda:{'state':'ready'})
        supplied=dict(self.plan,capabilities_covered=['forged'],warnings=['forged'])
        before=self.tree(self.root)
        with mock.patch.object(accp,'runtime_owner',return_value=runtime),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0,accp.activate_plan(self.args,supplied,accp.active_paths(self.project,'project')))
        result=json.loads(output.getvalue())['preview']['plan']
        self.assertEqual(result['capabilities_covered'],['cap']); self.assertEqual(result['warnings'],[])
        self.assertEqual(before,self.tree(self.root))

    def test_materialize_batch_denial_precedes_runtime(self):
        self.write_resolver_fixture([self.entry(),self.entry('denied',trust='quarantine')])
        for ids in (['fixture','denied'],[],['fixture','fixture'],['../escape'],['missing']):
            with self.subTest(ids=ids), mock.patch.object(accp,'runtime_owner') as owner, \
                    mock.patch.object(accp,'ensure_source_at_lock') as source:
                with self.assertRaises(RuntimeError):
                    accp.cmd_materialize(SimpleNamespace(id=ids,allow_partial=False))
                owner.assert_not_called(); source.assert_not_called()

    def test_materialize_rechecks_inside_session_before_source_work(self):
        self.setup_provider(); before=self.tree(accp.VAULT)
        with self.fake_runtime(on_enter=lambda:self.change_entry(trust='quarantine')), \
                mock.patch.object(accp,'ensure_source_at_lock') as source:
            with self.assertRaisesRegex(RuntimeError,'quarantine'):
                accp.cmd_materialize(SimpleNamespace(id=['fixture'],allow_partial=False))
            source.assert_not_called()
        self.assertEqual(before,self.tree(accp.VAULT))

    def test_materialize_rechecks_eligibility_and_exact_records_before_publication(self):
        self.setup_provider(); original=accp.CATALOG.read_bytes(); original_lock=accp.LOCK.read_bytes()
        source=self.root/'source'; (source/'skill').mkdir(parents=True)
        (source/'skill'/'SKILL.md').write_bytes(b'new content')
        dest=accp.VAULT/'fixture'; retained=self.root/'retained-vault'
        dest.rename(retained); before=self.tree(retained)
        for drift in ('trust','entry','lock','dependency'):
            accp.CATALOG.write_bytes(original); accp.LOCK.write_bytes(original_lock)
            def fetch(*args):
                if drift=='trust': self.change_entry(trust='quarantine')
                elif drift=='entry': self.change_entry(notes='changed while fetching')
                elif drift=='dependency': self.change_entry(runtime={'requires':['unknown-stack'],'credentials':[]})
                else:
                    data=accp.readj(accp.LOCK,strict=True)
                    data['sources']['fixture']['approval']['high_risk']=True; self._write(accp.LOCK,data)
                return source
            with self.subTest(drift=drift), self.fake_runtime(), \
                    mock.patch.object(accp,'ensure_source_at_lock',side_effect=fetch):
                with self.assertRaises(RuntimeError):
                    accp.cmd_materialize(SimpleNamespace(id=['fixture'],allow_partial=False))
            self.assertFalse(dest.exists())
            self.assertEqual(before,self.tree(retained))

    def test_materialize_current_artifact_is_idempotent_without_source_work(self):
        self.setup_provider(); before=self.tree(accp.VAULT)
        with self.fake_runtime(), mock.patch.object(accp,'ensure_source_at_lock') as source:
            accp.cmd_materialize(SimpleNamespace(id=['fixture'],allow_partial=False))
            accp.cmd_materialize(SimpleNamespace(id=['fixture'],allow_partial=False))
            source.assert_not_called()
        self.assertEqual(before,self.tree(accp.VAULT))

    def test_pin_flags_are_literal_booleans_before_any_write(self):
        self.setup_provider(); before=accp.LOCK.read_bytes()
        for name in ('approve_partial','approve_high_risk'):
            for value in (None,0,1,'false','true',[],{}):
                args=SimpleNamespace(id='fixture',approve_partial=False,approve_high_risk=False)
                setattr(args,name,value)
                with self.subTest(name=name,value=value):
                    with self.assertRaisesRegex(RuntimeError,'must be boolean'): accp.cmd_pin(args)
                    self.assertEqual(before,accp.LOCK.read_bytes())


if __name__=='__main__': unittest.main()
