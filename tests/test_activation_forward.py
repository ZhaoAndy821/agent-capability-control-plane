"""A3 live producer tests; real binding fixtures, disposable repository-local data."""
import io
import json
import os
from pathlib import Path
from contextlib import redirect_stdout, contextmanager
from unittest import mock
import unittest

import test_admission as fixtures
import accp
import active_transaction as txn


class ActivationForward(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Admission(); self.f.setUp(); self.f.setup_provider()
        self.addCleanup(self.f.doCleanups)
        self.args=self.f.args; self.paths=accp.active_paths(self.f.project,'project')
        self.owner=txn.JournalAuthority(accp.ROOT,self.f.project)

    def activate(self):
        output=io.StringIO()
        with self.f.fake_runtime(), redirect_stdout(output): accp.cmd_activate(self.args)
        return json.loads(output.getvalue())

    def recover(self, cleanup=False):
        op=self.owner.cleanup if cleanup else self.owner.recover
        return op(lambda:accp.read_install_manifest(*self.paths[:4],self.args.project,self.args.scope),lambda:None)

    def live(self): return accp.activation.live_observation(self.paths)

    def old(self, ids=('fixture','retired')):
        base,skills,im,state,_=self.paths; skills.mkdir(parents=True,exist_ok=True)
        for ident in ids:
            (skills/ident).mkdir(); (skills/ident/'SKILL.md').write_bytes(('old '+ident).encode())
        (skills/'personal').mkdir(); (skills/'personal'/'keep').write_bytes(b'user-owned')
        for path,value in ((im,dict(schema_version=1,control_plane_path=str(accp.ROOT),project=str(self.f.project),
                scope='project',managed_ids=list(ids))),
                (state,dict(schema_version=1,control_plane_path=str(accp.ROOT),active_ids=list(ids)))):
            path.write_bytes((json.dumps(value,indent=2)+'\n').encode())

    def test_initial_success_retains_evidence_then_enrolled_reactivation(self):
        self.assertTrue(self.activate()['committed'])
        first=self.owner.load_activation(); self.assertEqual('COMMITTED',first['phase'])
        self.assertTrue(self.owner.lock_path.exists()); self.assertTrue(self.owner.locator.exists())
        before=self.live()
        with self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(before,self.live())
        self.recover(True)
        self.assertTrue(self.activate()['committed'])
        self.assertNotEqual(first['transaction_id'],self.owner.load_activation()['transaction_id'])
        self.assertFalse(accp._activation_attempts)

    def test_same_and_disjoint_old_ids_keep_root_unmanaged_and_exact_snapshots(self):
        self.old(); before=self.live(); personal=accp.activation.tree_observation(self.paths[1]/'personal')
        self.activate(); record=self.owner.load_activation()
        self.assertEqual(before['tree'][0]['identity'],accp.activation.tree_observation(self.paths[1])[0]['identity'])
        self.assertEqual(personal,accp.activation.tree_observation(self.paths[1]/'personal'))
        self.assertEqual(['fixture','retired'],record['old_ids']); self.assertEqual(['fixture'],record['new_ids'])
        for ident in record['old_ids']:
            self.assertEqual(record['old_children'][ident],self.owner._activation_child(self.owner.workspace(record['transaction_id'])/'old'/ident))
        self.assertFalse((self.paths[1]/'retired').exists())
        self.assertTrue(self.recover()['committed']); self.recover(True)
        self.assertEqual(personal,accp.activation.tree_observation(self.paths[1]/'personal'))

    def test_phase_locator_proof_and_move_order(self):
        self.old(); events=[]; publish=txn.JournalAuthority.publish_journal; replace=os.replace
        def journal(owner,record,previous=None):
            events.append(record['phase']); return publish(owner,record,previous)
        def move(source,target):
            target=Path(target)
            if target.parent.name=='old' or target.parent==self.paths[1]:
                attempt=next(iter(accp._activation_attempts))
                self.assertEqual('consumed',attempt.phase); self.assertTrue(attempt.runtime_held)
                self.assertIsNotNone(attempt.authority._held)
                self.assertTrue(self.owner.locator.exists()); events.append('move:'+target.name)
            return replace(source,target)
        with mock.patch.object(txn.JournalAuthority,'publish_journal',journal),mock.patch.object(os,'replace',move):
            self.activate()
        self.assertLess(events.index('PREPARING'),events.index('PREPARED'))
        self.assertLess(events.index('APPLYING'),events.index('move:fixture'))
        self.assertEqual(['move:fixture','move:retired','move:fixture'],[e for e in events if e.startswith('move:')])
        self.assertEqual('COMMITTED',events[-1])

    def test_partial_switch_retained_then_exact_rollback(self):
        self.old(); before=self.live(); original=os.replace; fired=[]
        def interrupt(source,target):
            result=original(source,target)
            if Path(target).parent.name=='old' and not fired:
                fired.append(True); raise OSError('move interruption')
            return result
        with mock.patch.object(os,'replace',interrupt),self.assertRaises(txn.JournalError): self.activate()
        self.assertTrue(fired); self.assertFalse(accp._activation_attempts)
        self.assertTrue(self.recover()['rolled_back'])
        after=self.live(); self.assertEqual(before['tree'],after['tree'])
        for key in ('manifest','state'): self.assertEqual(before[key]['sha256'],after[key]['sha256'])
        self.recover(True)

    def test_stage_tamper_preserved_and_no_live_mutation(self):
        self.old(); before=self.live(); copy=accp.shutil.copytree; fired=[]
        def tamper(source,target,*args,**kwargs):
            result=copy(source,target,*args,**kwargs)
            if Path(source)==accp.VAULT/'fixture':
                fired.append(True); (Path(target)/'SKILL.md').write_bytes(b'foreign')
            return result
        with mock.patch.object(accp.shutil,'copytree',tamper),self.assertRaises(txn.JournalError): self.activate()
        self.assertTrue(fired); self.assertEqual(before,self.live())
        self.assertEqual('PREPARING',self.owner.load_activation()['phase'])
        with self.assertRaises(txn.JournalError): self.recover()

    def test_final_context_drift_retains_recoverable_stage(self):
        self.old(); before=self.live(); validate=accp.activation.ActivationAttempt.validate; fired=[]
        def drift(attempt,args,plan,paths,stage=None):
            if stage is not None:
                fired.append(True); self.f.change_entry(trust='quarantine')
            return validate(attempt,args,plan,paths,stage)
        with mock.patch.object(accp.activation.ActivationAttempt,'validate',drift),self.assertRaises(txn.JournalError): self.activate()
        self.assertTrue(fired); self.assertEqual(before,self.live())
        self.assertTrue(self.recover()['rolled_back']); self.recover(True)

    def test_runtime_then_lifecycle_drift_refuses_before_begin(self):
        self.old(); before=self.live(); lock=txn.JournalAuthority.lifecycle_lock; events=[]
        @contextmanager
        def held(owner,create=True):
            self.assertEqual(['runtime-enter'],events)
            with lock(owner,create):
                events.append('lifecycle'); self.f.change_entry(trust='quarantine'); yield owner
        with self.f.fake_runtime(events),mock.patch.object(txn.JournalAuthority,'lifecycle_lock',held),redirect_stdout(io.StringIO()):
            with self.assertRaises((txn.JournalError,RuntimeError)): accp.cmd_activate(self.args)
        self.assertEqual(['runtime-enter','lifecycle','runtime-exit'],events)
        self.assertEqual(before,self.live()); self.assertFalse(self.owner.journal.exists())
        with self.owner.lifecycle_lock(create=False): pass

    def test_inventory_bounds_refuse_before_applying(self):
        self.old(); before=self.live()
        with mock.patch.object(txn,'MAX_CLEANUP_ENTRIES',0),self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(before,self.live()); self.assertEqual('PREPARED',self.owner.load_activation()['phase'])
        self.recover(); self.recover(True)

    def test_workspace_allocation_gap_is_not_adopted(self):
        self.old(); before=self.live(); publish=txn.JournalAuthority.publish_journal
        def gap(owner,record,previous=None):
            if record['workspace_identity'] is not None: raise OSError('registration interrupted')
            return publish(owner,record,previous)
        with mock.patch.object(txn.JournalAuthority,'publish_journal',gap),self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(before,self.live())
        with self.assertRaises(txn.JournalError): self.recover()

    def test_empty_selection_without_runtime_initial_and_existing(self):
        self.f.write_resolver_fixture([self.f.entry()],seed=[])
        with mock.patch.object(accp,'runtime_owner',side_effect=AssertionError('empty plan runtime access')):
            self.assertTrue(self.activate()['committed'])
        self.assertEqual([],self.owner.load_activation()['new_ids']); self.recover(True)

    def test_unmanaged_collision_and_missing_parent_refuse_before_enrollment(self):
        skills=self.paths[1]; skills.mkdir(parents=True); (skills/'fixture').mkdir()
        before=self.live()
        with self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(before,self.live()); self.assertFalse(self.owner.lock_path.exists())

    def test_standalone_forward_helpers_cannot_authorize(self):
        from test_activation_transaction import ActivationFixture
        fixture=ActivationFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups); record=fixture.build()
        with fixture.owner.lifecycle_lock(create=False):
            with self.assertRaises(txn.JournalError): fixture.owner._publish_forward(dict(record,phase='APPLYING'))
            with self.assertRaises(txn.JournalError): fixture.owner._forward_switch_ready(dict(record,phase='APPLYING'))

    def test_deactivate_normal_entry_refuses_orphan_and_pending_activation_residue(self):
        self.old(); before=self.live()
        for name in ('.active-state.json.unknown.pending','.accp-txn-unregistered','.skills-stage-legacy'):
            path=self.paths[0]/name; path.write_bytes(b'unknown retained evidence')
            with self.subTest(name=name), self.assertRaises(txn.JournalError):
                accp.cmd_deactivate(self.args)
            self.assertEqual(before,self.live()); self.assertEqual(b'unknown retained evidence',path.read_bytes())
            self.assertFalse(self.owner.lock_path.exists()); self.assertFalse(self.owner.journal.exists())
            path.unlink()  # disposable plain fixture only

    def test_metadata_pair_and_collision_refuse_before_runtime_access(self):
        self.old(); self.paths[3].unlink(); before=self.live()
        with mock.patch.object(accp,'runtime_owner',side_effect=AssertionError('runtime accessed')):
            with self.assertRaises(txn.JournalError): accp.cmd_activate(self.args)
        self.assertEqual(before,self.live()); self.assertFalse(self.owner.lock_path.exists())

    def test_cleanup_projection_bounds_longer_discard_layout_without_publication(self):
        from test_activation_transaction import ActivationFixture
        fixture=ActivationFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record=fixture.build(); before=fixture.observe(); captured=[]
        serialize=fixture.owner.serialize
        def observe(value):
            if value['phase']=='CLEANING': captured.append(value)
            return serialize(value)
        with mock.patch.object(fixture.owner,'serialize',side_effect=observe):
            fixture.owner._project_activation_cleanup(record)
        rollback=captured[1]
        self.assertEqual({'discard'}, {e['area'] for e in rollback['cleanup_entries']})
        shorter=dict(rollback,cleanup_entries=[dict(e,area='new') for e in rollback['cleanup_entries']])
        with mock.patch.object(txn,'MAX_JOURNAL',len(serialize(shorter))):
            with self.assertRaises(txn.JournalError): fixture.owner._project_activation_cleanup(record)
        self.assertEqual(before,fixture.observe())

    def test_projected_live_plus_unmanaged_must_fit_observation_limits(self):
        from test_activation_transaction import ActivationFixture
        fixture=ActivationFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record=fixture.build(old=()); before=fixture.observe()
        live=accp.activation.tree_observation(fixture.skills)
        staged=accp.activation.tree_observation(fixture.workspace/'new')
        for field,limit in (('MAX_ENTRIES',max(len(live),len(staged))),
                ('MAX_PAYLOAD',max(sum(r.get('size',0) for r in live),sum(r.get('size',0) for r in staged)))):
            with self.subTest(field=field),mock.patch.object(accp.binding,field,limit):
                with self.assertRaisesRegex(txn.JournalError,'projected live tree'):
                    fixture.owner._project_activation_cleanup(record)
        self.assertEqual(before,fixture.observe())

    def test_cleanup_projection_reserves_future_created_root_identity(self):
        from test_activation_transaction import ActivationFixture
        fixture=ActivationFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record=fixture.build(old=(),absent=True,missing_metadata=True); before=fixture.observe()
        sizes=[]; serialize=fixture.owner.serialize
        def observed(value):
            raw=serialize(value)
            if value['phase']=='CLEANING': sizes.append(len(raw))
            return raw
        with mock.patch.object(fixture.owner,'serialize',side_effect=observed):
            fixture.owner._project_activation_cleanup(record)
        with mock.patch.object(txn,'MAX_JOURNAL',max(sizes)):
            with self.assertRaisesRegex(txn.JournalError,'projected cleanup journal size'):
                fixture.owner._project_activation_cleanup(record)
        self.assertEqual(before,fixture.observe())

    def test_lifecycle_contention_releases_runtime_without_begin(self):
        self.old(); before=self.live(); events=[]
        with self.owner.lifecycle_lock():
            with self.f.fake_runtime(events), self.assertRaisesRegex(txn.JournalError,'busy or unavailable'):
                accp.cmd_activate(self.args)
        self.assertEqual(['runtime-enter','runtime-exit'],events)
        self.assertEqual(before,self.live()); self.assertFalse(self.owner.journal.exists())
        self.assertFalse(accp._activation_attempts)

    def test_commit_publication_exception_reads_retained_outcome(self):
        self.old(); publish=txn.JournalAuthority.publish_journal; fired=[]
        def interrupted(owner,record,previous=None):
            publish(owner,record,previous)
            if record['phase']=='COMMITTED': fired.append(True); raise OSError('after durable commit')
        with mock.patch.object(txn.JournalAuthority,'publish_journal',interrupted):
            with self.assertRaisesRegex(txn.JournalError,'authority=COMMITTED'): self.activate()
        self.assertTrue(fired); committed=self.live()
        self.assertTrue(self.recover()['committed']); self.recover(True)
        self.assertEqual(committed,self.live()); self.assertFalse(accp._activation_attempts)

    def test_created_root_registration_gap_preserves_unknown_allocation(self):
        publish=txn.JournalAuthority.publish_journal; fired=[]
        def interrupted(owner,record,previous=None):
            if record['skills_created_identity'] is not None:
                fired.append(True); raise OSError('root registration interrupted')
            return publish(owner,record,previous)
        with mock.patch.object(txn.JournalAuthority,'publish_journal',interrupted):
            with self.assertRaises(txn.JournalError): self.activate()
        self.assertTrue(fired); self.assertTrue(self.paths[1].is_dir())
        self.assertFalse(any(self.paths[1].iterdir())); self.assertFalse(self.paths[2].exists())
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertTrue(self.owner.journal.exists()); self.assertTrue(self.owner.locator.exists())


if __name__=='__main__': unittest.main()
