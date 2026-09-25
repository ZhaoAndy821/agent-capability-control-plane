"""A1 classifiers and A2 rollback/cleanup; fixture setup is not a forward producer."""
import copy
import os
import json
import subprocess
import unittest
from unittest import mock
from pathlib import Path
import stat

from test_activation_transaction import ActivationFixture, txn, binding


class ActivationRecoveryModel(ActivationFixture):
    def test_all_forward_and_rollback_cuts_same_id_and_disjoint(self):
        self.build(); self.classify(); self.applying()
        for ident in self.record['old_ids']:
            self.classify(); self.move_old(ident); self.classify()
        for ident in self.record['new_ids']:
            self.classify(); self.move_new(ident); self.classify()
        self.im.write_bytes(txn.snapshot_bytes(self.record['new_manifest'])); self.classify()
        self.state.write_bytes(txn.snapshot_bytes(self.record['new_state'])); self.classify()
        self.record['phase']='ROLLING_BACK'; self.persist()
        for ident in reversed(self.record['new_ids']):
            os.replace(self.skills/ident, self.workspace/'discard'/ident); self.classify()
        for ident in reversed(self.record['old_ids']):
            os.replace(self.workspace/'old'/ident,self.skills/ident); self.classify()
        self.state.write_bytes(txn.snapshot_bytes(self.record['old_state'])); self.classify()
        self.im.write_bytes(txn.snapshot_bytes(self.record['old_manifest'])); self.classify()
        self.record['phase']='ROLLED_BACK'; self.persist(); self.classify(); self.classify()

    def test_initial_absence_and_created_root_rollback(self):
        self.build(old=(), absent=True, missing_metadata=True); self.classify(); self.applying(); self.classify()
        self.skills.mkdir(); self.refuse()
        self.record['skills_created_identity']=txn.directory_identity(self.skills); self.persist(); self.classify()
        for ident in self.record['new_ids']: self.move_new(ident)
        self.im.write_bytes(txn.snapshot_bytes(self.record['new_manifest'])); self.classify()
        self.state.write_bytes(txn.snapshot_bytes(self.record['new_state'])); self.classify()
        self.record['phase']='ROLLING_BACK'; self.persist()
        for ident in reversed(self.record['new_ids']):
            os.replace(self.skills/ident,self.workspace/'discard'/ident); self.classify()
        self.state.unlink(); self.classify(); self.im.unlink(); self.classify()
        self.skills.rmdir(); self.classify()
        self.record['phase']='ROLLED_BACK'; self.persist(); self.classify()
        self.cleanup_record('rolled_back'); self.classify()

    def test_empty_selection_commits_without_runtime(self):
        self.build(new=()); self.committed()
        self.assertIsNone(self.record['activation']['runtime_binding'])
        self.assertEqual('retain', self.classify()['action'])

    def test_empty_initial_install(self):
        self.build(old=(),new=(),absent=True,missing_metadata=True); self.classify(); self.committed(); self.classify()

    def test_staged_area_has_aggregate_payload_bound(self):
        self.build(old=(),absent=True,missing_metadata=True)
        with mock.patch.object(binding,'MAX_PAYLOAD',12): self.refuse()

    def test_registered_preparing_prefix_and_unregistered_copies(self):
        self.build(prepared=False); self.classify()
        self.workspace.mkdir(); self.refuse()
        for area in ('old','new','discard'): (self.workspace/area).mkdir()
        self.record['workspace_identity']={area: txn.directory_identity(self.workspace if area=='root' else self.workspace/area)
                                         for area in ('root','old','new','discard')}
        self.persist(); self.classify()
        child=self.workspace/'new'/'alpha'; child.mkdir(); (child/'SKILL.md').write_bytes(b'partial'); self.refuse()
        self.record['new_children']['alpha']=self.owner._activation_child(child); self.persist(); self.classify()
        self.record['phase']='ROLLING_BACK'; self.persist(); self.classify()
        self.record['phase']='ROLLED_BACK'; self.persist(); self.classify()
        self.cleanup_record('rolled_back'); self.classify()

    def test_wrong_order_early_metadata_and_foreign_bytes(self):
        self.build(); self.applying()
        self.move_old('beta'); self.refuse()
        os.replace(self.workspace/'old'/'beta',self.skills/'beta')
        self.move_new('gamma'); self.refuse()
        os.replace(self.skills/'gamma',self.workspace/'new'/'gamma')
        self.im.write_bytes(txn.snapshot_bytes(self.record['new_manifest'])); self.refuse()
        self.im.write_bytes(txn.snapshot_bytes(self.record['old_manifest']))
        self.state.write_bytes(b'{}'); self.refuse()

    def test_duplicate_missing_replaced_and_unmanaged_drift(self):
        self.build(); self.applying()
        child=self.workspace/'new'/'alpha'; child.rename(self.root/'saved'); self.refuse()
        child.mkdir(); (child/'SKILL.md').write_bytes(b'new-alpha'); self.refuse()
        (child/'SKILL.md').unlink(); child.rmdir(); (self.root/'saved').rename(child)
        # Identical bytes at a second location still have a foreign directory identity.
        duplicate=self.workspace/'discard'/'alpha'; duplicate.mkdir()
        (duplicate/'SKILL.md').write_bytes(b'new-alpha'); self.refuse()
        (duplicate/'SKILL.md').unlink(); duplicate.rmdir()
        (self.skills/'user.txt').write_bytes(b'changed'); self.refuse()

    def test_pending_missing_foreign_and_malformed_authority(self):
        self.build(); raw=self.owner.journal.read_bytes(); locator=self.owner.locator.read_bytes()
        for path in (self.owner.journal_pending,self.owner.locator_pending,
                     self.owner.metadata_slots(self.record)['manifest'][1]):
            path.write_bytes(b'{}'); self.refuse(); path.unlink()
        for path,saved in ((self.owner.journal,raw),(self.owner.locator,locator)):
            for data in (b'{', b'{}', b'\xff'):
                path.write_bytes(data); self.refuse()
            path.write_bytes(saved)
            path.unlink(); self.refuse(); path.write_bytes(saved)
        loc=json.loads(locator); loc['transaction_id']='00000000-0000-4000-8000-000000000000'
        self.owner.locator.write_bytes(json.dumps(loc).encode()); self.refuse()

    def test_locator_absent_initial_intent_only_and_no_lock_creation(self):
        self.build(prepared=False); self.owner.locator.unlink(); self.classify()
        self.owner.lock_path.unlink(); before=self.observe()
        with self.assertRaises(txn.JournalError): self.owner.classify_activation()
        self.assertEqual(before,self.observe())
        self.assertFalse(self.owner.lock_path.exists())
        with self.assertRaises(txn.JournalError): self.owner.require_legacy_activation_safe()

    def test_partial_cleanup_and_done_are_read_only(self):
        self.build(); self.committed(); self.cleanup_record(); self.classify()
        entries=list(self.record['cleanup_entries'])
        for entry in sorted(entries,key=lambda e:len(e['relative'].split('/')) if e['relative']!='.' else 0,reverse=True):
            root=self.workspace/entry['area']/entry['id']
            path=root if entry['relative']=='.' else root/entry['relative']
            path.unlink() if entry['type']=='file' else path.rmdir()
            self.classify()
        for area in ('old','new','discard'):
            (self.workspace/area).rmdir(); self.classify()
        self.workspace.rmdir(); self.classify()
        self.record['phase']='DONE'; self.persist(); self.classify()
        self.owner.locator.unlink(); self.classify(); self.classify()

    def test_cleanup_unknown_entries_and_identity_tampering(self):
        self.build(); self.committed(); self.cleanup_record()
        extra=self.workspace/'new'/'unexpected'; extra.mkdir(); self.refuse(); extra.rmdir()
        target=self.workspace/'old'/'alpha'/'SKILL.md'; target.write_bytes(b'changed'); self.refuse()
        record=copy.deepcopy(self.record); record['cleanup_entries'][0]['relative']='../escape'
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        record=copy.deepcopy(self.record); record['cleanup_entries']=[]
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        record=copy.deepcopy(self.record); record['cleanup_entries'][1]['relative']='．．/escape'
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        with mock.patch.object(txn,'MAX_CLEANUP_ENTRIES',0), self.assertRaises(txn.JournalError):
            self.owner.validate(self.record)

    def test_foreign_checkout_project_and_replaced_workspace(self):
        self.build()
        for field in ('control_plane_path','project_path','base_path'):
            record=copy.deepcopy(self.record); record[field]=str(self.root)
            self.owner.journal.write_bytes(json.dumps(record).encode()); self.refuse()
        self.persist()
        self.workspace.rename(self.root/'old-workspace'); self.workspace.mkdir()
        for name in ('old','new','discard'): (self.workspace/name).mkdir()
        self.refuse()

    def test_hardlink_refusal_is_nonmutating(self):
        self.build()
        path=self.skills/'user.txt'; os.link(path,self.root/'hardlink')
        self.refuse()

    def test_recorded_created_root_cannot_disappear_during_applying(self):
        self.build(old=(),absent=True,missing_metadata=True); self.applying()
        self.skills.mkdir(); self.record['skills_created_identity']=txn.directory_identity(self.skills)
        self.persist(); self.classify(); self.skills.rmdir(); self.refuse()

    def test_unswitched_metadata_replacement_refused(self):
        self.build(); self.applying()
        replacement=self.root/'replacement'; replacement.write_bytes(self.im.read_bytes())
        os.replace(replacement,self.im); self.refuse()

    def test_rollback_cannot_restore_old_before_evacuating_new(self):
        self.build(); self.committed(); self.record['phase']='ROLLING_BACK'; self.persist()
        os.replace(self.workspace/'old'/'beta',self.skills/'beta'); self.refuse()

    def test_classifier_requires_os_lock_and_contends_without_writes(self):
        self.build(); before=self.observe()
        with self.assertRaises(txn.JournalError): self.owner.classify_activation()
        other=txn.JournalAuthority(self.cp,self.project)
        with self.owner.lifecycle_lock(create=False):
            with self.assertRaises(txn.JournalError):
                with other.lifecycle_lock(create=False): other.classify_activation()
        self.assertEqual(before,self.observe())

    @unittest.skipUnless(os.name=='nt', 'native Windows junction/ADS test')
    def test_native_junction_and_stream_refusal_preserves_targets(self):
        self.build()
        target=self.root/'target'; target.mkdir(); (target/'sentinel').write_bytes(b'untouched')
        link=self.skills/'redirect'
        result=subprocess.run(['cmd.exe','/c','mklink','/J',str(link),str(target)],capture_output=True)
        self.assertEqual(0,result.returncode,result.stderr)
        try: self.refuse()
        finally: link.rmdir()
        self.assertEqual(b'untouched',(target/'sentinel').read_bytes())
        stream=str(self.skills/'user.txt')+':extra'
        with open(stream,'wb') as file: file.write(b'named stream')
        try:
            self.refuse()
            with open(stream,'rb') as file: self.assertEqual(b'named stream',file.read())
        finally: os.unlink(stream)
        self.assertEqual(b'untouched user content',(self.skills/'user.txt').read_bytes())

    def test_native_symlink_refusal(self):
        self.build()
        link=self.skills/'link'
        try: link.symlink_to(self.root/'runtime',target_is_directory=True)
        except OSError as exc:
            if os.name=='nt' and getattr(exc,'winerror',None)==1314:
                self.skipTest('native symlink creation requires Windows privilege (WinError 1314)')
            raise
        try: self.refuse()
        finally: link.unlink()

    def test_user_scope_and_runtime_disappearance_do_not_require_admission(self):
        old=self.owner
        self.base=self.root/'user-base'; self.base.mkdir()
        self.owner=txn.JournalAuthority(self.cp,self.project,'user',self.base)
        self.owner.lock_path.write_bytes(b'')
        self.skills=self.base/'skills'; self.im=self.base/'install-manifest.json'; self.state=self.base/'active-state.json'
        self.build(); self.classify()
        self.runtime.rename(self.root/'runtime-removed')
        self.classify()
        self.assertIsNone(old.load_activation())


class ActivationRecoveryExecution(ActivationFixture):
    def recover(self, dry=False):
        return self.owner.recover(lambda: self.fail('v1/admission preflight reached'),
                                  lambda: self.fail('v1 path preflight reached'), dry_run=dry)

    def cleanup(self, dry=False):
        return self.owner.cleanup(lambda: self.fail('v1/admission preflight reached'),
                                  lambda: self.fail('v1 path preflight reached'), dry_run=dry)

    def switched(self, **kwargs):
        self.build(**kwargs); self.committed()
        self.record['phase'] = 'APPLYING'; self.persist()

    def assert_restored(self):
        record = self.owner.load_activation()
        self.assertEqual('ROLLED_BACK', record['phase'])
        for ident, child in record['old_children'].items():
            self.assertEqual(child, self.owner._activation_child(self.skills / ident))
        for key, path in (('manifest', self.im), ('state', self.state)):
            self.assertEqual(record['old_' + key], self.owner._activation_metadata(path)[0])
        self.assertEqual(record['skills_before'] != {'exists': False}, self.skills.exists())
        self.classify()

    def test_order_exact_objects_metadata_and_repeat(self):
        self.switched(); sentinel = self.observe()['project/.agents/skills/user.txt']
        events = []; replace = os.replace
        def traced(src, dst):
            events.append((Path(src), Path(dst))); return replace(src, dst)
        with mock.patch.object(txn.os, 'replace', side_effect=traced):
            self.assertTrue(self.recover()['rolled_back'])
        destinations = [dst for _, dst in events]
        expected = [self.workspace/'discard'/'gamma', self.workspace/'discard'/'alpha',
                    self.skills/'beta', self.skills/'alpha', self.state, self.im]
        self.assertEqual(expected, [p for p in destinations if p != self.owner.journal])
        self.assert_restored()
        before = self.observe(); self.assertTrue(self.recover()['noop']); self.assertEqual(before, self.observe())
        self.assertEqual(sentinel, self.observe()['project/.agents/skills/user.txt'])
        self.assertTrue(self.owner.locator.exists()); self.assertTrue(self.workspace.exists())

    def test_dry_run_is_byte_and_identity_preserving(self):
        self.switched(); before = self.observe()
        self.assertEqual('rollback',self.recover(True)['preview']['action']); self.assertEqual(before, self.observe())
        self.recover(); before = self.observe()
        self.assertEqual('finalize',self.cleanup(True)['preview']['action']); self.assertEqual(before, self.observe())

    def test_pristine_missing_locator_and_registered_prefix(self):
        self.build(prepared=False); self.owner.locator.unlink()
        self.assertTrue(self.recover()['rolled_back']); self.assert_restored()
        self.assertTrue(self.cleanup()['finalized'])
        self.assertFalse(self.workspace.exists())

    def test_partial_registered_preparation(self):
        self.build(); (self.workspace/'new'/'gamma'/'SKILL.md').unlink(); (self.workspace/'new'/'gamma').rmdir()
        self.record.update(phase='PREPARING', prepared=False)
        self.record['new_children']['gamma'] = {'prepared': False}; self.persist()
        self.recover(); self.assert_restored(); self.assertTrue(self.cleanup()['finalized'])

    def test_initial_absence_and_empty_selection(self):
        self.switched(old=(), new=(), absent=True, missing_metadata=True)
        self.recover(); self.assert_restored()
        self.assertFalse(self.im.exists()); self.assertFalse(self.state.exists())
        self.assertTrue(self.cleanup()['finalized']); self.assertFalse(self.skills.exists())

    def test_committed_never_rolls_back_and_cleanup_preserves_new(self):
        self.build(); self.committed(); live = txn.activation_observation.tree_observation(self.skills)
        self.assertTrue(self.recover()['committed'])
        self.assertTrue(self.cleanup()['finalized'])
        self.assertEqual(live, txn.activation_observation.tree_observation(self.skills))
        self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
        self.assertFalse(self.workspace.exists()); self.assertTrue(self.owner.lock_path.exists())
        # After evidence removal the shared no-transaction path uses F01 preflight.
        self.assertTrue(self.owner.cleanup(lambda: {'managed_ids': self.record['new_ids']}, lambda: None)['noop'])

    def test_rolled_back_cleanup_preserves_old_and_unrelated_data(self):
        self.switched(); self.recover(); live = txn.activation_observation.tree_observation(self.skills)
        unrelated = self.root/'unrelated'; unrelated.mkdir(); (unrelated/'keep').write_bytes(b'keep')
        self.cleanup()
        self.assertEqual(live, txn.activation_observation.tree_observation(self.skills))
        self.assertEqual(b'keep', (unrelated/'keep').read_bytes())

    def test_runtime_removed_user_scope_and_no_review_lookup(self):
        self.base = self.root/'user-base'; self.base.mkdir()
        self.owner = txn.JournalAuthority(self.cp, self.project, 'user', self.base)
        self.owner.lock_path.write_bytes(b'')
        self.skills = self.base/'skills'; self.im = self.base/'install-manifest.json'; self.state = self.base/'active-state.json'
        self.switched(); self.runtime.rename(self.root/'runtime-removed')
        with mock.patch.object(binding, 'validate_runtime_binding', wraps=binding.validate_runtime_binding) as shape:
            self.recover(); self.assert_restored(); self.cleanup(); self.assertTrue(shape.called)
        self.assertTrue((self.root/'runtime-removed'/'vault').exists())

    def test_pending_and_malformed_authority_refuse_without_mutation(self):
        self.switched(); raw = self.owner.journal.read_bytes()
        for path, data in ((self.owner.journal_pending, b'partial'), (self.owner.locator_pending, b'{'),
                           (self.owner.metadata_slots(self.record)['state'][1], b'partial')):
            path.write_bytes(data); before = self.observe()
            for method in (self.recover, self.cleanup):
                with self.assertRaises(txn.JournalError): method()
                self.assertEqual(before, self.observe())
            path.unlink()
        self.owner.journal.write_bytes(raw[:-2]); before = self.observe()
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertEqual(before, self.observe())

    def test_conflict_replacement_and_foreign_content_refuse(self):
        self.switched()
        # Foreign authoritative identity, then restore canonical original authority.
        raw = self.owner.journal.read_bytes()
        value = json.loads(raw); value['project_identity']['inode'] = '999999'
        self.owner.journal.write_text(json.dumps(value), encoding='utf-8'); before = self.observe()
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertEqual(before, self.observe()); self.owner.journal.write_bytes(raw)
        (self.workspace/'old'/'alpha'/'unexpected').write_bytes(b'foreign'); before = self.observe()
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertEqual(before, self.observe())

    def test_lock_contention_and_legacy_lock(self):
        self.switched(); other = txn.JournalAuthority(self.cp, self.project)
        before = self.observe()
        with self.owner.lifecycle_lock(create=False):
            with self.assertRaisesRegex(txn.JournalError, 'busy'): other.recover(lambda: None, lambda: None)
        self.assertEqual(before, self.observe())
        self.owner.legacy_lock.write_bytes(b'legacy'); before = self.observe()
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertEqual(before, self.observe())

    def test_no_forward_transition_or_helper_metadata_bypass(self):
        self.build(); before = self.observe()
        with self.owner.lifecycle_lock(create=False):
            for phase in ('PREPARING', 'PREPARED', 'APPLYING', 'COMMITTED'):
                with self.assertRaises(txn.JournalError):
                    self.owner.publish_journal(dict(self.record, phase=phase), self.owner.serialize(self.record))
            with self.assertRaises(txn.JournalError):
                self.owner._publish(*self.owner.metadata_slots(self.record)['manifest'],
                    txn.snapshot_bytes(self.record['new_manifest']), self.im.read_bytes(), metadata_record=self.record)
        self.assertEqual(before, self.observe())

    def test_readonly_cleanup_and_hardlink_refusal(self):
        self.build(); self.committed()
        file = self.workspace/'old'/'alpha'/'SKILL.md'; alias = self.root/'alias'
        os.link(file, alias); before = self.observe()
        with self.assertRaises(txn.JournalError): self.cleanup()
        self.assertEqual(before, self.observe()); alias.unlink()
        # Refresh the synthetic observation to model a read-only original object.
        file.chmod(stat.S_IREAD)
        self.record['old_children']['alpha'] = self.owner._activation_child(file.parent); self.persist()
        self.assertTrue(self.cleanup()['finalized'])

    def test_publication_pending_is_not_promoted(self):
        self.switched(); replace = os.replace
        def fail(src, dst):
            if Path(dst) == self.owner.journal: raise OSError('injected publication')
            return replace(src, dst)
        with mock.patch.object(txn.os, 'replace', side_effect=fail) as hook:
            with self.assertRaises(txn.JournalError): self.recover()
            self.assertTrue(hook.called)
        self.assertTrue(self.owner.journal_pending.exists()); before = self.observe()
        with self.assertRaises(txn.JournalError): self.recover()
        self.assertEqual(before, self.observe())

    def test_cli_dispatch_and_real_process_exit_then_retry(self):
        import sys
        self.switched()
        code = '''import sys, os
from pathlib import Path
import accp, active_transaction as txn
accp.ROOT = Path(sys.argv[1])
original = os.replace
def interrupted(src, dst):
    original(src, dst)
    if Path(dst).parent.name == 'discard': os._exit(73)
os.replace = interrupted
sys.argv = ['accp', 'recover', '--project', sys.argv[2]]
raise SystemExit(accp.main())
'''
        env = dict(os.environ, PYTHONPATH=str(Path(txn.__file__).parent), PYTHONDONTWRITEBYTECODE='1')
        child = subprocess.run([sys.executable, '-B', '-c', code, str(self.cp), str(self.project)],
                               env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(73, child.returncode, child.stderr)
        self.assertEqual('ROLLING_BACK', self.owner.load_activation()['phase'])
        # The terminated process released the OS lock; use the actual parser and handler.
        import accp, io
        from contextlib import redirect_stdout
        with mock.patch.object(accp, 'ROOT', self.cp), mock.patch.object(accp, 'runtime_owner',
                side_effect=AssertionError('recovery must not touch runtime ownership')):
            for flags in ([], [], ['--cleanup'], ['--cleanup']):
                args = accp.parser().parse_args(['recover', '--project', str(self.project), *flags])
                output = io.StringIO()
                with redirect_stdout(output): args.fn(args)
                self.assertTrue(json.loads(output.getvalue()))
        self.assertFalse(self.owner.journal.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows native junction/stream fixture')
    def test_executor_junction_and_stream_refuse_without_target_mutation(self):
        self.switched(); backup = self.workspace/'old'/'alpha'; outside = self.root/'saved-alpha'
        backup.rename(outside)
        result = subprocess.run([os.environ['COMSPEC'], '/c', 'mklink', '/J', str(backup), str(outside)],
                                capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        try:
            for method in (self.recover, self.cleanup):
                with self.assertRaises(txn.JournalError): method()
            self.assertEqual(b'old-alpha', (outside/'SKILL.md').read_bytes())
        finally: backup.rmdir()
        outside.rename(backup)
        stream = str(backup/'SKILL.md') + ':foreign'
        with open(stream, 'wb') as handle: handle.write(b'foreign stream')
        try:
            with self.assertRaises(txn.JournalError): self.recover()
            with open(stream, 'rb') as handle: self.assertEqual(b'foreign stream', handle.read())
        finally: os.unlink(stream)

    def test_metadata_unlink_and_manifest_helpers_enforce_order(self):
        self.switched(old=(), absent=True, missing_metadata=True)
        with self.owner.lifecycle_lock(create=False):
            record = dict(self.record, phase='ROLLING_BACK')
            self.owner.publish_journal(record, self.owner.serialize(self.record))
        before = self.observe()
        with self.owner.lifecycle_lock(create=False):
            with self.assertRaises(txn.JournalError): self.owner._restore_activation_metadata(record, 'state')
        self.assertEqual(before, self.observe())


def publication_fault(phase, after):
    def test(self):
        self.switched(); original = os.replace; seen = []
        if phase in ('CLEANING', 'DONE'): self.recover()
        def fail(src, dst):
            hit = Path(dst) == self.owner.journal and json.loads(Path(src).read_bytes())['phase'] == phase
            if hit and not seen:
                seen.append(True)
                if after: original(src, dst)
                raise OSError('injected phase publication')
            return original(src, dst)
        action = self.cleanup if phase in ('CLEANING', 'DONE') else self.recover
        with mock.patch.object(txn.os, 'replace', side_effect=fail):
            with self.assertRaises(txn.JournalError): action()
        self.assertTrue(seen)
        if after:
            if phase in ('CLEANING', 'DONE'): self.assertTrue(self.cleanup()['finalized'])
            else: self.recover(); self.assert_restored()
        else:
            self.assertTrue(self.owner.journal_pending.exists()); before = self.observe()
            with self.assertRaises(txn.JournalError): action()
            self.assertEqual(before, self.observe())
    return test


def initial_locator_fault(after):
    def test(self):
        self.build(prepared=False); self.owner.locator.unlink(); original = os.replace; seen = []
        def fail(src, dst):
            if Path(dst) == self.owner.locator and not seen:
                seen.append(True)
                if after: original(src, dst)
                raise OSError('injected locator publication')
            return original(src, dst)
        with mock.patch.object(txn.os, 'replace', side_effect=fail):
            with self.assertRaises(txn.JournalError): self.recover()
        self.assertTrue(seen)
        if after:
            self.recover(); self.assert_restored()
        else:
            before = self.observe()
            with self.assertRaises(txn.JournalError): self.recover()
            self.assertEqual(before, self.observe()); self.assertTrue(self.owner.locator_pending.exists())
    return test


def forward_cut_recovery(old_count, new_count, metadata_count):
    def test(self):
        self.build(); self.applying()
        for ident in self.record['old_ids'][:old_count]: self.move_old(ident)
        for ident in self.record['new_ids'][:new_count]: self.move_new(ident)
        for key, path in [('manifest', self.im), ('state', self.state)][:metadata_count]:
            path.write_bytes(txn.snapshot_bytes(self.record['new_' + key]))
        self.recover(); self.assert_restored(); self.cleanup()
        self.assertFalse(self.workspace.exists())
    return test


for _cut in ((0,0,0), (1,0,0), (2,0,0), (2,1,0), (2,2,1)):
    setattr(ActivationRecoveryExecution, 'test_forward_cut_' + '_'.join(map(str, _cut)), forward_cut_recovery(*_cut))
for _after in (False, True):
    setattr(ActivationRecoveryExecution, f'test_initial_locator_publication_{_after}', initial_locator_fault(_after))


for _phase in ('ROLLING_BACK', 'ROLLED_BACK', 'CLEANING', 'DONE'):
    for _after in (False, True):
        setattr(ActivationRecoveryExecution, f'test_publication_{_phase}_{_after}', publication_fault(_phase, _after))


def rollback_fault(target, after):
    def test(self):
        self.switched(old=() if target in ('unlink-state', 'unlink-manifest', 'rmdir-skills') else ('alpha','beta'),
                      absent=target in ('unlink-state', 'unlink-manifest', 'rmdir-skills'),
                      missing_metadata=target in ('unlink-state', 'unlink-manifest', 'rmdir-skills'))
        rename_targets = {'discard-gamma': self.workspace/'discard'/'gamma',
            'discard-alpha': self.workspace/'discard'/'alpha', 'restore-beta': self.skills/'beta',
            'restore-alpha': self.skills/'alpha', 'state': self.state, 'manifest': self.im,
            'rollback-journal': self.owner.journal}
        seen = []
        replace, unlink, rmdir = os.replace, Path.unlink, Path.rmdir
        def crash(call, args, hit):
            if hit and not seen:
                seen.append(True)
                if after: call(*args)
                raise KeyboardInterrupt('simulated process interruption')
            return call(*args)
        def move(src, dst): return crash(replace, (src,dst), Path(dst) == rename_targets.get(target))
        def remove(path, *args, **kwargs):
            hit = path == (self.state if target == 'unlink-state' else self.im if target == 'unlink-manifest' else None)
            return crash(unlink, (path,), hit)
        def directory(path): return crash(rmdir, (path,), target == 'rmdir-skills' and path == self.skills)
        with mock.patch.object(txn.os, 'replace', side_effect=move), mock.patch.object(Path, 'unlink', remove), \
             mock.patch.object(Path, 'rmdir', directory):
            with self.assertRaises(KeyboardInterrupt): self.recover()
        self.assertTrue(seen, 'fault hook did not fire')
        if self.owner.journal_pending.exists() or any(p.exists() for _, p in self.owner.metadata_slots(self.record).values()):
            before = self.observe()
            with self.assertRaises(txn.JournalError): self.recover()
            self.assertEqual(before, self.observe())  # pending bytes must be inspected, never promoted
        else:
            self.recover(); self.assert_restored(); self.assertTrue(self.recover()['noop'])
    return test


for _target in ('discard-gamma','discard-alpha','restore-beta','restore-alpha','state','manifest',
                'rollback-journal','unlink-state','unlink-manifest','rmdir-skills'):
    for _after in (False, True):
        setattr(ActivationRecoveryExecution, f'test_interruption_{_target.replace("-","_")}_{_after}', rollback_fault(_target, _after))


def cleanup_fault(target, after, committed):
    def test(self):
        self.build(); self.committed()
        if not committed:
            self.record['phase'] = 'APPLYING'; self.persist(); self.recover()
        live = txn.activation_observation.tree_observation(self.skills)
        area = 'old' if committed else 'discard'
        paths = {'file': self.workspace/area/'alpha'/'SKILL.md', 'child': self.workspace/area/'alpha',
                 'area': self.workspace/area, 'root': self.workspace,
                 'locator': self.owner.locator, 'journal': self.owner.journal}
        unlink, rmdir = Path.unlink, Path.rmdir; seen = []
        def call(fn, path):
            if path == paths[target] and not seen:
                seen.append(True)
                if after: fn(path)
                raise OSError('injected cleanup failure')
            return fn(path)
        with mock.patch.object(Path, 'unlink', lambda path: call(unlink,path)), \
             mock.patch.object(Path, 'rmdir', lambda path: call(rmdir,path)):
            with self.assertRaises(txn.JournalError): self.cleanup()
        self.assertTrue(seen, 'fault hook did not fire')
        self.assertEqual(live, txn.activation_observation.tree_observation(self.skills))
        if self.owner.journal.exists(): self.assertTrue(self.cleanup()['finalized'])
        else:
            ids = self.record['new_ids'] if committed else self.record['old_ids']
            self.assertTrue(self.owner.cleanup(lambda: {'managed_ids': ids}, lambda: None)['finalized'])
        self.assertEqual(live, txn.activation_observation.tree_observation(self.skills))
        self.assertFalse(self.workspace.exists()); self.assertFalse(self.owner.journal.exists())
    return test


for _target in ('file','child','area','root','locator','journal'):
    for _after in (False, True):
        for _committed in (False, True):
            setattr(ActivationRecoveryExecution, f'test_cleanup_{_target}_{_after}_{_committed}',
                    cleanup_fault(_target, _after, _committed))


if __name__ == '__main__': unittest.main()
