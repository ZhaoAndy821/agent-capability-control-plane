"""Focused F06 M3 activation-attempt context tests.

These tests compose the disposable F05 Admission fixture.  They intentionally
exercise the public activation boundary and record the complete live tree so a
failed proof check cannot leave a partial switch behind.
"""
import copy
import hashlib
import io
import os
import pathlib
import shutil
import sys
import unittest
from contextlib import nullcontext, contextmanager
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import accp
import active_transaction as txn
import test_admission as admission_fixture


class ActivationContext(unittest.TestCase):
    def setUp(self):
        self.fixture = admission_fixture.Admission()
        self.fixture.setUp()
        self.fixture.setup_provider()
        self.addCleanup(self.fixture.doCleanups)
        self.args = self.fixture.args
        self.paths = accp.active_paths(self.fixture.project, 'project')

    def tree(self, path):
        result = {}
        if not path.exists():
            return result
        for p in sorted(path.rglob('*')):
            st = p.lstat()
            result[str(p.relative_to(path))] = (st.st_dev, st.st_ino, st.st_mode,
                                                p.read_bytes() if p.is_file() else None)
        return result

    def live_snapshot(self):
        return accp.activation.live_observation(self.paths)

    def finalize(self):
        owner=txn.JournalAuthority(accp.ROOT,self.fixture.project)
        owner.cleanup(lambda:accp.read_install_manifest(*self.paths[:4],self.args.project,self.args.scope),lambda:None)

    def lock_hook(self, callback):
        original=txn.JournalAuthority.lifecycle_lock
        @contextmanager
        def held(owner,create=True):
            with original(owner,create=create):
                callback(owner)
                yield owner
        return mock.patch.object(txn.JournalAuthority,"lifecycle_lock",held)

    def run_activate(self, runtime=True):
        with self.fixture.fake_runtime() if runtime else nullcontext(), redirect_stdout(io.StringIO()):
            return accp.cmd_activate(self.args)

    def test_repeated_activations_use_independent_attempts(self):
        self.run_activate()
        first = accp.activation.content_rows(accp.activation.tree_observation(self.paths[1]))
        self.finalize()
        self.run_activate()
        self.assertEqual(first, accp.activation.content_rows(accp.activation.tree_observation(self.paths[1])))

    def test_fake_or_missing_attempt_refuses_activate_plan_without_mutation(self):
        before = self.live_snapshot()
        for token in (None, 'fake-token'):
            with self.subTest(token=token), self.assertRaises((RuntimeError,txn.JournalError)):
                accp.activate_plan(self.args, self.fixture.plan, self.paths, attempt=token)
            self.assertEqual(before, self.live_snapshot())

    def test_runtime_and_lock_revalidation_rejects_eligible_catalog_drift(self):
        before = self.live_snapshot()
        with self.fixture.fake_runtime(on_enter=self._eligible_drift):
            with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'context/binding changed'):
                self.run_activate(runtime=False)
        self.assertEqual(before, self.live_snapshot())

    def _eligible_drift(self):
        self.fixture.change_entry(notes='changed during activation')
        lock = self.fixture.lock(accp.catalog_index(strict=True)['fixture'])
        self.fixture._write(accp.LOCK, {'schema_version': 2, 'sources': {'fixture': lock}})

    def test_acquire_lock_project_policy_drift_releases_original_lock(self):
        before = self.live_snapshot()
        def drift(authority):
            self.fixture._write(self.fixture.project / '.codex-skillset.json',
                                {'schema_version': 1, 'allow': []})
        with self.lock_hook(drift):
            with self.assertRaises((RuntimeError,txn.JournalError)):
                self.run_activate()
        self.assertEqual(before, self.live_snapshot())
        self.assertFalse(self.paths[4].exists())

    def test_copytree_stage_tampering_refuses_before_live_switch(self):
        before = self.live_snapshot()
        original = shutil.copytree
        def tamper(src, dst, *args, **kwargs):
            result = original(src, dst, *args, **kwargs)
            if pathlib.Path(src) == accp.VAULT / 'fixture':
                (pathlib.Path(dst) / 'SKILL.md').write_bytes(b'tampered')
                (pathlib.Path(dst) / 'agents').mkdir(exist_ok=True)
                (pathlib.Path(dst) / 'agents' / 'openai.yaml').write_text('bad')
            return result
        with mock.patch.object(accp.shutil, 'copytree', side_effect=tamper):
            with self.assertRaises((RuntimeError,txn.JournalError)):
                self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_vault_or_manifest_change_after_copy_is_rejected(self):
        before = self.live_snapshot()
        original = shutil.copytree
        def copy_and_change(src, dst, *args, **kwargs):
            result = original(src, dst, *args, **kwargs)
            if pathlib.Path(src) == accp.VAULT / 'fixture':
                (accp.VAULT / 'fixture' / 'SKILL.md').write_bytes(b'changed-after-copy')
            return result
        with mock.patch.object(accp.shutil, 'copytree', side_effect=copy_and_change):
            with self.assertRaises((RuntimeError,txn.JournalError)):
                self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_attempt_replay_and_cross_attempt_reuse_refused(self):
        attempts = []
        original = accp.activate_plan
        def observe(args, plan, paths, *, attempt=None):
            if attempts:
                before = self.live_snapshot()
                with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'current activation attempt required'):
                    original(args, plan, paths, attempt=attempts[0])
                self.assertEqual(before, self.live_snapshot())
            attempts.append(attempt)
            return original(args, plan, paths, attempt=attempt)
        with mock.patch.object(accp, 'activate_plan', side_effect=observe):
            self.run_activate()
            self.finalize()
            self.run_activate()
        self.assertNotEqual(attempts[0].nonce, attempts[1].nonce)
        for attempt in attempts:
            self.assertEqual(attempt.phase, 'expired')
            self.assertNotIn(attempt, accp._activation_attempts)
            with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'missing, stale or consumed'):
                attempt.validate(self.args, self.fixture.plan, self.paths)

    def test_candidate_project_scope_and_flags_cannot_change_after_issue(self):
        original = accp.activate_plan
        for field, value in [('project', str(self.fixture.root)), ('scope', 'user'),
                             ('mode', 'foreign'), ('allow_partial', True)]:
            args = copy.copy(self.args)
            before = self.live_snapshot()
            def substitute(received, plan, paths, *, attempt=None):
                setattr(received, field, value)
                return original(received, plan, paths, attempt=attempt)
            with self.subTest(field=field), self.fixture.fake_runtime(), \
                    mock.patch.object(accp, 'activate_plan', side_effect=substitute):
                with self.assertRaises((RuntimeError,txn.JournalError)):
                    accp.cmd_activate(args)
            self.assertEqual(before, self.live_snapshot())
        def substitute_candidate(args, plan, paths, *, attempt=None):
            return original(args, dict(plan, providers=[]), paths, attempt=attempt)
        with mock.patch.object(accp, 'activate_plan', side_effect=substitute_candidate):
            with self.assertRaises((RuntimeError,txn.JournalError)): self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_repository_identity_change_refuses_before_stage(self):
        original = accp.binding.directory_identity
        armed = False
        def identity(path):
            result = original(path)
            if armed and pathlib.Path(path) == self.fixture.root:
                return dict(result, inode=str(int(result['inode']) + 1))
            return result
        def change(authority):
            nonlocal armed
            armed = True
        before = self.live_snapshot()
        with mock.patch.object(accp.binding, 'directory_identity', side_effect=identity), \
                self.lock_hook(change):
            with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'identity|directory|binding'):
                self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_project_directory_replacement_is_not_adopted(self):
        old=self.fixture.root/'retained-project'
        original=accp.activate_plan
        def replace(args,plan,paths,*,attempt=None):
            self.fixture.project.rename(old)
            shutil.copytree(old,self.fixture.project)
            return original(args,plan,paths,attempt=attempt)
        with mock.patch.object(accp,'activate_plan',side_effect=replace):
            with self.assertRaisesRegex((RuntimeError,txn.JournalError),'identity|directory|binding'):
                self.run_activate()
        self.assertFalse(self.paths[1].exists())
        self.assertTrue(old.exists())

    def at_provider_copy(self, mutate):
        original = shutil.copytree
        def changed(src, dst, *args, **kwargs):
            result = original(src, dst, *args, **kwargs)
            if pathlib.Path(src) == accp.VAULT / 'fixture': mutate(pathlib.Path(dst))
            return result
        return mock.patch.object(accp.shutil, 'copytree', side_effect=changed)

    def test_deploy_path_drift_after_staging_refused(self):
        before = self.live_snapshot()
        with self.at_provider_copy(lambda _: self.fixture.change_entry(deploy={
                'deployable': True, 'skill_name': 'fixture', 'path': 'other'})):
            with self.assertRaises((RuntimeError,txn.JournalError)): self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_same_bytes_replacement_of_vault_child_refused(self):
        old = self.fixture.root / 'retained-provider'
        before = self.live_snapshot()
        def replace(_):
            provider = accp.VAULT / 'fixture'
            provider.rename(old); shutil.copytree(old, provider)
        with self.at_provider_copy(replace):
            with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'Vault identity/state changed'):
                self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_ready_receipt_drift_after_staging_refused(self):
        before = self.live_snapshot()
        def change(_):
            self.fixture.fixture_rb['runtime_id'] = '00000000-0000-4000-8000-000000000001'
        with self.at_provider_copy(change):
            with self.assertRaises((RuntimeError,txn.JournalError)): self.run_activate()
        self.assertEqual(before, self.live_snapshot())

    def test_staged_junction_is_preserved_without_following_cleanup(self):
        if os.name != 'nt': self.skipTest('Windows junction only')
        import subprocess
        outside = self.fixture.root / 'unrelated'; outside.mkdir()
        (outside / 'keep').write_bytes(b'unrelated')
        junctions = []
        def redirect(dst):
            junction = dst / 'redirect'
            result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(junction), str(outside)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            junctions.append(junction)
        try:
            with self.at_provider_copy(redirect):
                with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'link/reparse'):
                    self.run_activate()
            self.assertEqual((outside / 'keep').read_bytes(), b'unrelated')
            self.assertTrue(junctions[0].exists())  # uncertain cleanup is retained
            self.assertFalse(self.paths[1].exists())
        finally:
            for junction in junctions: junction.rmdir()  # remove the junction, never its target

    def test_unsafe_project_spellings_refused_without_runtime_access(self):
        before = self.live_snapshot()
        for spelling in ('C:relative', r'\\server\share', r'\\?\C:\device',
                         str(self.fixture.project / '..' / 'project')):
            with self.subTest(spelling=spelling), mock.patch.object(accp, 'runtime_owner') as runtime:
                args = copy.copy(self.args); args.project = spelling
                with self.assertRaises((RuntimeError, OSError)): accp.cmd_activate(args)
                runtime.assert_not_called()
            self.assertEqual(before, self.live_snapshot())

    def test_independently_valid_rebound_source_or_path_is_stale_for_attempt(self):
        def rebind(field):
            ab = accp.binding
            cat = accp.readj(accp.CATALOG, strict=True)
            locks = accp.readj(accp.LOCK, strict=True)
            ev_path = self.fixture.evidence_dir / 'fixture.json'
            ev = ab.decode_evidence(ev_path.read_bytes())
            if field == 'source_tree_oid': ev['candidate'][field] = 'b' * 40
            else:
                ev['candidate']['deploy_path'] = 'other'
                cat['entries'][0]['deploy']['path'] = 'other'
                locks['sources']['fixture']['deploy_path'] = 'other'
                ev['candidate']['catalog_sha256'] = ab.catalog_digest(cat['entries'][0])
            ev['candidate_sha256'] = ab.digest('accp-candidate-v1', ev['candidate'])
            data = ab.encode_evidence(ev)
            ev_path.write_bytes(data)
            locks['sources']['fixture']['binding']['candidate_sha256'] = ev['candidate_sha256']
            locks['sources']['fixture']['evidence_sha256'] = hashlib.sha256(data).hexdigest()
            self.fixture._write(accp.CATALOG, cat); self.fixture._write(accp.LOCK, locks)
            # A completely fresh resolution accepts the new reviewed record.
            self.assertEqual(accp.resolve_plan('smoke', self.fixture.project)['providers'], ['fixture'])
        for index,field in enumerate(('source_tree_oid', 'deploy_path')):
            if index:
                self.fixture.doCleanups(); self.setUp()
            before = self.live_snapshot()
            with self.subTest(field=field), self.at_provider_copy(lambda _: rebind(field)):
                with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'context/binding changed'):
                    self.run_activate()
            self.assertEqual(before, self.live_snapshot())

    def test_unissued_object_and_failed_attempt_cannot_authorize(self):
        attempt = accp.activation.ActivationAttempt(accp, self.args, self.fixture.plan)
        with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'current activation attempt required'):
            accp.activate_plan(self.args, self.fixture.plan, self.paths, attempt=attempt)
        saved = []
        original = accp.activate_plan
        def capture(args, plan, paths, *, attempt=None):
            saved.append(attempt)
            return original(args, plan, paths, attempt=attempt)
        with mock.patch.object(accp, 'activate_plan', side_effect=capture), \
                self.at_provider_copy(lambda p: (p / 'SKILL.md').write_bytes(b'corrupt')):
            with self.assertRaises((RuntimeError,txn.JournalError)): self.run_activate()
        self.assertEqual(saved[0].phase, 'expired')
        with self.assertRaisesRegex((RuntimeError,txn.JournalError), 'current activation attempt required'):
            accp.activate_plan(self.args, self.fixture.plan, self.paths, attempt=saved[0])

    def test_final_proof_is_checked_under_both_locks_before_first_switch(self):
        # Exact-byte mutation oracles include prior managed and unrelated content.
        self.run_activate()
        self.finalize()
        personal = self.paths[1] / 'personal'; personal.mkdir()
        (personal / 'keep').write_bytes(b'keep\x00\xff')
        events = []
        original_validate = accp.activation.ActivationAttempt.validate
        original_replace = os.replace
        def checked(attempt, args, plan, paths, stage=None):
            result = original_validate(attempt, args, plan, paths, stage=stage)
            if stage is not None:
                self.assertTrue(attempt.runtime_held)
                self.assertIsNotNone(attempt.authority._held)
                self.assertEqual(attempt.phase, 'running')
                events.append('final-proof')
            return result
        def replace(src, dst):
            if pathlib.Path(src).parent == self.paths[1]:
                self.assertEqual(events, ['final-proof'])
                attempt = next(iter(accp._activation_attempts))
                self.assertEqual(attempt.phase, 'consumed')
                self.assertIsNotNone(attempt.authority._held)
                events.append('switch')
            return original_replace(src, dst)
        with mock.patch.object(accp.activation.ActivationAttempt, 'validate', new=checked), \
                mock.patch.object(accp.os, 'replace', side_effect=replace):
            self.run_activate()
        self.assertEqual(events, ['final-proof', 'switch'])
        self.assertEqual((personal / 'keep').read_bytes(), b'keep\x00\xff')

    def test_user_scope_preserves_original_override_refusals(self):
        self.args.scope = 'user'
        before = self.live_snapshot()
        for raw in ('relative-root', 'C:relative', r'\\server\share', r'\\?\C:\device',
                    str(self.fixture.root / '..' / 'user')):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT':raw}), \
                    mock.patch.object(accp, 'runtime_owner') as runtime:
                with self.assertRaises((RuntimeError, OSError)): accp.cmd_activate(self.args)
                runtime.assert_not_called()
            self.assertEqual(before, self.live_snapshot())

    def test_valid_user_scope_still_activates(self):
        self.args.scope = 'user'
        user_root = self.fixture.root / 'user-root'
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT':str(user_root)}):
            self.run_activate()
            expected = (accp.VAULT / 'fixture' / 'SKILL.md').read_bytes()
            self.assertEqual((user_root / 'skills' / 'fixture' / 'SKILL.md').read_bytes(), expected)
            self.assertFalse((user_root / '.accp-activate.lock').exists())

    def test_user_scope_root_change_after_lock_is_rejected(self):
        before = self.live_snapshot()
        user_root = self.fixture.root / 'user-root'
        user_root.mkdir()
        self.args.scope = 'user'
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT': str(user_root)}):
            def drift(authority):
                os.environ['ACCP_USER_SCOPE_ROOT'] = str(self.fixture.root / 'other-root')
            with self.lock_hook(drift):
                with self.assertRaises((RuntimeError,txn.JournalError)):
                    self.run_activate()
        self.assertEqual(before, self.live_snapshot())


if __name__ == '__main__':
    unittest.main()
