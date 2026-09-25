import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import accp
import active_transaction as txn


class DeactivateRecovery(unittest.TestCase):
    def setUp(self):
        temp = ROOT / '.local' / 'audit-temp'; temp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cp = self.root / 'cp'; self.cp.mkdir()
        self.project = self.root / 'project'; self.project.mkdir()
        self.base = self.project / '.agents'; self.skills = self.base / 'skills'
        self.skills.mkdir(parents=True)
        for name in ('alpha', 'beta', 'personal'):
            (self.skills / name).mkdir(); (self.skills / name / 'payload').write_bytes(name.encode())
        self.im = self.base / 'install-manifest.json'; self.state = self.base / 'active-state.json'
        self.im.write_bytes(json.dumps({'schema_version': 1, 'control_plane_path': str(self.cp),
            'project': str(self.project), 'scope': 'project', 'managed_ids': ['alpha', 'beta']}, indent=3).encode() + b'\r\n')
        self.state.write_bytes(json.dumps({'schema_version': 1, 'control_plane_path': str(self.cp),
                                         'active_ids': ['alpha', 'beta']}).encode() + b'\n\n')
        self.old_im, self.old_state = self.im.read_bytes(), self.state.read_bytes()
        self.identities = {name: txn.directory_identity(self.skills / name) for name in ('alpha', 'beta', 'personal')}
        patcher = mock.patch.object(accp, 'ROOT', self.cp); patcher.start(); self.addCleanup(patcher.stop)
        self.owner = txn.JournalAuthority(self.cp, self.project)

    def call(self, command='recover', extra=()):
        args = accp.parser().parse_args([command, '--project', str(self.project), *extra])
        output = io.StringIO()
        with redirect_stdout(output), mock.patch.object(accp, 'runtime_owner', side_effect=AssertionError('runtime accessed')):
            args.fn(args)
        return json.loads(output.getvalue())

    def interrupt(self, phase='COMMITTED', after=False):
        original = txn.JournalAuthority.publish_journal
        def stop(owner, record, previous=None):
            if record['phase'] == phase:
                if after: original(owner, record, previous)
                raise OSError('test interruption')
            return original(owner, record, previous)
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.call('deactivate')
        return self.owner.parse(self.owner.journal.read_bytes())

    def assert_restored(self):
        self.assertEqual(self.old_im, self.im.read_bytes())
        self.assertEqual(self.old_state, self.state.read_bytes())
        for name, identity in self.identities.items():
            self.assertEqual(identity, txn.directory_identity(self.skills / name))
            self.assertEqual(name.encode(), (self.skills / name / 'payload').read_bytes())
        record = self.owner.parse(self.owner.journal.read_bytes())
        self.assertEqual('ROLLED_BACK', record['phase'])
        self.assertTrue(self.owner.locator.exists()); self.assertTrue(self.owner.lock_path.exists())
        return record

    def test_order_exact_restore_and_repeated_recovery(self):
        self.interrupt(); events = []
        publish = txn.JournalAuthority.publish_journal; replace = txn.os.replace
        def journal(owner, record, previous=None):
            owner._assert_locked(); result = publish(owner, record, previous)
            events.append(record['phase']); return result
        def move(source, destination):
            if Path(source).parent.name == 'old': events.append('restore-' + Path(source).name)
            if Path(destination) == self.state: events.append('state')
            if Path(destination) == self.im: events.append('manifest')
            return replace(source, destination)
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=journal), \
                mock.patch.object(txn.os, 'replace', side_effect=move):
            self.assertTrue(self.call()['rolled_back'])
        self.assertEqual(['ROLLING_BACK', 'restore-beta', 'restore-alpha', 'state', 'manifest', 'ROLLED_BACK'], events)
        self.assert_restored()
        before = self.owner.journal.read_bytes()
        self.assertTrue(self.call()['noop']); self.assert_restored()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_prepared_noop_rollback(self):
        self.interrupt('PREPARED', after=True)
        self.call(); self.assert_restored()

    def test_pristine_preparing_missing_locator_and_dry_run(self):
        self.interrupt('PREPARING', after=True)
        before = self.owner.journal.read_bytes()
        report=self.call(extra=['--dry-run'])
        self.assertEqual('RECOVERY_REQUIRED',report['lifecycle'])
        self.assertEqual('rollback',report['preview']['action'])
        self.assertFalse(self.owner.locator.exists())
        self.assertEqual(before, self.owner.journal.read_bytes())
        self.call(); record = self.assert_restored()
        self.assertFalse(self.owner.workspace(record['transaction_id']).exists())

    def test_unregistered_workspace_refused(self):
        self.interrupt('PREPARED')
        before = self.owner.journal.read_bytes()
        with self.assertRaisesRegex(txn.JournalError, 'unregistered workspace'): self.call()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_committed_is_never_rolled_back(self):
        self.call('deactivate')
        before = self.owner.journal.read_bytes()
        result = self.call()
        self.assertTrue(result['committed']); self.assertFalse(result['rolled_back'])
        self.assertFalse((self.skills / 'alpha').exists())
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_mixed_metadata_new_state_old_manifest(self):
        self.interrupt(); self.im.write_bytes(self.old_im)
        self.call(); self.assert_restored()

    def test_mixed_metadata_old_state_new_manifest(self):
        self.interrupt(); self.state.write_bytes(self.old_state)
        self.call(); self.assert_restored()

    def test_third_metadata_bytes_refuse_before_restore(self):
        self.interrupt(); self.state.write_bytes(b'foreign bytes')
        before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertFalse((self.skills / 'alpha').exists())
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_failed_restore_retries_only_remaining_backup(self):
        self.interrupt(); replace = txn.os.replace
        def fail(source, destination):
            if Path(source).parent.name == 'old' and Path(source).name == 'alpha':
                raise OSError('restore denied')
            return replace(source, destination)
        for _ in range(2):
            with mock.patch.object(txn.os, 'replace', side_effect=fail), self.assertRaises(txn.JournalError): self.call()
            self.assertTrue((self.skills / 'beta').exists())
            self.assertFalse((self.skills / 'alpha').exists())
        self.call(); self.assert_restored()

    def test_rollback_metadata_failure_retains_retryable_mixture(self):
        record = self.interrupt(); publish = txn.JournalAuthority._publish
        def fail(owner, target, *args, **kwargs):
            if target == self.im: raise OSError('manifest restore denied')
            return publish(owner, target, *args, **kwargs)
        with mock.patch.object(txn.JournalAuthority, '_publish', autospec=True, side_effect=fail):
            with self.assertRaises(txn.JournalError): self.call()
        self.assertEqual(self.old_state, self.state.read_bytes())
        with mock.patch.object(txn, 'sync_directory', wraps=txn.sync_directory) as sync:
            self.call()
        flushed = [args.args[0] for args in sync.call_args_list]
        self.assertIn(self.skills, flushed)
        self.assertIn(self.owner.workspace(record['transaction_id']) / 'old', flushed)
        self.assert_restored()

    def test_malformed_foreign_traversal_and_wrong_identity(self):
        record = self.interrupt(); original = self.owner.journal.read_bytes()
        for key, value in [('project_path', str(self.root)), ('phase', 'UNKNOWN'),
                           ('old_ids', ['../escape']), ('base_identity', {'device': '1', 'inode': '2'})]:
            changed = dict(record); changed[key] = value
            raw = json.dumps(changed).encode(); self.owner.journal.write_bytes(raw)
            with self.subTest(key=key), self.assertRaises(txn.JournalError): self.call()
            self.assertEqual(raw, self.owner.journal.read_bytes())
        for raw in (b'{partial', b'{"phase":"APPLYING","phase":"COMMITTED"}'):
            self.owner.journal.write_bytes(raw)
            with self.assertRaises(txn.JournalError): self.call()
        self.owner.journal.write_bytes(original)
        self.assertFalse((self.skills / 'alpha').exists())

    def test_all_pending_slots_refuse_without_adoption(self):
        record = self.interrupt(); before = self.owner.journal.read_bytes()
        paths = [self.owner.journal_pending, self.owner.locator_pending]
        paths += [pending for _, pending in self.owner.metadata_slots(record).values()]
        for path in paths:
            path.write_bytes(before)  # even complete valid-looking bytes grant no authority
            with self.subTest(path=path.name), self.assertRaises(txn.JournalError): self.call()
            self.assertEqual(before, path.read_bytes()); path.unlink()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_lock_contention_and_missing_lock_refuse(self):
        self.interrupt()
        with self.owner.lifecycle_lock():
            with self.assertRaises(txn.JournalError): self.call()
        self.owner.lock_path.unlink()
        with self.assertRaises(FileNotFoundError): self.call()
        self.assertFalse(self.owner.lock_path.exists())

    def test_replaced_backup_and_duplicate_live_refuse(self):
        record = self.interrupt()
        (self.skills / 'alpha').mkdir()
        with self.assertRaises(txn.JournalError): self.call()
        (self.skills / 'alpha').rmdir()
        backup = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        backup.rename(self.root / 'saved-alpha'); backup.mkdir()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertFalse((self.skills / 'beta').exists())

    def test_missing_locator_after_switch_is_not_repaired(self):
        self.interrupt(); self.owner.locator.unlink()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertFalse(self.owner.locator.exists())

    def test_missing_metadata_refuses_before_restoring_any_child(self):
        self.interrupt(); self.state.unlink()
        before = self.owner.journal.read_bytes()
        with self.assertRaises(FileNotFoundError): self.call()
        self.assertFalse((self.skills / 'alpha').exists())
        self.assertFalse((self.skills / 'beta').exists())
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_prepared_phase_with_switched_children_is_a_conflict(self):
        record = self.interrupt(); record['phase'] = 'PREPARED'
        self.owner.journal.write_bytes(self.owner.serialize(record))
        before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertFalse((self.skills / 'alpha').exists())
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_no_records_noop_is_readonly_but_orphan_refuses(self):
        before = {p.relative_to(self.base).as_posix(): p.read_bytes()
                  for p in self.base.rglob('*') if p.is_file()}
        self.assertTrue(self.call()['noop'])
        self.assertFalse(self.owner.lock_path.exists()); self.assertFalse(self.owner.store.exists())
        self.assertEqual(before, {p.relative_to(self.base).as_posix(): p.read_bytes()
                                 for p in self.base.rglob('*') if p.is_file()})
        (self.base / '.accp-txn-orphan').mkdir()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertTrue((self.base / '.accp-txn-orphan').exists())

    def test_unrelated_data_and_unowned_runtime_are_untouched(self):
        other = self.root / 'other-project'; other.mkdir(); (other / 'keep').write_bytes(b'other')
        runtime = self.root / 'legacy-runtime'; runtime.mkdir(); (runtime / 'keep').write_bytes(b'runtime')
        self.interrupt()
        with mock.patch.dict(os.environ, {'ACCP_RUNTIME_ROOT': str(runtime)}): self.call()
        self.assert_restored()
        self.assertEqual(b'other', (other / 'keep').read_bytes())
        self.assertEqual(b'runtime', (runtime / 'keep').read_bytes())

    def child(self, action, boundary):
        code = ('import sys,os; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                'import accp; accp.ROOT=Path(sys.argv[2]); import active_transaction as txn; '
                'original=txn.os.replace\n'
                'def stop(src,dst):\n'
                ' result=original(src,dst)\n'
                ' if (sys.argv[5]=="move" and Path(src).parent.name==("skills" if sys.argv[4]=="deactivate" else "old")) '
                'or (sys.argv[5]=="state" and Path(dst).name=="active-state.json"): os._exit(73)\n'
                ' return result\n'
                'txn.os.replace=stop\n'
                'args=accp.parser().parse_args([sys.argv[4],"--project",sys.argv[3]])\n'
                'args.fn(args)\n')
        return subprocess.run([sys.executable, '-B', '-c', code, str(ROOT / 'scripts'), str(self.cp),
                               str(self.project), action, boundary], capture_output=True, timeout=20)

    def test_process_exit_after_forward_move_then_recovery(self):
        result = self.child('deactivate', 'move')
        self.assertEqual(73, result.returncode, result.stderr)
        self.call(); self.assert_restored()

    def test_process_exit_during_restore_then_repeated_recovery(self):
        self.interrupt(); result = self.child('recover', 'move')
        self.assertEqual(73, result.returncode, result.stderr)
        self.call(); self.assert_restored()

    def test_process_exit_after_state_restoration(self):
        self.interrupt(); result = self.child('recover', 'state')
        self.assertEqual(73, result.returncode, result.stderr)
        self.call(); self.assert_restored()

    def test_user_scope_recovery_preserves_project_scope(self):
        self.interrupt()
        # Initialize a separate user-scope fixture; project recovery stays pending.
        user = self.root / 'user-active'; user.mkdir(); (user / 'skills').mkdir()
        for name in ('alpha', 'beta'):
            (user / 'skills' / name).mkdir(); (user / 'skills' / name / 'payload').write_bytes(name.encode())
        manifest = json.loads(self.old_im); manifest['scope'] = 'user'
        (user / 'install-manifest.json').write_bytes(json.dumps(manifest).encode())
        (user / 'active-state.json').write_bytes(self.old_state)
        original = txn.JournalAuthority.publish_journal
        def stop(owner, record, previous=None):
            if record['phase'] == 'COMMITTED': raise OSError('stop user commit')
            return original(owner, record, previous)
        project_journal = self.owner.journal.read_bytes()
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT': str(user)}):
            with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=stop):
                with self.assertRaises(txn.JournalError): self.call('deactivate', ['--scope', 'user'])
            self.assertTrue(self.call(extra=['--scope', 'user'])['rolled_back'])
            self.assertTrue(self.call(extra=['--scope', 'user'])['noop'])
        self.assertEqual(project_journal, self.owner.journal.read_bytes())
        self.assertTrue((user / 'skills' / 'alpha').exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows junction fixture')
    def test_backup_junction_is_refused(self):
        record = self.interrupt(); backup = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        outside = self.root / 'saved-alpha'; backup.rename(outside)
        result = subprocess.run([os.environ['COMSPEC'], '/c', 'mklink', '/J', str(backup), str(outside)], capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        try:
            with self.assertRaises(txn.JournalError): self.call()
            self.assertEqual(b'alpha', (outside / 'payload').read_bytes())
        finally:
            backup.rmdir()


if __name__ == '__main__':
    unittest.main()
