import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import accp
import active_transaction as txn


class TransactionalDeactivate(unittest.TestCase):
    def setUp(self):
        temp = ROOT / '.local' / 'audit-temp'; temp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cp = self.root / 'cp'; self.cp.mkdir()
        self.project = self.root / 'project'; self.project.mkdir()
        patcher = mock.patch.object(accp, 'ROOT', self.cp); patcher.start(); self.addCleanup(patcher.stop)
        self.base = self.project / '.agents'
        self.fixture(self.base, 'project')
        self.owner = txn.JournalAuthority(self.cp, self.project)

    def fixture(self, base, scope):
        skills = base / 'skills'; skills.mkdir(parents=True)
        for name in ('managed', 'personal'):
            (skills / name).mkdir(); (skills / name / 'payload').write_bytes(name.encode())
        (skills / 'personal-file').write_bytes(b'loose file')
        (skills / 'managed' / '.git').mkdir()
        (skills / 'managed' / '.git' / 'payload').write_bytes(b'include in digest')
        manifest = {'schema_version': 1, 'control_plane_path': str(self.cp), 'scope': scope,
                    'project': str(self.project), 'managed_ids': ['managed']}
        state = {'schema_version': 1, 'control_plane_path': str(self.cp), 'active_ids': ['managed']}
        (base / 'install-manifest.json').write_bytes(json.dumps(manifest, indent=3).encode() + b'\r\n')
        (base / 'active-state.json').write_bytes(json.dumps(state).encode() + b'\n\n')

    def call(self, scope='project', dry=False):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(accp, 'runtime_owner', side_effect=AssertionError('runtime touched')):
            accp.cmd_deactivate(Namespace(project=str(self.project), scope=scope, dry_run=dry))
        return json.loads(out.getvalue())

    def test_project_success_exact_snapshots_backups_and_repeat(self):
        old_im = (self.base / 'install-manifest.json').read_bytes()
        old_state = (self.base / 'active-state.json').read_bytes()
        personal = self.base / 'skills' / 'personal'
        personal_id = txn.directory_identity(personal)
        unrelated = self.root / 'other-project'; unrelated.mkdir(); (unrelated / 'keep').write_bytes(b'other')
        runtime = self.root / 'unowned-runtime'; runtime.mkdir(); (runtime / 'keep').write_bytes(b'runtime')
        with mock.patch.dict(os.environ, {'ACCP_RUNTIME_ROOT': str(runtime)}):
            result = self.call()
            self.assertTrue(self.call()['noop'])
        record = self.owner.parse(self.owner.journal.read_bytes())
        self.assertEqual('COMMITTED', record['phase'])
        self.assertEqual(old_im, txn.snapshot_bytes(record['old_manifest']))
        self.assertEqual(old_state, txn.snapshot_bytes(record['old_state']))
        self.assertFalse((self.base / 'skills' / 'managed').exists())
        backup = self.owner.child_path(result['transaction_id'], 'old', 'managed')
        self.assertEqual(b'managed', (backup / 'payload').read_bytes())
        self.assertEqual(personal_id, txn.directory_identity(personal))
        self.assertEqual(b'personal', (personal / 'payload').read_bytes())
        self.assertEqual(b'loose file', (self.base / 'skills' / 'personal-file').read_bytes())
        self.assertEqual(b'other', (unrelated / 'keep').read_bytes())
        self.assertEqual(b'runtime', (runtime / 'keep').read_bytes())

    def test_user_scope_keeps_project_active_set(self):
        user = self.root / 'user-active'; self.fixture(user, 'user')
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT': str(user)}):
            self.call('user'); self.assertTrue(self.call('user')['noop'])
        self.assertFalse((user / 'skills' / 'managed').exists())
        self.assertTrue((self.base / 'skills' / 'managed').exists())

    def test_publication_phase_and_live_move_order(self):
        events = []; publish = txn.JournalAuthority.publish_journal
        locator = txn.JournalAuthority.publish_locator; replace = txn.os.replace
        def journal(owner, record, previous=None):
            owner._assert_locked(); result = publish(owner, record, previous)
            events.append(record['phase']); return result
        def locate(owner, record):
            result = locator(owner, record); events.append('LOCATOR'); return result
        def move(source, destination):
            if Path(source) == self.base / 'skills' / 'managed': events.append('MOVE')
            if Path(destination) == self.base / 'install-manifest.json': events.append('MANIFEST')
            if Path(destination) == self.base / 'active-state.json': events.append('STATE')
            return replace(source, destination)
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=journal), \
                mock.patch.object(txn.JournalAuthority, 'publish_locator', autospec=True, side_effect=locate), \
                mock.patch.object(txn.os, 'replace', side_effect=move):
            self.call()
        self.assertEqual(['PREPARING', 'LOCATOR', 'PREPARED', 'APPLYING', 'MOVE', 'MANIFEST', 'STATE', 'COMMITTED'], events)

    def test_metadata_failure_retains_switch_evidence_and_refuses_retry(self):
        publish = txn.JournalAuthority._publish
        def fail(owner, target, *args, **kwargs):
            if target == self.base / 'active-state.json': raise OSError('injected state failure')
            return publish(owner, target, *args, **kwargs)
        with mock.patch.object(txn.JournalAuthority, '_publish', autospec=True, side_effect=fail):
            with self.assertRaisesRegex(txn.JournalError, 'requires inspection/recovery'): self.call()
        record = self.owner.parse(self.owner.journal.read_bytes())
        self.assertEqual('APPLYING', record['phase'])
        backup = self.owner.child_path(record['transaction_id'], 'old', 'managed')
        self.assertTrue(backup.exists()); self.assertTrue(self.owner.locator.exists())
        before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_pending_foreign_and_identity_mismatch_refuse_without_mutation(self):
        self.call(); original = self.owner.journal.read_bytes()
        for key, value in [('phase', 'UNKNOWN'), ('project_path', str(self.root / 'other')),
                           ('base_identity', {'device': '1', 'inode': '2'})]:
            record = json.loads(original); record[key] = value
            self.owner.journal.write_text(json.dumps(record))
            before = self.owner.journal.read_bytes()
            with self.assertRaises(txn.JournalError): self.call()
            self.assertEqual(before, self.owner.journal.read_bytes())
        self.owner.journal.write_bytes(original)

    def test_lock_contention_dry_run_and_legacy_activation_gate(self):
        self.assertEqual('UNCOORDINATED',self.call(dry=True)['lifecycle'])
        self.assertFalse(self.owner.lock_path.exists())
        with self.owner.lifecycle_lock():
            with self.assertRaises(txn.JournalError): self.call()
        self.assertFalse(self.owner.journal.exists())
        with self.assertRaisesRegex(RuntimeError, 'transactional lifecycle'):
            accp.acquire_lock(self.owner)
        self.assertFalse((self.base / '.accp-activate.lock').exists())

    def test_digest_includes_git_and_backup_replacement_refuses_repeat(self):
        source = self.base / 'skills' / 'managed'
        before = txn.observed_tree(source)
        (source / '.git' / 'payload').write_bytes(b'changed')
        self.assertNotEqual(before['sha256'], txn.observed_tree(source)['sha256'])
        result = self.call(); backup = self.owner.child_path(result['transaction_id'], 'old', 'managed')
        backup.rename(backup.with_name('saved')); backup.mkdir()
        with self.assertRaises(txn.JournalError): self.call()

    def test_uninitialized_noop_does_not_create_lifecycle_state(self):
        (self.base / 'install-manifest.json').unlink()
        (self.base / 'active-state.json').unlink()
        self.assertTrue(self.call()['noop'])
        self.assertFalse(self.owner.lock_path.exists())
        self.assertFalse(self.owner.journal.exists())
        self.assertTrue((self.base / 'skills' / 'managed').exists())  # unclaimed, preserved


if __name__ == '__main__':
    unittest.main()
