"""FR01: real activation must not bypass external authority after marker loss."""
import io
import json
import os
from pathlib import Path
from contextlib import redirect_stdout
import unittest
from unittest import mock
import uuid

import test_deactivate_recovery as recovery_fixture
import accp
import active_transaction as txn


class ActivationAuthority(unittest.TestCase):
    # Reuse only the disposable fixture helpers, not its test methods.
    call = recovery_fixture.DeactivateRecovery.call
    interrupt = recovery_fixture.DeactivateRecovery.interrupt

    def setUp(self):
        recovery_fixture.DeactivateRecovery.setUp(self)
        self._set_up_resolver_fixtures()

    def _set_up_resolver_fixtures(self):
        fixture_paths = {
            'CATALOG': self.cp / 'registry' / 'catalog.json',
            'LOCK': self.cp / 'lock' / 'sources.lock.json',
            'CONFLICTS': self.cp / 'registry' / 'conflict-groups.json',
            'OP_MODES': self.cp / 'modes' / 'operational-modes.json',
        }
        for path in fixture_paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        fixture_paths['CATALOG'].write_text(
            json.dumps({'schema_version': 2, 'entries': []}) + '\n', encoding='utf-8')
        fixture_paths['LOCK'].write_text(
            json.dumps({'schema_version': 2, 'sources': {}}) + '\n', encoding='utf-8')
        fixture_paths['CONFLICTS'].write_text(
            json.dumps({'schema_version': 2, 'groups': {}}) + '\n', encoding='utf-8')
        fixture_paths['OP_MODES'].write_text(json.dumps({
            'schema_version': 1,
            'modes': {'fixture': {'providers': []}, 'audit': {'providers': []}},
        }) + '\n', encoding='utf-8')
        patchers = [mock.patch.object(accp, name, path)
                    for name, path in fixture_paths.items()]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def activate(self, scope='project', providers=()):
        args = accp.parser().parse_args(['activate', '--mode', 'fixture',
            '--project', str(self.project), '--scope', scope])
        with redirect_stdout(io.StringIO()):
            accp.cmd_activate(args)

    def remove_indicators(self, lock=True, locator=True):
        if lock: self.owner.lock_path.unlink(missing_ok=True)
        if locator: self.owner.locator.unlink(missing_ok=True)

    def snapshot(self):
        result = {}
        for path in sorted(self.root.rglob('*')):
            info = path.lstat()
            result[str(path.relative_to(self.root))] = (
                info.st_dev, info.st_ino, info.st_nlink,
                path.read_bytes() if path.is_file() else None)
        return result

    def refused(self, scope='project'):
        before = self.snapshot()
        with self.assertRaises((txn.JournalError, RuntimeError, OSError)):
            self.activate(scope)
        self.assertEqual(before, self.snapshot())

    def test_interrupted_switch_both_indicators_missing(self):
        record = self.interrupt()
        self.assertEqual('APPLYING', record['phase'])
        self.remove_indicators()
        self.refused()
        self.assertTrue(all(self.owner.child_path(record['transaction_id'], 'old', i).exists()
                            for i in record['old_ids']))

    def test_missing_locator_and_valid_recoverable_preparing(self):
        self.interrupt('PREPARING', after=True)
        self.assertIsNone(self.owner.parse(self.owner.journal.read_bytes())['workspace_identity'])
        self.remove_indicators()
        self.assertIsNotNone(self.owner._load_recovery(allow_cleanup=True))
        self.refused()

    def test_only_locator_missing_or_only_lock_missing(self):
        self.interrupt()
        locator = self.owner.locator.read_bytes()
        self.remove_indicators(lock=False)
        self.refused()
        self.owner.locator.write_bytes(locator)
        self.remove_indicators(locator=False)
        self.refused()

    def test_user_scope_authority_uses_configured_base(self):
        user_project = self.root / 'user-base'
        self.base.rename(user_project)
        self.base = user_project; self.skills = user_project / 'skills'
        self.im = self.base / 'install-manifest.json'; self.state = self.base / 'active-state.json'
        im = json.loads(self.im.read_bytes()); im['scope'] = 'user'
        self.im.write_text(json.dumps(im), encoding='utf-8')
        self.owner = txn.JournalAuthority(self.cp, self.project, 'user', self.base)
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT': str(self.base)}):
            self.call('deactivate', ['--scope', 'user'])
            self.remove_indicators()
            self.refused('user')

    def test_malformed_and_binding_mismatches(self):
        self.interrupt(); self.remove_indicators()
        original = self.owner.journal.read_bytes()
        variants = [b'{', b'\xff', b'{"phase":"APPLYING","phase":"DONE"}']
        for field in ('control_plane_identity', 'project_identity', 'base_identity'):
            record = json.loads(original); record[field] = {'device': '1', 'inode': '2'}
            variants.append(json.dumps(record).encode())
        for field, value in [('project_path', str(self.root)), ('scope', 'user'),
                             ('phase', 'UNKNOWN'), ('transaction_id', 'not-a-uuid')]:
            record = json.loads(original); record[field] = value
            variants.append(json.dumps(record).encode())
        for raw in variants:
            with self.subTest(raw=raw[:100]):
                self.owner.journal.write_bytes(raw)
                self.refused()

    def test_stale_transaction_uuid_with_matching_locator(self):
        self.interrupt()
        record = self.owner.parse(self.owner.journal.read_bytes())
        record['transaction_id'] = str(uuid.uuid4())
        self.owner.journal.write_bytes(self.owner.serialize(record))
        self.owner.locator.write_text(json.dumps(self.owner.locator_record(record)), encoding='utf-8')
        self.remove_indicators(locator=False)
        self.refused()

    def test_ambiguous_backup_and_missing_indicators(self):
        record = self.interrupt(); self.remove_indicators()
        backup = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        backup.rename(backup.with_name('unregistered-backup'))
        self.refused()

    def test_pending_authority_and_locator_without_published_record(self):
        self.owner.store.mkdir(parents=True)
        for slot in (self.owner.journal_pending, self.owner.locator_pending):
            with self.subTest(slot=slot.name):
                slot.write_bytes(b'{"phase":"DONE"}')
                self.refused()
                slot.unlink()

    def test_orphan_workspace_or_pending_metadata(self):
        for name in ('.accp-txn-' + uuid.uuid4().hex, '.active-state.json.stale.pending'):
            with self.subTest(name=name):
                path = self.base / name; path.write_bytes(b'preserve orphan')
                self.refused(); path.unlink()

    def test_fresh_and_repeated_activation_without_records(self):
        (self.root / 'runtime-sentinel').write_bytes(b'preserve runtime')
        self.activate(); self.call(extra=['--cleanup']); self.activate()
        self.assertEqual([], json.loads(self.im.read_bytes())['managed_ids'])
        self.assertEqual(b'personal', (self.skills / 'personal' / 'payload').read_bytes())
        self.assertEqual(b'preserve runtime', (self.root / 'runtime-sentinel').read_bytes())
        self.assertTrue(self.owner.lock_path.exists())
        self.assertEqual('COMMITTED', self.owner.parse(self.owner.journal.read_bytes())['phase'])

    def test_new_base_activation_and_relative_project(self):
        project = self.root / 'fresh'; project.mkdir()
        self.project = Path(os.path.relpath(project))
        self.activate()
        self.assertTrue((project / '.agents' / 'install-manifest.json').is_file())
        self.assertTrue((project / '.agents' / '.accp-lifecycle.lock').exists())

    def test_repeated_recovery_and_finalization_allow_enrolled_activation(self):
        self.interrupt(); self.call(); self.call()
        self.refused()
        self.call(extra=['--cleanup']); self.call(extra=['--cleanup'])
        self.assertFalse(self.owner.journal.exists())
        self.assertFalse(self.owner.locator.exists())
        self.assertTrue(self.owner.lock_path.exists())
        self.activate()
        self.assertEqual('COMMITTED', self.owner.parse(self.owner.journal.read_bytes())['phase'])

    def test_retained_committed_is_not_activation_authority(self):
        self.call('deactivate'); self.remove_indicators()
        self.refused()

    def test_done_missing_locator_requires_finalization_not_activation(self):
        self.call('deactivate')
        unlink = txn.JournalAuthority._unlink_evidence
        def stop(owner, path, *args):
            if path == owner.journal: raise OSError('stop before journal unlink')
            return unlink(owner, path, *args)
        with mock.patch.object(txn.JournalAuthority, '_unlink_evidence', autospec=True, side_effect=stop):
            with self.assertRaises((OSError, txn.JournalError)):
                self.call(extra=['--cleanup'])
        self.assertEqual('DONE', self.owner.parse(self.owner.journal.read_bytes())['phase'])
        self.remove_indicators()
        self.refused()

    def test_external_pending_appears_after_lifecycle_lock_creation(self):
        self.owner.store.mkdir(parents=True)
        original = accp.os.open
        def open_and_interrupt(path, flags, *args, **kwargs):
            fd = original(path, flags, *args, **kwargs)
            if Path(path) == self.owner.lock_path:
                self.owner.journal_pending.write_bytes(b'interrupted publication')
            return fd
        metadata = self.im.read_bytes(), self.state.read_bytes()
        identity = txn.directory_identity(self.skills)
        with mock.patch.object(accp.os, 'open', side_effect=open_and_interrupt):
            with self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(metadata, (self.im.read_bytes(), self.state.read_bytes()))
        self.assertEqual(identity, txn.directory_identity(self.skills))
        self.assertEqual(b'interrupted publication', self.owner.journal_pending.read_bytes())
        self.assertFalse(self.owner.legacy_lock.exists())

    def test_unreadable_authority_fails_closed(self):
        self.interrupt(); self.remove_indicators()
        with mock.patch.object(txn.JournalAuthority, '_read', side_effect=PermissionError('denied')):
            self.refused()


if __name__ == '__main__':
    unittest.main()
