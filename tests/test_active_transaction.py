import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import active_transaction as txn


class JournalFoundation(unittest.TestCase):
    def setUp(self):
        temp = ROOT / '.local' / 'audit-temp'
        temp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / 'checkout'
        self.project = self.root / 'project'
        self.checkout.mkdir()
        self.project.mkdir()
        (self.project / '.agents').mkdir()
        self.authority = txn.JournalAuthority(self.checkout, self.project)

    def record(self, phase='PREPARING'):
        a = self.authority
        manifest = {'schema_version': 1, 'control_plane_path': str(a.checkout),
                    'project': str(a.project), 'scope': a.scope, 'managed_ids': []}
        state = {'schema_version': 1, 'control_plane_path': str(a.checkout), 'active_ids': []}
        result = dict(a.bindings(), schema_version=1, kind='accp-active-txn',
                      transaction_id=str(uuid.uuid4()), operation='deactivate', phase=phase,
                      prepared=False, skills_before={'exists': False},
                      skills_created_identity=None, workspace_identity=None,
                      old_ids=[], new_ids=[], old_children={}, new_children={},
                      old_manifest=txn.snapshot(None), old_state=txn.snapshot(None),
                      new_manifest=txn.snapshot(json.dumps(manifest).encode()),
                      new_state=txn.snapshot(json.dumps(state).encode()))
        return result

    def put_records(self, record):
        a = self.authority
        a.store.mkdir(parents=True)
        a.journal.write_bytes(a.serialize(record))
        a.locator.write_bytes(json.dumps(a.locator_record(record)).encode())

    def test_valid_journal_roundtrip_and_bound_locator(self):
        record = self.record()
        self.assertEqual(record, self.authority.parse(self.authority.serialize(record)))
        self.put_records(record)
        self.assertEqual(txn.RecordState.PENDING, self.authority.inspect().state)

    def test_malformed_utf8_duplicate_partial_and_non_json_records(self):
        valid = self.authority.serialize(self.record())
        cases = [b'', b'{', valid[:-3], b'[]', b'null', b'\xff', b'\xef\xbb\xbf{}',
                 b'{"phase":"PREPARING","phase":"COMMITTED"}',
                 b'{"x":{"a":1,"a":2}}', b'{"x":NaN}', b'{"x":"\\ud800"}']
        for raw in cases:
            with self.subTest(raw=raw[:60]), self.assertRaises(txn.JournalError):
                self.authority.parse(raw)

    def test_unknown_phase_fields_types_and_incomplete_commit(self):
        for key, value in [('phase', 'COMMIT'), ('schema_version', True),
                           ('operation', 'recover'), ('prepared', 1),
                           ('transaction_id', '../outside'), ('unexpected', 1),
                           ('phase', 'COMMITTED')]:
            record = self.record(); record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(txn.JournalError):
                self.authority.serialize(record)
        record = self.record(); del record['old_state']
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)

    def test_foreign_bindings_and_directory_replacement(self):
        for field in ('control_plane_path', 'project_path', 'base_path', 'scope',
                      'control_plane_identity', 'project_identity', 'base_identity'):
            record = self.record()
            record[field] = {'device': '1', 'inode': '2'} if field.endswith('identity') else 'foreign'
            with self.subTest(field=field), self.assertRaises(txn.JournalError):
                self.authority.serialize(record)
        raw = self.authority.serialize(self.record())
        self.project.rename(self.root / 'old-project'); self.project.mkdir()
        (self.project / '.agents').mkdir()
        with self.assertRaises(txn.JournalError): self.authority.parse(raw)

    def test_snapshot_digest_base64_size_and_pair_conflicts(self):
        for value in ({'exists': 0}, {'exists': False, 'extra': 1},
                      {'exists': True, 'bytes_base64': '!!!', 'sha256': '0' * 64},
                      {'exists': True, 'bytes_base64': 'eA==', 'sha256': '0' * 64}):
            with self.subTest(value=value), self.assertRaises(txn.JournalError):
                txn.snapshot_bytes(value)
        with self.assertRaises(txn.JournalError): txn.snapshot(b'x' * (txn.MAX_METADATA + 1))
        record = self.record(); record['new_state'] = txn.snapshot(None)
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)
        record = self.record()
        state = json.loads(txn.snapshot_bytes(record['new_state']))
        state['active_ids'] = ['foreign']
        record['new_state'] = txn.snapshot(json.dumps(state).encode())
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)

    def test_child_inventory_and_digest_validation(self):
        for values in (['../escape'], ['C:\\escape'], ['con'], ['dup', 'dup'],
                       ['ok'] * (txn.MAX_IDS + 1)):
            record = self.record(); record['old_ids'] = values
            with self.subTest(values=values[:2]), self.assertRaises(txn.JournalError):
                self.authority.serialize(record)
        record = self.record(); record['new_children'] = {'unlisted': {'prepared': False}}
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)
        record = self.record(); record['skills_before'] = txn.directory_identity(self.project)
        record['old_ids'] = ['one']
        record['old_children'] = {'one': {'identity': txn.directory_identity(self.project), 'sha256': 'bad'}}
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)

    def test_nonempty_prepared_inventory_and_snapshot_roundtrip(self):
        record = self.record('PREPARED')
        record['operation'] = 'activate'; record['prepared'] = True
        record['new_ids'] = ['provider']
        record['workspace_identity'] = {name: {'device': '1', 'inode': str(i + 1)}
                                        for i, name in enumerate(('root', 'old', 'new', 'discard'))}
        record['new_children'] = {'provider': {'identity': {'device': '1', 'inode': '5'},
                                                'sha256': 'a' * 64}}
        for name, field in (('new_manifest', 'managed_ids'), ('new_state', 'active_ids')):
            value = json.loads(txn.snapshot_bytes(record[name]))
            value[field] = ['provider']
            record[name] = txn.snapshot(json.dumps(value).encode())
        self.assertEqual(record, self.authority.parse(self.authority.serialize(record)))
        record['new_children']['provider'] = {'prepared': False}
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)

    def test_prepared_and_terminal_phase_representation(self):
        record = self.record(); record['phase'] = 'PREPARED'; record['prepared'] = True
        record['workspace_identity'] = {name: {'device': '1', 'inode': str(i + 1)}
                                        for i, name in enumerate(('root', 'old', 'new', 'discard'))}
        self.authority.serialize(record)
        for phase in ('APPLYING', 'COMMITTED', 'ROLLING_BACK', 'ROLLED_BACK'):
            record['phase'] = phase
            self.authority.serialize(record)
        for phase in ('CLEANING', 'DONE'):
            record['phase'] = phase; record['outcome'] = 'committed'
            self.authority.serialize(record)
        record['prepared'] = False
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)
        record['outcome'] = 'rolled_back'
        self.authority.serialize(record)

    def test_legacy_metadata_path_spelling_and_foreign_path(self):
        record = self.record()
        manifest = json.loads(txn.snapshot_bytes(record['new_manifest']))
        if os.name == 'nt':
            manifest['control_plane_path'] = manifest['control_plane_path'].upper()
            manifest['project'] = manifest['project'].upper()
        record['new_manifest'] = txn.snapshot(json.dumps(manifest).encode())
        self.authority.serialize(record)
        manifest['project'] = str(self.root / 'other-project')
        record['new_manifest'] = txn.snapshot(json.dumps(manifest).encode())
        with self.assertRaises(txn.JournalError): self.authority.serialize(record)

    def test_interrupted_publication_never_authorizes_commit(self):
        record = self.record(); self.put_records(record)
        self.authority.journal_pending.write_bytes(b'{"phase":"COMMITTED"')
        result = self.authority.inspect()
        self.assertEqual(txn.RecordState.INTERRUPTED, result.state)
        self.assertFalse(hasattr(result, 'journal'))
        self.authority.journal_pending.unlink()
        self.authority.journal.write_bytes(b'{"phase":"COMMITTED"')
        self.assertEqual(txn.RecordState.CONFLICT, self.authority.inspect().state)

    def test_locator_alone_foreign_locator_and_missing_locator(self):
        record = self.record(); self.put_records(record)
        locator = self.authority.locator_record(record); locator['key'] = '0' * 64
        self.authority.locator.write_text(json.dumps(locator))
        self.assertEqual(txn.RecordState.CONFLICT, self.authority.inspect().state)
        self.authority.journal.unlink()
        self.assertEqual(txn.RecordState.CONFLICT, self.authority.inspect().state)
        self.authority.locator.unlink()
        self.authority.journal.write_bytes(self.authority.serialize(record))
        self.assertEqual(txn.RecordState.INTERRUPTED, self.authority.inspect().state)

    def test_status_is_nonmutating_and_missing_store_is_absent(self):
        def inventory():
            return {str(p.relative_to(self.root)): p.read_bytes() if p.is_file() else None
                    for p in self.root.rglob('*')}
        before = inventory()
        for _ in range(2):
            self.assertEqual(txn.RecordState.ABSENT, self.authority.inspect().state)
        self.assertEqual(before, inventory())
        self.assertFalse(self.authority.store.exists())

    def test_raw_paths_and_store_overlap(self):
        for raw in ('', '.', '..', 'relative', 'C:relative', '\\rooted',
                    '\\\\server\\share', '\\\\?\\C:\\runtime', str(self.root) + '/x/../y'):
            with self.subTest(raw=raw), self.assertRaises(txn.JournalError): txn.canonical(raw)
        for base in (self.authority.store, self.authority.store / 'child', self.checkout / '.local'):
            with self.subTest(base=base), self.assertRaises(txn.JournalError):
                txn.JournalAuthority(self.checkout, self.project, 'user', base)
        with self.assertRaises(txn.JournalError):
            self.authority.child_path(str(uuid.uuid4()), 'old', '../escape')
        with self.assertRaises(txn.JournalError): self.authority.workspace('../../escape')

    def test_reparse_metadata_and_hardlinked_record_refused(self):
        self.put_records(self.record())
        original = Path.lstat
        target = self.authority.store
        info = type('Info', (), {'st_mode': stat.S_IFDIR, 'st_file_attributes': 0x400})()
        def fake(path, *args, **kwargs):
            return info if path == target else original(path, *args, **kwargs)
        with mock.patch.object(Path, 'lstat', autospec=True, side_effect=fake):
            self.assertEqual(txn.RecordState.CONFLICT, self.authority.inspect().state)
        os.link(self.authority.journal, self.root / 'journal-alias')
        self.assertEqual(txn.RecordState.CONFLICT, self.authority.inspect().state)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction fixture')
    def test_real_junction_authority_store_refused(self):
        outside = self.root / 'outside'; outside.mkdir()
        self.authority.store.parent.mkdir(parents=True)
        link = self.authority.store
        result = subprocess.run([os.environ['COMSPEC'], '/c', 'mklink', '/J', str(link), str(outside)],
                                capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        try:
            with self.assertRaises(txn.JournalError): txn.JournalAuthority(self.checkout, self.project)
        finally:
            link.rmdir()  # unlink this fixture junction only

    def test_size_limit_and_identity_helper(self):
        with self.assertRaises(txn.JournalError):
            self.authority.parse(b' ' * (txn.MAX_JOURNAL + 1))
        with self.assertRaises(txn.JournalError):
            txn.verify_directory(self.project, {'device': '1', 'inode': '2'})

    def child_command(self, body):
        code = ("import sys,os; sys.path.insert(0,sys.argv[1]); "
                "from active_transaction import JournalAuthority; "
                "a=JournalAuthority(sys.argv[2],sys.argv[3]);\n" + body)
        return [sys.executable, '-B', '-c', code, str(ROOT / 'scripts'),
                str(self.checkout), str(self.project)]

    def test_persistent_lock_contention_and_process_exit(self):
        a = self.authority
        with a.lifecycle_lock():
            result = subprocess.run(self.child_command('with a.lifecycle_lock(): pass'),
                                    capture_output=True, timeout=15)
            self.assertNotEqual(0, result.returncode)
            self.assertIn(b'lock busy or unavailable', result.stderr)
        identity = txn.regular_identity(a.lock_path)
        result = subprocess.run(self.child_command('with a.lifecycle_lock(): os._exit(0)'),
                                capture_output=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        with a.lifecycle_lock(create=False):
            self.assertEqual(identity, txn.regular_identity(a.lock_path))
        self.assertTrue(a.lock_path.exists())

    def test_legacy_lock_and_noncreating_lock(self):
        a = self.authority
        with self.assertRaises(FileNotFoundError):
            with a.lifecycle_lock(create=False): pass
        self.assertFalse(a.lock_path.exists())
        a.legacy_lock.write_text('stale 1 1900-01-01')
        with self.assertRaises(txn.JournalError):
            with a.lifecycle_lock(): pass
        self.assertEqual('stale 1 1900-01-01', a.legacy_lock.read_text())
        self.assertFalse(a.lock_path.exists())

    def test_publication_requires_lock_and_journal_before_locator(self):
        a = self.authority; record = self.record()
        with self.assertRaises(txn.JournalError): a.publish_journal(record)
        self.assertFalse(a.store.exists())
        with a.lifecycle_lock():
            with self.assertRaises(FileNotFoundError): a.publish_locator(record)
            a.publish_journal(record)
            self.assertFalse(a.locator.exists())
            self.assertEqual(txn.RecordState.INTERRUPTED, a.inspect().state)
            a.publish_locator(record)
            self.assertEqual(txn.RecordState.PENDING, a.inspect().state)
            with self.assertRaises(txn.JournalError): a.publish_locator(record)
        self.assertFalse(a.journal_pending.exists())
        self.assertFalse(a.locator_pending.exists())

    def test_publication_flush_then_replace_then_directory_sync(self):
        a = self.authority; record = self.record(); a.store.mkdir(parents=True)
        events = []; fsync = txn.os.fsync; replace = txn.os.replace
        def flush(fd):
            events.append('file-sync'); return fsync(fd)
        def switch(src, dst):
            events.append('replace'); return replace(src, dst)
        with a.lifecycle_lock(), mock.patch.object(txn.os, 'fsync', side_effect=flush), \
                mock.patch.object(txn.os, 'replace', side_effect=switch), \
                mock.patch.object(txn, 'sync_directory', side_effect=lambda p: events.append('dir-sync')):
            a.publish_journal(record)
        self.assertEqual(['file-sync', 'replace', 'dir-sync'], events)

    def test_failed_flush_or_replace_preserves_pending_and_blocks_retry(self):
        for failure in ('fsync', 'replace'):
            with self.subTest(failure=failure):
                a = self.authority; record = self.record(); a.store.mkdir(parents=True, exist_ok=True)
                with a.lifecycle_lock(), mock.patch.object(txn.os, failure, side_effect=OSError('injected')):
                    with self.assertRaises(txn.PublicationError) as error: a.publish_journal(record)
                self.assertFalse(error.exception.replacement_completed)
                self.assertFalse(a.journal.exists())
                self.assertTrue(a.journal_pending.exists())
                before = a.journal_pending.read_bytes()
                with a.lifecycle_lock(), self.assertRaises(txn.JournalError): a.publish_journal(record)
                self.assertEqual(before, a.journal_pending.read_bytes())
                a.journal_pending.unlink()  # fixture reset only; production never cleans pending

    def test_directory_sync_failure_reports_replacement_without_success(self):
        a = self.authority; record = self.record(); a.store.mkdir(parents=True)
        with a.lifecycle_lock(), mock.patch.object(txn, 'sync_directory', side_effect=OSError('sync failed')):
            with self.assertRaises(txn.PublicationError) as error: a.publish_journal(record)
        self.assertTrue(error.exception.replacement_completed)
        self.assertEqual(record, a.parse(a.journal.read_bytes()))
        self.assertFalse(a.locator.exists())

    def test_interrupted_process_retains_partial_slot(self):
        a = self.authority; a.store.mkdir(parents=True)
        body = ('with a.lifecycle_lock():\n'
                ' with a.journal_pending.open("xb") as f:\n'
                '  f.write(b"{partial"); f.flush(); os.fsync(f.fileno())\n'
                ' os._exit(0)')
        result = subprocess.run(self.child_command(body), capture_output=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(txn.RecordState.INTERRUPTED, a.inspect().state)
        with a.lifecycle_lock(), self.assertRaises(txn.JournalError): a.publish_journal(self.record())
        self.assertEqual(b'{partial', a.journal_pending.read_bytes())

    def test_partial_publisher_write_is_retained_without_replacement(self):
        a = self.authority; record = self.record(); original = Path.open
        class ShortWriter:
            def __enter__(self):
                self.stream = original(a.journal_pending, 'xb')
                return self
            def write(self, raw):
                self.stream.write(raw[:9]); self.stream.flush()
                raise OSError('interrupted write')
            def __exit__(self, *args):
                self.stream.close()
        def opened(path, *args, **kwargs):
            return ShortWriter() if path == a.journal_pending else original(path, *args, **kwargs)
        with a.lifecycle_lock(), mock.patch.object(Path, 'open', autospec=True, side_effect=opened):
            with self.assertRaises(txn.PublicationError) as error: a.publish_journal(record)
        self.assertFalse(error.exception.replacement_completed)
        self.assertEqual(a.serialize(record)[:9], a.journal_pending.read_bytes())
        self.assertFalse(a.journal.exists())

    def test_process_exit_between_journal_and_locator_publication(self):
        a = self.authority; record = self.record()
        source = self.root / 'input.json'; source.write_bytes(a.serialize(record))
        body = ('r=a.parse(open(sys.argv[4],"rb").read())\n'
                'with a.lifecycle_lock():\n'
                ' a.publish_journal(r)\n'
                ' os._exit(0)')
        result = subprocess.run(self.child_command(body) + [str(source)], capture_output=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(txn.RecordState.INTERRUPTED, a.inspect().state)
        self.assertFalse(a.locator.exists())
        with a.lifecycle_lock(), self.assertRaises(txn.JournalError): a.publish_journal(record)
        self.assertEqual(record, a.parse(a.journal.read_bytes()))

    def test_store_replacement_under_lock_and_linked_lock_refused(self):
        a = self.authority; record = self.record(); a.store.mkdir(parents=True)
        with a.lifecycle_lock():
            a.store.rename(a.store.with_name('saved-store')); a.store.mkdir()
            with self.assertRaises(txn.JournalError): a.publish_journal(record)
        os.link(a.lock_path, self.root / 'lock-alias')
        with self.assertRaises(txn.JournalError):
            with a.lifecycle_lock(): pass

    def test_lock_identity_rechecked_before_publication(self):
        a = self.authority; record = self.record(); original = txn.regular_identity
        with a.lifecycle_lock():
            def changed(path):
                return (1, 2) if path == a.lock_path else original(path)
            with mock.patch.object(txn, 'regular_identity', side_effect=changed), self.assertRaises(txn.JournalError):
                a.publish_journal(record)
        self.assertFalse(a.store.exists())

    def test_compare_replace_transition_and_outcome_guards(self):
        a = self.authority; record = self.record()
        with a.lifecycle_lock():
            a.publish_journal(record); a.publish_locator(record)
            before = a.journal.read_bytes()
            next_record = dict(record, phase='ROLLING_BACK')
            a.publish_journal(next_record, previous=before)
            with self.assertRaises(txn.JournalError): a.publish_journal(next_record, previous=before)
            before = a.journal.read_bytes()
            foreign = dict(next_record, transaction_id=str(uuid.uuid4()))
            with self.assertRaises(txn.JournalError): a.publish_journal(foreign, previous=before)
            next_record = dict(next_record, phase='ROLLED_BACK')
            a.publish_journal(next_record, previous=before)
            before = a.journal.read_bytes()
            next_record = dict(next_record, phase='CLEANING', outcome='rolled_back')
            a.publish_journal(next_record, previous=before)
            before = a.journal.read_bytes()
            wrong = dict(next_record, phase='DONE', outcome='committed')
            with self.assertRaises(txn.JournalError): a.publish_journal(wrong, previous=before)
            self.assertEqual(before, a.journal.read_bytes())


if __name__ == '__main__':
    unittest.main()
